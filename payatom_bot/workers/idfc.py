# payatom_bot/workers/idfc.py
from __future__ import annotations

import os
import time
from io import BytesIO
from datetime import datetime, timedelta, date
from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, StaleElementReferenceException

from ..worker_base import BaseWorker
from ..autobank_client import AutoBankClient


class IDFCWorker(BaseWorker):
    """
    IDFC Bank automation (ported from your main.py):
      1) Login: username -> password -> OTP (OTP supplied via Telegram handler that sets worker.otp_code)
      2) Scrape Net Withdrawal balance and report
      3) Download statement (Excel) using React datepicker (custom range)
      4) Upload to AutoBank with bank = "IDFC"  (keep legacy selector/label, as requested)
      5) Loop every 60s; robust retries & screenshots via BaseWorker helpers

    Expected creds (from your CSV loader):
      cred = {
        "alias": str,
        "auth_id": str,       # canonical user id (username/login_id/user_id)
        "username": str,      # raw; may be empty
        "password": str,
        "account_number": str,
        "bank_label": str,
      }
    """

    LOGIN_URL = "https://my.idfcfirstbank.com/login"

    def __init__(
        self,
        *,
        bot,
        chat_id: int,
        alias: str,
        cred: dict,
        messenger,
        profile_dir: str,
        two_captcha: Optional[object] = None,  # not used for IDFC
    ):
        super().__init__(
            bot=bot,
            chat_id=chat_id,
            alias=alias,
            cred=cred,
            messenger=messenger,
            profile_dir=profile_dir,
        )
        self.wait = WebDriverWait(self.driver, 20)
        self.otp_code: Optional[str] = None
        self.idfc_win: Optional[str] = None

    # ———————————————————
    # Public thread entry
    # ———————————————————
    def run(self):
        self.info("🚀 Starting IDFC automation")
        retry_count = 0
        try:
            while not self.stop_evt.is_set():
                try:
                    self._login()
                    retry_count = 0

                    # steady-state loop
                    while not self.stop_evt.is_set():
                        self._run_with_retries(self._scrape_and_upload, "IDFC statement")
                        time.sleep(60)
                    break  # graceful stop
                except Exception as e:
                    retry_count += 1
                    self.error(f"IDFC loop error: {e!r} — retry {retry_count}/5")
                    self.screenshot_all_tabs("IDFC loop error")
                    if retry_count > 5:
                        self.error("❌ Too many failures. Stopping.")
                        return
                    self._cycle_tabs()  # new blank tab, close old handles, reset state
        finally:
            self.stop()

    # ———————————————————
    # Steps
    # ———————————————————
    def _login(self):
        d = self.driver
        w = self.wait

        # e1–e2: username → Proceed
        d.get(self.LOGIN_URL)
        w.until(EC.presence_of_element_located((By.NAME, "customerUserName")))
        user = (self.cred.get("auth_id") or self.cred.get("username") or "").strip()
        if not user:
            raise RuntimeError("Missing username/auth_id for IDFC login")
        d.find_element(By.NAME, "customerUserName").send_keys(user)
        d.find_element(By.CSS_SELECTOR, "[data-testid='submit-button-id']").click()

        # e3–e4: password → Login Securely
        w.until(EC.presence_of_element_located((By.ID, "login-password-input")))
        d.find_element(By.ID, "login-password-input").send_keys(self.cred["password"])
        d.find_element(By.CSS_SELECTOR, "[data-testid='login-button']").click()

        # e5–e6: OTP via Telegram
        self.info("🔐 Waiting for 6-digit OTP (send it in Telegram)…")
        start = time.time()
        while self.otp_code is None and not self.stop_evt.is_set():
            if time.time() - start > 300:  # 5-min expiry
                raise TimeoutException("OTP expired — restarting login")
            time.sleep(0.5)
        if self.stop_evt.is_set():
            return

        # Inject OTP and verify
        d.find_element(By.NAME, "otp").send_keys(self.otp_code)
        d.find_element(By.CSS_SELECTOR, "[data-testid='verify-otp']").click()

        # Wait until Accounts tab is interactive
        WebDriverWait(d, 30).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "span[data-testid='Accounts']")))
        self.idfc_win = d.current_window_handle
        self.logged_in = True
        self.info("✅ Logged in to IDFC")

    def _select_date(self, field_id: str, target: date):
        """Open the React datepicker for `field_id` and pick the given `target` day."""
        d = self.driver

        # 1) Click the readonly input to open the calendar widget
        inp = d.find_element(By.ID, field_id)
        inp.click()

        # 2) Wait for the datepicker header (month/year dropdowns)
        header = WebDriverWait(d, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "react-datepicker__header"))
        )

        # 3) Grab the two <select> elements (month then year)
        selects = header.find_elements(By.TAG_NAME, "select")
        if len(selects) < 2:
            raise NoSuchElementException("Could not locate month/year selectors in datepicker")
        month_dropdown, year_dropdown = Select(selects[0]), Select(selects[1])

        # month is zero-based (0=Jan); year shows full strings
        month_dropdown.select_by_index(int(target.month) - 1)
        year_dropdown.select_by_visible_text(str(target.year))

        # 4) Click the day cell (exclude outside-month days)
        day_xpath = (
            f"//div[contains(@class,'react-datepicker__day') "
            f"and not(contains(@class,'--outside-month')) and text()='{target.day}']"
        )
        WebDriverWait(d, 10).until(EC.element_to_be_clickable((By.XPATH, day_xpath))).click()

    def _scrape_and_upload(self):
        d = self.driver
        w = self.wait

        # Ensure we're on the IDFC tab
        if self.idfc_win:
            d.switch_to.window(self.idfc_win)

        # e7: click Accounts
        d.find_element(By.CSS_SELECTOR, "span[data-testid='Accounts']").click()

        # e8: read "Net Withdrawal" balance (effective balance)
        bal = w.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "[data-testid='AccountEffectiveBalance-amount']"))
        ).text.strip()
        if bal:
            self.last_balance = bal
            self.info(f"💰 {bal}")

        time.sleep(0.5)

        # e9–e14: open Download Statement flow
        d.find_element(By.CSS_SELECTOR, "[data-testid='download-statement-link']").click()
        time.sleep(0.5)

        # Choose "Custom"
        w.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "label[for='AccountStatementDate-4']"))).click()
        time.sleep(0.5)

        # Select dates based on current time (Asia/Kolkata logic as in main.py)
        now = datetime.now()
        if now.hour < 5:
            frm_date = now.date() - timedelta(days=1)  # yesterday
            to_date = now.date()                       # today
        else:
            frm_date = now.date()                      # today
            to_date = now.date()                       # today

        self._select_date("custom-from-date", frm_date)
        time.sleep(0.4)
        self._select_date("custom-to-date", to_date)
        time.sleep(0.4)

        # Open format dropdown and pick "Excel"
        d.find_element(By.ID, "select-account-statement-format").click()
        w.until(EC.element_to_be_clickable((
            By.XPATH, "//ul[@id='select-account-statement-format-list']//span[text()='Excel']"
        ))).click()

        # Click the primary "Download" button
        d.find_element(By.CSS_SELECTOR, "[data-testid='PrimaryAction']").click()

        # Wait for a new Excel file to complete download (xlsx or xls)
        # Prefer .xlsx; fall back to .xls just in case.
        xlsx_path = self.wait_newest_file(".xlsx", timeout=90)
        xls_path = None
        if not xlsx_path:
            xls_path = self.wait_newest_file(".xls", timeout=30)
        file_path = xlsx_path or xls_path
        if not file_path:
            raise TimeoutException("Timed out waiting for Excel statement download")

        # Upload to AutoBank (keep legacy label "IDFC")
        original = d.current_window_handle
        d.execute_script("window.open('about:blank');")
        upload_tab = [h for h in d.window_handles if h != original][-1]

        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                d.switch_to.window(upload_tab)
                AutoBankClient(d).upload("IDFC", self.cred["account_number"], file_path)
                self.info(f"✅ AutoBank upload succeeded (attempt {attempt}/{max_attempts})")
                break
            except Exception as e:
                self.error(f"⚠️ AutoBank upload failed (attempt {attempt}/{max_attempts}): {type(e).__name__}: {e}")
                try:
                    self.screenshot_all_tabs("AutoBank upload failed")
                except Exception:
                    pass
                if attempt == max_attempts:
                    try:
                        d.close()
                    except Exception:
                        pass
                    d.switch_to.window(original)
                    raise
                time.sleep(2)

        # Close upload tab and return to bank
        try:
            d.switch_to.window(original)
            for h in list(d.window_handles):
                if h != original:
                    d.switch_to.window(h)
                    d.close()
            d.switch_to.window(original)
        except Exception:
            pass

        # Close statement modal/page if present (best-effort)
        try:
            d.find_element(By.CSS_SELECTOR, "[aria-label='Cross']").click()
        except Exception:
            pass

    # ———————————————————
    # External hook to inject OTP from Telegram handler
    # ———————————————————
    def set_otp(self, otp: str):
        """
        Called by your Telegram handler when a 6-digit OTP arrives in chat.
        Example handler can look up the running worker by alias and call worker.set_otp(text).
        """
        otp = (otp or "").strip()
        if len(otp) == 6 and otp.isdigit():
            self.otp_code = otp
            self.info("🔑 OTP received.")
        else:
            self.info("⚠️ Ignoring non-6-digit OTP payload.")
