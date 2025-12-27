# payatom_bot/workers/idbi.py
from __future__ import annotations

import os
import time
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException, NoSuchElementException

from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..autobank_client import AutoBankClient


class IDBIWorker(BaseWorker):
    """
    IDBI Bank automation (refactored from main.py):
      1) Login (username + CAPTCHA) → Continue → password → checkbox
      2) Read balance from the summary row for our account
      3) Open A/C Statement → set dates → VIEW → Download as XLS
      4) Upload to AutoBank with bank = "IDBI"
      5) Loop every 60s; on error take screenshots & retry
    Expects creds dict (from your CSV loader) with:
      cred = {
        "alias": str,
        "auth_id": str,         # canonical user id (username/login_id/user_id)
        "username": str,        # raw; may be empty
        "password": str,
        "account_number": str,
        "bank_label": str,
      }
    """

    LOGIN_URL = "https://inet.idbibank.co.in/"

    def __init__(
        self,
        *,
        bot,
        chat_id: int,
        alias: str,
        cred: dict,
        messenger,
        profile_dir: str,
        two_captcha: Optional[TwoCaptcha] = None,
    ):
        super().__init__(bot=bot, chat_id=chat_id, alias=alias, cred=cred, messenger=messenger, profile_dir=profile_dir)
        self.wait = WebDriverWait(self.driver, 20)
        self.solver = two_captcha
        self.idbi_win: Optional[str] = None
        self._captcha_id: Optional[str] = None
        self.captcha_code: Optional[str] = None

    # ———————————————————
    # Thread entry
    # ———————————————————
    def run(self):
        self.info("🚀 Starting IDBI automation")
        retry_count = 0
        try:
            while not self.stop_evt.is_set():
                try:
                    self._login()
                    retry_count = 0

                    self._read_balance_and_navigate_to_statement()

                    while not self.stop_evt.is_set():
                        self._run_with_retries(self._download_and_upload_statement, "IDBI statement")
                        time.sleep(60)

                    break  # graceful stop
                except Exception as e:
                    retry_count += 1
                    self.error(f"IDBI loop error: {e!r} — retry {retry_count}/5")
                    self.screenshot_all_tabs("IDBI loop error")
                    if retry_count > 5:
                        self.error("❌ Too many failures. Stopping.")
                        return
                    self._cycle_tabs()
        finally:
            self.stop()

    # ———————————————————
    # Steps
    # ———————————————————
    def _login(self):
        d = self.driver
        w = self.wait

        d.get(self.LOGIN_URL)

        # (1) Username (AuthenticationFG.USER_PRINCIPAL)
        w.until(EC.presence_of_element_located((By.ID, "AuthenticationFG.USER_PRINCIPAL")))
        user = (self.cred.get("auth_id") or self.cred.get("username") or "").strip()
        if not user:
            raise RuntimeError("Missing username/auth_id for IDBI login")
        d.find_element(By.ID, "AuthenticationFG.USER_PRINCIPAL").send_keys(user)

        # (2) CAPTCHA (IMAGECAPTCHA)
        img = w.until(EC.presence_of_element_located((By.ID, "IMAGECAPTCHA")))
        img_bytes = img.screenshot_as_png

        self.info("🤖 Solving CAPTCHA via 2Captcha…")
        solution, cid = (None, None)
        if self.solver and self.solver.key:
            solution, cid = self.solver.solve(img_bytes)
        if solution:
            self.captcha_code, self._captcha_id = solution, cid
            self.info(f"✅ Auto-solved: `{solution}`")
        else:
            self.msgr.send_photo(BytesIO(img_bytes), f"[{self.alias}] 🔐 Please solve this CAPTCHA", kind="CAPTCHA")
            raise TimeoutException("CAPTCHA not solved — add your manual flow if needed.")

        # (3) Fill CAPTCHA & Continue (STU_VALIDATE_CREDENTIALS)
        d.find_element(By.ID, "AuthenticationFG.VERIFICATION_CODE").send_keys(self.captcha_code)
        cont = None
        for btn in d.find_elements(By.ID, "STU_VALIDATE_CREDENTIALS"):
            if btn.is_displayed() and btn.is_enabled():
                cont = btn
                break
        if not cont:
            raise TimeoutException("Continue-to-Login button not found")
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", cont)
        try:
            cont.click()
        except Exception:
            d.execute_script("arguments[0].click();", cont)

        # (3a) Wrong CAPTCHA? detect and report
        try:
            wrapper = WebDriverWait(d, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "span.errorCodeWrapper"))
            )
            for p in wrapper.find_elements(By.TAG_NAME, "p"):
                if p.value_of_css_property("display") == "inline":
                    if "enter the characters" in (p.text or "").lower() and self._captcha_id:
                        self.error("❌ CAPTCHA wrong — reporting to 2Captcha and retrying…")
                        try:
                            self.solver.report_bad(self._captcha_id)
                        except Exception:
                            pass
                        raise TimeoutException("CAPTCHA incorrect")
        except TimeoutException:
            pass  # no visible error → proceed

        # (4) Password field + checkbox (AuthenticationFG.ACCESS_CODE / AuthenticationFG.TARGET_CHECKBOX)
        w.until(EC.presence_of_element_located((By.ID, "AuthenticationFG.ACCESS_CODE")))
        pwd = d.find_element(By.ID, "AuthenticationFG.ACCESS_CODE")
        pwd.send_keys(self.cred["password"])

        # Styled checkbox: input#AuthenticationFG.TARGET_CHECKBOX + sibling span.span-checkbox
        checkbox_span = WebDriverWait(d, 20).until(
            EC.element_to_be_clickable((
                By.XPATH,
                "//input[@id='AuthenticationFG.TARGET_CHECKBOX']/following-sibling::span[contains(@class,'span-checkbox')]"
            ))
        )
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", checkbox_span)
        time.sleep(0.2)
        try:
            checkbox_span.click()
        except Exception:
            d.execute_script("arguments[0].click();", checkbox_span)

        # Submit via Enter on password (common Finacle pattern)
        try:
            pwd.send_keys("\n")
        except Exception:
            pass

        # Wait until we can see the post-login content (account grid)
        WebDriverWait(d, 60).until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
        self.idbi_win = d.current_window_handle
        self.logged_in = True
        self.info("✅ Logged in to IDBI")

    def _read_balance_and_navigate_to_statement(self):
        d = self.driver
        w = self.wait

        if self.idbi_win:
            d.switch_to.window(self.idbi_win)

        acct = (self.cred.get("account_number") or "").strip()
        if not acct:
            raise RuntimeError("Missing account_number in credentials")

        # Find the row for our exact account number (span text equals our number)
        account_xpath = f"//span[normalize-space(text())='{acct}']/ancestor::tr"
        row = WebDriverWait(d, 60).until(
            EC.presence_of_element_located((By.XPATH, account_xpath))
        )
        time.sleep(0.5)

        # Read the INR balance from that row
        try:
            bal_text = row.find_element(By.XPATH, ".//td[contains(normalize-space(.),'INR')]").text.strip()
            if bal_text:
                self.last_balance = bal_text
                self.info(f"💰 Balance: {bal_text}")
        except NoSuchElementException:
            self.info("Balance cell not found; continuing.")

        # Click the “A/C Statement” link in the same row
        stmt = row.find_element(By.XPATH, ".//a[@title='A/C Statement']")
        WebDriverWait(d, 20).until(EC.element_to_be_clickable((By.XPATH, ".//a[@title='A/C Statement']")))
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", stmt)
        try:
            stmt.click()
        except Exception:
            d.execute_script("arguments[0].click();", stmt)

    def _download_and_upload_statement(self):
        d = self.driver

        # (1) Wait up to 5 minutes for the From date field to appear
        start = time.time()
        frm = None
        while time.time() - start < 300:
            try:
                frm = d.find_element(By.NAME, "TransactionHistoryFG.FROM_TXN_DATE")
                break
            except Exception:
                # occasionally the notification pane blocks; try closing it after 60s
                if time.time() - start > 60:
                    try:
                        d.find_element(By.ID, "span_HREF_Notifications").click()
                    except Exception:
                        pass
                time.sleep(5)
        if not frm:
            raise TimeoutException("Statement page did not load in time")

        # (2) Dates: same as legacy — 5AM cutover
        now = datetime.now()
        fr_dt = now - timedelta(days=1) if now.hour < 5 else now
        to_dt = now
        fr_s, to_s = fr_dt.strftime("%d/%m/%Y"), to_dt.strftime("%d/%m/%Y")

        # remove readonly and type values
        self.driver.execute_script("arguments[0].removeAttribute('readonly')", frm)
        frm.clear(); frm.send_keys(fr_s)

        to_elem = d.find_element(By.NAME, "TransactionHistoryFG.TO_TXN_DATE")
        self.driver.execute_script("arguments[0].removeAttribute('readonly')", to_elem)
        to_elem.clear(); to_elem.send_keys(to_s)

        # (3) Click VIEW (Action.SEARCH)
        view_loc = (By.NAME, "Action.SEARCH")
        WebDriverWait(d, 30).until(EC.element_to_be_clickable(view_loc))
        for _ in range(3):
            try:
                btn = d.find_element(*view_loc)
                d.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
                btn.click()
                break
            except StaleElementReferenceException:
                time.sleep(1)
        else:
            raise TimeoutException("Could not click VIEW STATEMENT")

        time.sleep(5)

        # (4) Wait for “Download:” label to appear (span.downloadtext)
        WebDriverWait(d, 120).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "span.downloadtext"))
        )

        # (5) Click the specific XLS button:
        # //input[@name='Action.GENERATE_REPORT' and contains(@onclick,'setOutformat(4')]
        xls_btn = WebDriverWait(d, 60).until(
            EC.element_to_be_clickable((
                By.XPATH,
                "//input[@name='Action.GENERATE_REPORT' and contains(@onclick,'setOutformat(4')]"
            ))
        )
        self.driver.execute_script("arguments[0].scrollIntoView({block:'center'});", xls_btn)
        time.sleep(0.2)
        try:
            xls_btn.click()
        except Exception:
            self.driver.execute_script("arguments[0].click();", xls_btn)

        # (6) Wait for a new .xls file to complete download (no .tmp/.crdownload)
        end = time.time() + 60
        xls_full = None
        before = set(os.listdir(self.download_dir))
        while time.time() < end:
            files = [f for f in os.listdir(self.download_dir)
                     if f.lower().endswith(".xls") and f not in before]
            if files:
                newest = max(files, key=lambda f: os.path.getctime(os.path.join(self.download_dir, f)))
                full = os.path.join(self.download_dir, newest)
                # ensure the file is stable
                try:
                    s1 = os.path.getsize(full)
                    time.sleep(0.8)
                    s2 = os.path.getsize(full)
                    if s1 == s2:
                        xls_full = full
                        break
                except FileNotFoundError:
                    pass
            time.sleep(0.5)
        if not xls_full:
            raise TimeoutException("Timed out waiting for XLS download")

        # (7) Upload to AutoBank using standard client with bank "IDBI"
        original = d.current_window_handle
        d.execute_script("window.open('about:blank');")
        upload_tab = [h for h in d.window_handles if h != original][-1]

        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                d.switch_to.window(upload_tab)
                AutoBankClient(d).upload("IDBI", self.cred["account_number"], xls_full)
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

        # Close the upload tab and return to IDBI
        try:
            d.switch_to.window(original)
            for h in list(d.window_handles):
                if h != original:
                    d.switch_to.window(h)
                    d.close()
            d.switch_to.window(original)
        except Exception:
            pass
