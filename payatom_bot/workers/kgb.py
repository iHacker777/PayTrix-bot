# payatom_bot/workers/kgb.py
from __future__ import annotations

import os
import re
import time
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..autobank_client import AutoBankClient


class KGBWorker(BaseWorker):
    """
    Kerala Gramin Bank automation:
      1) Login (username + CAPTCHA) → second factor (checkbox + password)
      2) Account Statement page -> pick account -> set dates → Search
      3) Select XLS → Generate/OK → wait .xls → upload to AutoBank as "Kerala Gramin Bank"
      4) Optional balance read from summary grid
    Expects creds loader to provide:
      cred = {
        "alias": str,
        "auth_id": str,           # canonical user id (username/login_id/user_id)
        "username": str,          # raw; may be empty
        "password": str,
        "account_number": str,
        "bank_label": str,        # mapped from alias suffix; ignored for AutoBank (we use exact text)
      }
    """

    LOGIN_URL = "https://netbanking.kgb.bank.in/"

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
        super().__init__(
            bot=bot,
            chat_id=chat_id,
            alias=alias,
            cred=cred,
            messenger=messenger,
            profile_dir=profile_dir,
        )
        self.wait = WebDriverWait(self.driver, 20)
        self.solver = two_captcha
        self.kgb_win: Optional[str] = None
        self._captcha_id: Optional[str] = None
        self.captcha_code: Optional[str] = None

    # ———————————————————
    # Thread entry
    # ———————————————————
    def run(self):
        self.info("🚀 Starting KGB automation")
        try:
            # Login once, then loop statement cycle every 60s
            self._run_with_retries(self._login, "Login")
            while not self.stop_evt.is_set():
                try:
                    self._run_with_retries(self._read_balance_and_navigate_to_statement, "Navigate statement")
                    self._run_with_retries(self._download_and_upload_statement, "Download+Upload")
                except Exception as e:
                    # Any failure in the steady loop: screenshot and keep going after tab cycle
                    self.error(f"KGB cycle error: {e!r}")
                    self.screenshot_all_tabs("KGB cycle error")
                    self._cycle_tabs()
                    self._run_with_retries(self._login, "Re-login")
                # steady cadence
                time.sleep(60)
        finally:
            self.stop()

    # ———————————————————
    # Steps
    # ———————————————————
    def _login(self):
        d = self.driver
        w = self.wait

        # 1) Open login page and wait user id field
        d.get(self.LOGIN_URL)
        w.until(EC.presence_of_element_located((By.ID, "AuthenticationFG.USER_PRINCIPAL")))
        user = (self.cred.get("auth_id") or self.cred.get("username") or "").strip()
        if not user:
            raise RuntimeError("Missing username/auth_id for KGB login")
        d.find_element(By.ID, "AuthenticationFG.USER_PRINCIPAL").send_keys(user)

        # 2) CAPTCHA: image #IMAGECAPTCHA
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
            # Show to Telegram for manual solve (if you wire a handler to set self.captcha_code)
            self.msgr.send_photo(BytesIO(img_bytes), f"[{self.alias}] 🔐 Please solve this CAPTCHA", kind="CAPTCHA")
            raise TimeoutException("CAPTCHA not solved — add your manual flow if needed.")

        d.find_element(By.ID, "AuthenticationFG.VERIFICATION_CODE").send_keys(self.captcha_code)

        # 3) Click visible STU_VALIDATE_CREDENTIALS
        login_btn = None
        for btn in d.find_elements(By.ID, "STU_VALIDATE_CREDENTIALS"):
            if btn.is_displayed() and btn.is_enabled():
                login_btn = btn
                break
        if login_btn is None:
            raise TimeoutException("Could not find visible STU_VALIDATE_CREDENTIALS button")

        d.execute_script("arguments[0].scrollIntoView({block:'center'});", login_btn)
        time.sleep(0.2)
        try:
            login_btn.click()
        except Exception:
            d.execute_script("arguments[0].click();", login_btn)

        # 4) If CAPTCHA wrong, error appears under span.errorCodeWrapper
        try:
            err = WebDriverWait(d, 5).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "span.errorCodeWrapper p[style='display: inline']"))
            )
            if "enter the characters" in (err.text or "").lower():
                if self._captcha_id:
                    try:
                        self.solver.report_bad(self._captcha_id)
                    except Exception:
                        pass
                raise TimeoutException("CAPTCHA incorrect")
        except TimeoutException:
            pass  # no error displayed — continue

        # 5) Second factor: click checkbox then fill password and submit by ENTER
        checkbox_span = WebDriverWait(d, 30).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "span.span-checkbox"))
        )
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", checkbox_span)
        time.sleep(0.2)
        try:
            checkbox_span.click()
        except Exception:
            d.execute_script("arguments[0].click();", checkbox_span)

        pwd = d.find_element(By.ID, "AuthenticationFG.ACCESS_CODE")
        pwd.send_keys(self.cred["password"])
        pwd.send_keys("\n")

        # 6) Logged in once left nav "Account Statement" becomes clickable
        WebDriverWait(d, 20).until(EC.element_to_be_clickable((By.LINK_TEXT, "Account Statement")))
        self.kgb_win = d.current_window_handle
        self.logged_in = True
        self.info("✅ Logged in to KGB")

    def _read_balance_and_navigate_to_statement(self):
        d = self.driver
        w = self.wait

        # Ensure we’re on the main KGB window
        if self.kgb_win:
            d.switch_to.window(self.kgb_win)

        # Left-nav → Account Statement
        link = w.until(EC.element_to_be_clickable((By.LINK_TEXT, "Account Statement")))
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", link)
        time.sleep(0.2)
        try:
            link.click()
        except Exception:
            d.execute_script("arguments[0].click();", link)

        # Wait for accounts table
        WebDriverWait(d, 20).until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, "table tbody tr")))

        acct_no = (self.cred.get("account_number") or "").strip()
        rows = d.find_elements(By.CSS_SELECTOR, "table tbody tr")
        found = False
        for row in rows:
            tds = row.find_elements(By.TAG_NAME, "td")
            if not tds:
                continue
            if tds[0].text.strip() == acct_no:
                # Try to read “Available” balance in this row
                try:
                    bal_span = row.find_element(By.CSS_SELECTOR, "span.hwgreentxt.amountRightAlign")
                    available = bal_span.text.strip()
                except NoSuchElementException:
                    # fallback: last line in 4th cell, last token
                    txt = (tds[3].text or "").splitlines()
                    available = (txt[-1].split()[-1] if txt else "").strip()

                if available:
                    self.info(f"💰: {available}")
                    self.last_balance = available

                # Click the account nickname to navigate to statement page
                try:
                    acct_link = row.find_element(By.XPATH, ".//a[@title='Account Nickname']")
                except NoSuchElementException:
                    acct_link = tds[1].find_element(By.TAG_NAME, "a")

                d.execute_script("arguments[0].scrollIntoView({block:'center'});", acct_link)
                time.sleep(0.2)
                try:
                    acct_link.click()
                except Exception:
                    d.execute_script("arguments[0].click();", acct_link)

                found = True
                break

        if not found:
            raise RuntimeError(f"Account number {acct_no!r} not found in summary grid")

    def _download_and_upload_statement(self):
        d = self.driver
        w = self.wait

        # Wait for date inputs on the statement page
        w.until(EC.presence_of_element_located(
            (By.ID, "PageConfigurationMaster_RXACBSW__1:TransactionHistoryFG.FROM_TXN_DATE")
        ))

        # Dates: custom if set, else your 6AM cutoff rule
        if hasattr(self, "from_dt") and hasattr(self, "to_dt"):
            dt_from, dt_to = self.from_dt, self.to_dt
        else:
            now = datetime.now()
            dt_from = now - timedelta(days=1) if now.hour < 6 else now
            dt_to = now

        from_str = dt_from.strftime("%d/%m/%Y")
        to_str = dt_to.strftime("%d/%m/%Y")

        # Fill From date
        from_input = d.find_element(By.ID, "PageConfigurationMaster_RXACBSW__1:TransactionHistoryFG.FROM_TXN_DATE")
        d.execute_script("arguments[0].removeAttribute('readonly')", from_input)
        d.execute_script("arguments[0].value = arguments[1]", from_input, from_str)

        # Fill To date
        to_input = d.find_element(By.ID, "PageConfigurationMaster_RXACBSW__1:TransactionHistoryFG.TO_TXN_DATE")
        d.execute_script("arguments[0].removeAttribute('readonly')", to_input)
        d.execute_script("arguments[0].value = arguments[1]", to_input, to_str)

        time.sleep(0.5)

        # Click Search
        search_btn = w.until(EC.element_to_be_clickable((By.ID, "PageConfigurationMaster_RXACBSW__1:SEARCH")))
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", search_btn)
        time.sleep(0.2)
        try:
            search_btn.click()
        except Exception:
            d.execute_script("arguments[0].click();", search_btn)

        # Handle “no transactions” transient error up to 3 attempts
        attempts = 0
        while attempts < 3:
            time.sleep(2)
            try:
                err_box = d.find_element(By.CSS_SELECTOR, "div.error-box, .errormessages")
                if "do not exist for the account" in (err_box.text or ""):
                    attempts += 1
                    self.info(f"⚠️ No transactions found; retrying search… ({attempts}/3)")
                    d.execute_script("arguments[0].scrollIntoView({block:'center'});", search_btn)
                    time.sleep(1)
                    try:
                        search_btn.click()
                    except Exception:
                        d.execute_script("arguments[0].click();", search_btn)
                    continue
            except Exception:
                pass
            break
        else:
            raise TimeoutException("No transactions after 3 attempts")

        # Ensure the OUTFORMAT <select> exists (may be hidden by UI library)
        w.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'select[name="TransactionHistoryFG.OUTFORMAT"]')))
        select_elem = d.find_element(By.CSS_SELECTOR, 'select[name="TransactionHistoryFG.OUTFORMAT"]')

        # Force-select “XLS” via JS to bypass fancy dropdown wrappers
        d.execute_script("""
            const s = arguments[0];
            for (let i=0;i<s.options.length;i++){
                const t = (s.options[i].text || '').trim();
                if (t === 'XLS'){ s.selectedIndex = i; s.dispatchEvent(new Event('change', {bubbles:true})); break; }
            }
        """, select_elem)

        # Click the OK/Generate button to trigger download
        ok_btn = w.until(EC.element_to_be_clickable(
            (By.ID, "PageConfigurationMaster_RXACBSW__1:GENERATE_REPORT")
        ))
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", ok_btn)
        time.sleep(0.2)
        try:
            ok_btn.click()
        except Exception:
            d.execute_script("arguments[0].click();", ok_btn)

        # Wait for a NEW .xls file with stable size
        end_time = time.time() + 90
        before = set(os.listdir(self.download_dir))
        xls_path = None
        while time.time() < end_time:
            candidates = [f for f in os.listdir(self.download_dir)
                          if f.lower().endswith(".xls") and f not in before]
            if candidates:
                newest = max(
                    candidates,
                    key=lambda f: os.path.getmtime(os.path.join(self.download_dir, f))
                )
                full = os.path.join(self.download_dir, newest)
                try:
                    s1 = os.path.getsize(full)
                    time.sleep(1.0)
                    s2 = os.path.getsize(full)
                    if s1 == s2:
                        xls_path = full
                        break
                except FileNotFoundError:
                    pass
            time.sleep(0.5)

        if not xls_path:
            raise TimeoutException("Timed out waiting for KGB XLS download")

        # Upload to AutoBank (label must match dropdown text exactly)
        original = d.current_window_handle
        d.execute_script("window.open('about:blank');")
        upload_tab = [h for h in d.window_handles if h != original][-1]

        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                d.switch_to.window(upload_tab)
                AutoBankClient(d).upload("Kerala Gramin Bank", self.cred["account_number"], xls_path)
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

        # Return to KGB tab and close the upload tab
        try:
            d.switch_to.window(original)
            for h in list(d.window_handles):
                if h != original:
                    d.switch_to.window(h)
                    d.close()
            d.switch_to.window(original)
        except Exception:
            pass
