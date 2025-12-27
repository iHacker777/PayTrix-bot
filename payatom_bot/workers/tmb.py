from __future__ import annotations
import time
import re
from io import BytesIO

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..autobank_client import AutoBankClient

class TMBWorker(BaseWorker):
    # No hardcoded BANK_LABEL — use cred["bank_label"]

    def __init__(self, *, bot, chat_id: int, alias: str, cred: dict, messenger, profile_dir: str, two_captcha: TwoCaptcha):
        super().__init__(bot=bot, chat_id=chat_id, alias=alias, cred=cred, messenger=messenger, profile_dir=profile_dir)
        self.wait = WebDriverWait(self.driver, 20)
        self.solver = two_captcha
        self.tmb_win = None
        self.captcha_id = None
        self.captcha_code = None

    def run(self):
        self.info("🚀 Starting TMB automation")
        try:
            self._run_with_retries(self._login, "Login")
            while not self.stop_evt.is_set():
                self._run_with_retries(self._balance_and_download, "Statement cycle")
                time.sleep(60)
        except Exception:
            self.error("❌ Too many failures. Stopping.")
        finally:
            self.stop()

    def _login(self):
        d = self.driver
        w = self.wait

        d.get("https://www.tmbnet.in/")
        w.until(EC.element_to_be_clickable((By.LINK_TEXT, "Net Banking Login"))).click()

        # Multiple landing variants
        try:
            w.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.login-button.btn-tmb-primary"))).click()
        except TimeoutException:
            try:
                w.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Continue to Login')]"))).click()
            except TimeoutException:
                pass

        # Use your canonical auth_id (username/login_id/user_id) + password
        w.until(EC.presence_of_element_located((By.NAME, "AuthenticationFG.USER_PRINCIPAL")))
        d.find_element(By.NAME, "AuthenticationFG.USER_PRINCIPAL").send_keys(self.cred["auth_id"])
        d.find_element(By.NAME, "AuthenticationFG.ACCESS_CODE").send_keys(self.cred["password"])

        # CAPTCHA
        img = w.until(EC.presence_of_element_located((By.ID, "IMAGECAPTCHA")))
        image_bytes = img.screenshot_as_png
        self.info("🤖 Solving CAPTCHA via 2Captcha…")
        sol, cid = (None, None)
        if self.solver and self.solver.key:
            sol, cid = self.solver.solve(image_bytes)
        if sol:
            self.captcha_code, self.captcha_id = sol, cid
            self.info(f"✅ Auto-solved: `{sol}`")
        else:
            self.msgr.send_photo(BytesIO(image_bytes), f"[{self.alias}] 🔐 Please solve this CAPTCHA", kind="CAPTCHA")
            # If you support manual entry via Telegram, replace the next line with your waiting loop
            raise TimeoutException("CAPTCHA not solved (hook manual flow here)")

        d.find_element(By.NAME, "AuthenticationFG.VERIFICATION_CODE").send_keys(self.captcha_code)
        d.find_element(By.ID, "VALIDATE_CREDENTIALS").click()

        w.until(EC.any_of(
            EC.element_to_be_clickable((By.ID, "Account_Summary")),
            EC.presence_of_element_located((By.XPATH, "//*[contains(., 'My Accounts')]"))
        ))
        self.tmb_win = d.current_window_handle
        self.logged_in = True
        self.info("✅ Logged in!")

    def _balance_and_download(self):
        d = self.driver
        w = self.wait

        # (Optional) Balance
        try:
            w.until(EC.element_to_be_clickable((By.ID, "Account_Summary"))).click()
            w.until(EC.presence_of_element_located((By.XPATH, "//h1[contains(.,'My Accounts')]")))
            row = w.until(EC.presence_of_element_located((By.CSS_SELECTOR, "#SummaryList tr.listwhiterow")))
            tds = row.find_elements(By.TAG_NAME, "td")
            if len(tds) >= 3:
                self.last_balance = tds[2].text
                self.info(f"💰 Balance: {self.last_balance}")
        except Exception:
            self.info("Balance read skipped.")

        # Statement → Search → XLS
        w.until(EC.element_to_be_clickable((By.LINK_TEXT, "Account Statement"))).click()
        w.until(EC.any_of(
            EC.text_to_be_present_in_element((By.CSS_SELECTOR, "#PgHeading h1"), "My Transactions"),
            EC.presence_of_element_located((By.XPATH, "//*[contains(.,'My Transactions')]"))
        ))

        btn = w.until(EC.element_to_be_clickable((By.ID, "SEARCH")))
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
        btn.click()

        # Pages (best effort)
        try:
            ele = WebDriverWait(d, 5).until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(),'Page') and contains(text(),'of')]")))
            m = re.search(r"Page\s+\d+\s+of\s+(\d+)", ele.text or "")
            if m:
                self.info(f"Pages: {m.group(1)}")
        except Exception:
            pass

        fmt = w.until(EC.presence_of_element_located((By.CSS_SELECTOR, "select[id$='.OUTFORMAT']")))
        Select(fmt).select_by_visible_text("XLS")

        clicked = False
        for by, loc in ((By.NAME, "Action.CUSTOM_GENERATE_REPORTS"), (By.ID, "okButton"), (By.XPATH, "//input[@value='Download']")):
            try:
                w.until(EC.element_to_be_clickable((by, loc))).click()
                clicked = True
                break
            except Exception:
                continue
        if not clicked:
            raise TimeoutException("No download button found")

        xls_path = self.wait_newest_file(".xls", timeout=60)
        if not xls_path:
            raise TimeoutException("XLS download timeout")

        # Upload with the bank label inferred from alias
        original = d.current_window_handle
        d.execute_script("window.open();")
        new_tab = [h for h in d.window_handles if h != original][-1]
        d.switch_to.window(new_tab)
        try:
            AutoBankClient(d).upload(self.cred["bank_label"], self.cred["account_number"], xls_path)
            self.info("✅ AutoBank upload succeeded")
        finally:
            d.close()
            d.switch_to.window(original)
