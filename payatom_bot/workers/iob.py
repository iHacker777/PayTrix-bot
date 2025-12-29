# payatom_bot/workers/iob.py
"""
Indian Overseas Bank (Retail + Corporate) worker with robust error handling.

Features:
- Automatic error recovery with retries
- Professional error messages with screenshots
- Safe operations for non-critical tasks
- Comprehensive logging
- Context-aware error reporting
"""
from __future__ import annotations

import os
import re
import time
import logging
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional
from telegram.constants import ParseMode
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, ElementClickInterceptedException

from ..cipherbank_client import get_cipherbank_client 
from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..autobank_client import AutoBankClient
from ..error_handler import (
    worker_method_error_wrapper,
    ErrorContext,
    safe_operation,
)

logger = logging.getLogger(__name__)


class IOBWorker(BaseWorker):
    """
    Indian Overseas Bank (Retail + Corporate).

    Decides 'personal' vs 'corporate' by alias suffix or bank_label from creds.

    CSV schema used:
        alias,login_id,user_id,username,password,account_number

    cred fields available (via creds loader):
        cred["auth_id"]         # canonical user (username/login_id/user_id)
        cred["username"]        # raw
        cred["login_id"]        # raw (corp)
        cred["user_id"]         # raw (corp)
        cred["password"]
        cred["account_number"]
        cred["bank_label"]      # "IOB" OR "IOB CORPORATE" (derived from alias)
    """

    LOGIN_URL = "https://netbanking.iob.bank.in/ibanking/html/index.html"

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
        self.iob_win: Optional[str] = None
        self._captcha_id: Optional[str] = None
        self.captcha_code: Optional[str] = None

    # ------------------------------------------------------------------
    # Robust tab-cycling with error handling (PRESERVED BUT NOT USED)
    # ------------------------------------------------------------------
    def _cycle_tabs(self) -> None:
        """
        Close all existing tabs, open a fresh about:blank tab and reset
        login state with robust error handling.
        
        NOTE: Currently not used as AutoBank uploads are disabled.
        """
        d = self.driver
        
        with ErrorContext(
            "cycling browser tabs",
            messenger=self.msgr,
            alias=self.alias,
            reraise=False
        ):
            handles_before = safe_operation(
                lambda: list(d.window_handles),
                context=f"get window handles for {self.alias}",
                default=[]
            )
            
            if not handles_before:
                logger.warning("IOB %s: no windows to cycle; driver may be closed", self.alias)
                return

            # 1) Open a new blank tab
            safe_operation(
                lambda: d.execute_script("window.open('about:blank','_blank');"),
                context=f"open new tab for {self.alias}",
                default=None
            )
            time.sleep(0.5)

            # 2) Find the newly opened handle
            handles_after = safe_operation(
                lambda: list(d.window_handles),
                context=f"get new window handles for {self.alias}",
                default=handles_before
            )
            
            new_handle = None
            for h in handles_after:
                if h not in handles_before:
                    new_handle = h
                    break

            if not new_handle:
                logger.error("IOB %s: failed to locate new tab during cycle", self.alias)
                return

            # 3) Close every old tab
            for h in handles_before:
                try:
                    d.switch_to.window(h)
                    d.close()
                except Exception as e:
                    logger.debug("IOB %s: failed to close old tab: %s", self.alias, e)

            # 4) Switch into the fresh tab and reset state
            try:
                d.switch_to.window(new_handle)
                self.iob_win = new_handle
                self.captcha_code = None
                self.logged_in = False
                self.info("🔄 IOB: cycled tabs – will re-login on next loop")
            except Exception as e:
                logger.error("IOB %s: failed to switch to new tab: %s", self.alias, e)
                self.stop_evt.set()

    # ------------------------------------------------------------------
    # Detect "You are Logged OUT..." page with error handling
    # ------------------------------------------------------------------
    def _check_logged_out_and_cycle(self) -> None:
        """
        Check if the current page shows the IOB 'You are Logged OUT' message.
        If detected, immediately cycle tabs and force a retry.
        """
        source = safe_operation(
            lambda: self.driver.page_source,
            context=f"get page source for {self.alias}",
            default=""
        )
        
        if source and "You are Logged OUT of internet banking due to ANY of the following reasons" in source:
            self.info("IOB: detected logged-out page; cycling tabs and retrying login")
            self._cycle_tabs()
            raise TimeoutException("IOB logged out (server message)")

    # ———————————————————
    # Public thread entry with robust error handling
    # ———————————————————
    def run(self) -> None:
        """Main worker loop with comprehensive error handling."""
        self.info("🚀 Starting IOB automation")
        retry_count = 0
        max_retries = 5
        
        try:
            while not self.stop_evt.is_set():
                try:
                    # Fresh login for each outer loop
                    self._login()
                    retry_count = 0  # reset after successful login

                    # Steady-state: download → upload → balance → sleep
                    while not self.stop_evt.is_set():
                        # Check if server has logged us out
                        self._check_logged_out_and_cycle()

                        # 1) Download + upload statement (with internal retries)
                        self._download_and_upload_statement()

                        # Check again before balance enquiry
                        self._check_logged_out_and_cycle()

                        # 2) Balance enquiry (best-effort; don't crash on failure)
                        balance_result = safe_operation(
                            self._balance_enquiry,
                            context=f"balance enquiry for {self.alias}",
                            default=None
                        )
                        
                        if balance_result is None:
                            self.info("ℹ️ Balance enquiry skipped (selector/layout change)")

                        time.sleep(60)  # steady-state sleep
                        
                except TimeoutException as e:
                    # Logged-out or timeout - increment retry and continue
                    retry_count += 1
                    logger.warning(
                        "IOB %s timeout/logged-out (retry %d/%d): %s",
                        self.alias,
                        retry_count,
                        max_retries,
                        e
                    )
                    
                    if retry_count > max_retries:
                        self.error(f"❌ Too many failures ({max_retries}). Stopping IOB worker.")
                        return
                    
                    # Screenshot and reset
                    try:
                        self.screenshot_all_tabs(f"IOB error - retry {retry_count}/{max_retries}")
                    except Exception:
                        pass
                    
                    self._cycle_tabs()
                    
                except Exception as e:
                    retry_count += 1
                    self.error(
                        f"⚠️ IOB loop error (retry {retry_count}/{max_retries}): "
                        f"{type(e).__name__}: {e}"
                    )
                    
                    try:
                        self.screenshot_all_tabs("IOB error")
                    except Exception:
                        pass

                    if retry_count > max_retries:
                        self.error(f"❌ Too many failures ({max_retries}). Stopping IOB worker.")
                        return

                    self._cycle_tabs()
                    
        finally:
            self.stop()

    # ———————————————————
    # Steps with error handling
    # ———————————————————
    @worker_method_error_wrapper
    def _login(self) -> None:
        """Login to IOB with automatic error handling and screenshots."""
        d = self.driver
        w = self.wait

        with ErrorContext("opening IOB login page", messenger=self.msgr, alias=self.alias):
            # 1) Open login page
            d.get(self.LOGIN_URL)

        with ErrorContext("clicking continue to internet banking", messenger=self.msgr, alias=self.alias):
            # 2) Click "Continue to Internet Banking Home Page"
            w.until(
                EC.element_to_be_clickable((By.LINK_TEXT, "Continue to Internet Banking Home Page"))
            ).click()

        # 3) Choose personal vs corporate
        is_corp = False
        bank_label = (self.cred.get("bank_label") or "").upper().strip()
        if bank_label == "IOB CORPORATE" or self.alias.lower().endswith("_iobcorp"):
            is_corp = True
        role_text = "Corporate Login" if is_corp else "Personal Login"
        
        with ErrorContext(f"selecting {role_text}", messenger=self.msgr, alias=self.alias):
            w.until(EC.element_to_be_clickable((By.LINK_TEXT, role_text))).click()

        # 4) Fill credentials
        with ErrorContext("filling login credentials", messenger=self.msgr, alias=self.alias):
            if is_corp:
                # Corporate uses separate loginId + userId + password
                d.find_element(By.NAME, "loginId").send_keys(self.cred.get("login_id", ""))
                d.find_element(By.NAME, "userId").send_keys(self.cred.get("user_id", ""))
                d.find_element(By.NAME, "password").send_keys(self.cred["password"])
            else:
                # Retail takes loginId + password
                user = self.cred.get("auth_id") or self.cred.get("username") or ""
                d.find_element(By.NAME, "loginId").send_keys(user)
                d.find_element(By.NAME, "password").send_keys(self.cred["password"])

        # 5) Captcha image
        with ErrorContext("capturing CAPTCHA image", messenger=self.msgr, alias=self.alias):
            img = WebDriverWait(d, 10).until(
                EC.presence_of_element_located((By.ID, "captchaimg"))
            )
            # Scroll into view
            d.execute_script("arguments[0].scrollIntoView(true);", img)
            time.sleep(1)

            # Re-locate after scroll
            img = WebDriverWait(d, 10).until(
                EC.visibility_of_element_located((By.ID, "captchaimg"))
            )
            img_bytes = img.screenshot_as_png

        # 6) Solve captcha
        with ErrorContext("solving CAPTCHA", messenger=self.msgr, alias=self.alias):
            self.info("🤖 Solving CAPTCHA via 2Captcha…")
            solution, cid = (None, None)
            if self.solver and safe_operation(lambda: self.solver.key, context="get 2Captcha key", default=None):
                solution, cid = safe_operation(
                    lambda: self.solver.solve(img_bytes, min_len=6, max_len=6, regsense=True),
                    context="2Captcha solve",
                    default=(None, None)
                )

            if solution:
                normalized = re.sub(r"\s+", "", solution).upper()
                self.captcha_code, self._captcha_id = normalized, cid
                self.info(f"✅ Auto-solved: `{normalized}`")
            else:
                self.msgr.send_photo(
                    BytesIO(img_bytes),
                    f"[{self.alias}] 🔐 Please solve captcha",
                    kind="CAPTCHA",
                )
                raise TimeoutException("CAPTCHA not solved – add your manual flow if needed.")

        # 7) Fill the captcha
        with ErrorContext("entering CAPTCHA solution", messenger=self.msgr, alias=self.alias):
            field = d.find_element(By.NAME, "captchaid")
            field.clear()
            field.send_keys((self.captcha_code or "").strip().upper())

        # 8) Submit
        with ErrorContext("submitting login form", messenger=self.msgr, alias=self.alias):
            d.find_element(By.ID, "btnSubmit").click()

        # 8a) Check for wrong captcha
        try:
            err_span = WebDriverWait(d, 5).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "div.otpmsg span.red"))
            )
            if (
                "captcha entered is incorrect" in (err_span.text or "").lower()
                and self._captcha_id
            ):
                self.error("❌ CAPTCHA wrong — reporting to 2Captcha and retrying…")
                if self.solver:
                    safe_operation(
                        lambda: self.solver.report_bad(self._captcha_id),
                        context="report bad CAPTCHA",
                        default=None
                    )
                self._cycle_tabs()
                raise TimeoutException("Captcha incorrect")
        except TimeoutException:
            # no error shown → carry on to dashboard
            pass

        # 9) Wait for main nav (logged in)
        with ErrorContext("waiting for login confirmation", messenger=self.msgr, alias=self.alias):
            w.until(EC.presence_of_element_located((By.CSS_SELECTOR, "nav.accordian")))
            self.iob_win = d.current_window_handle
            self.logged_in = True
            self.info("✅ Logged in to IOB!")

    @worker_method_error_wrapper
    def _download_and_upload_statement(self) -> None:
        """Download statement and upload to CipherBank with error handling."""
        d = self.driver

        # 1) Navigate to "Account statement"
        with ErrorContext("navigating to Account Statement", messenger=self.msgr, alias=self.alias):
            stmt_link = WebDriverWait(d, 60).until(
                EC.element_to_be_clickable((By.LINK_TEXT, "Account statement"))
            )
            d.execute_script("arguments[0].scrollIntoView({block:'center'});", stmt_link)
            time.sleep(0.3)
            try:
                stmt_link.click()
            except ElementClickInterceptedException:
                d.execute_script("arguments[0].click();", stmt_link)
            time.sleep(3)

        # 2) Pick the right account
        with ErrorContext("selecting account", messenger=self.msgr, alias=self.alias):
            acct_sel = self.wait.until(EC.element_to_be_clickable((By.ID, "accountNo")))
            dropdown = Select(acct_sel)
            acct_no = (self.cred.get("account_number") or "").strip()
            if acct_no:
                for opt in dropdown.options:
                    if opt.text.strip().startswith(acct_no):
                        dropdown.select_by_visible_text(opt.text)
                        break

        # 3) Compute date window
        now = datetime.now()
        from_dt = now - timedelta(days=1) if now.hour < 6 else now
        to_dt = now
        from_str = from_dt.strftime("%m/%d/%Y")
        to_str = to_dt.strftime("%m/%d/%Y")

        # 4) Fill "From Date"
        with ErrorContext("setting from date", messenger=self.msgr, alias=self.alias):
            from_input = self.wait.until(EC.presence_of_element_located((By.ID, "fromDate")))
            d.execute_script("arguments[0].removeAttribute('readonly')", from_input)
            d.execute_script("arguments[0].value = arguments[1]", from_input, from_str)

        # 5) Fill "To Date"
        with ErrorContext("setting to date", messenger=self.msgr, alias=self.alias):
            to_input = self.wait.until(EC.presence_of_element_located((By.ID, "toDate")))
            d.execute_script("arguments[0].removeAttribute('readonly')", to_input)
            d.execute_script("arguments[0].value = arguments[1]", to_input, to_str)

        # 6) Click "View"
        with ErrorContext("clicking View button", messenger=self.msgr, alias=self.alias):
            view_btn = self.wait.until(
                EC.element_to_be_clickable((By.ID, "accountstatement_view"))
            )
            d.execute_script("arguments[0].scrollIntoView({block:'center'});", view_btn)
            time.sleep(0.3)
            try:
                view_btn.click()
            except ElementClickInterceptedException:
                d.execute_script("arguments[0].click();", view_btn)

        # 7) Export CSV
        with ErrorContext("exporting CSV", messenger=self.msgr, alias=self.alias):
            csv_btn = WebDriverWait(d, 20).until(
                EC.element_to_be_clickable((By.ID, "accountstatement_csvAcctStmt"))
            )
            d.execute_script("arguments[0].scrollIntoView({block:'center'});", csv_btn)
            time.sleep(0.3)
            try:
                csv_btn.click()
            except ElementClickInterceptedException:
                d.execute_script("arguments[0].click();", csv_btn)

        # 8) Wait for CSV download
        time.sleep(3)
        with ErrorContext("waiting for CSV download", messenger=self.msgr, alias=self.alias):
            csv_path = self.wait_newest_file(".csv", timeout=60.0)
            if not csv_path:
                raise TimeoutException("Timed out waiting for IOB CSV download")
            self.info(f"📥 Downloaded CSV: {os.path.basename(csv_path)}")
        
        time.sleep(5)

        # ============================================================
        # 9) Upload to AutoBank (DISABLED - COMMENTED OUT)
        # ============================================================
        # original_handle = d.current_window_handle
        # 
        # with ErrorContext("opening AutoBank upload tab", messenger=self.msgr, alias=self.alias):
        #     d.execute_script("window.open('about:blank');")
        #     autobank_handle = [h for h in d.window_handles if h != original_handle][-1]
        # 
        # max_attempts = 5
        # for attempt in range(1, max_attempts + 1):
        #     with ErrorContext(
        #         f"uploading to AutoBank (attempt {attempt}/{max_attempts})",
        #         messenger=self.msgr,
        #         alias=self.alias,
        #         reraise=(attempt == max_attempts)
        #     ):
        #         d.switch_to.window(autobank_handle)
        #         AutoBankClient(d).upload("IOB", acct_no, csv_path)
        #         self.info(f"✅ AutoBank upload succeeded (attempt {attempt}/{max_attempts})")
        #         break
        # 
        # # Return to IOB tab
        # with ErrorContext("closing upload tab", messenger=self.msgr, alias=self.alias, reraise=False):
        #     d.switch_to.window(original_handle)
        #     for h in list(d.window_handles):
        #         if h != original_handle:
        #             d.switch_to.window(h)
        #             d.close()
        #     d.switch_to.window(original_handle)

        # ============================================================
        # 10) Upload to CipherBank (ACTIVE)
        # ============================================================
        max_attempts = 5
        cipherbank = get_cipherbank_client()
        
        if cipherbank:
            for attempt in range(1, max_attempts + 1):
                with ErrorContext(
                    f"uploading to CipherBank (attempt {attempt}/{max_attempts})",
                    messenger=self.msgr,
                    alias=self.alias,
                    reraise=False  # Don't crash worker on CipherBank failure
                ):
                    cipherbank.upload_statement(
                        bank_code=self.cred["bank_label"],
                        account_number=self.cred["account_number"],
                        file_path=csv_path,
                        alias=self.alias,
                    )
                    self.info(f"✅ CipherBank upload succeeded (attempt {attempt}/{max_attempts})")
                    break  # Success - exit retry loop
                
                # If we get here, the attempt failed
                if attempt < max_attempts:
                    self.info(f"⏳ Retrying CipherBank upload in 2 seconds...")
                    time.sleep(2)
                else:
                    # Final attempt failed
                    self.error(
                        f"❌ CipherBank upload failed after {max_attempts} attempts. "
                        "Continuing with next cycle."
                    )
        else:
            logger.debug("CipherBank client not available - skipping upload for %s", self.alias)

    def _balance_enquiry(self) -> None:
        """
        Fetch balance from IOB - this is best-effort and won't crash the worker.
        Use safe_operation in the caller for extra safety.
        """
        d = self.driver

        # ============================================================
        # Make sure we're on the IOB tab (DISABLED - NOT NEEDED WITHOUT AUTOBANK)
        # ============================================================
        # if self.iob_win:
        #     with ErrorContext("switching to IOB window", messenger=self.msgr, alias=self.alias):
        #         d.switch_to.window(self.iob_win)

        # Scroll back to top
        with ErrorContext("scrolling to top", messenger=self.msgr, alias=self.alias, reraise=False):
            d.execute_script("window.scrollTo(0, 0);")
            time.sleep(0.5)

        # Locate Balance Enquiry link
        with ErrorContext("navigating to Balance Enquiry", messenger=self.msgr, alias=self.alias):
            balance_link = WebDriverWait(d, 60).until(
                EC.element_to_be_clickable((By.LINK_TEXT, "Balance Enquiry"))
            )
            d.execute_script("arguments[0].scrollIntoView({block: 'center'});", balance_link)
            time.sleep(0.3)
            try:
                balance_link.click()
            except Exception:
                d.execute_script("arguments[0].click();", balance_link)

        # Click the specific account link
        acctno = (self.cred.get("account_number") or "").strip()
        with ErrorContext("clicking account link", messenger=self.msgr, alias=self.alias):
            wait_long = WebDriverWait(d, 180)
            if acctno:
                acct_link = wait_long.until(
                    EC.element_to_be_clickable(
                        (By.XPATH, f"//a[contains(@href,'getBalance') and contains(.,'{acctno}')]")
                    )
                )
            else:
                acct_link = wait_long.until(
                    EC.element_to_be_clickable((By.XPATH, "//a[contains(@href,'getBalance')]"))
                )

            d.execute_script("arguments[0].scrollIntoView({block:'center'});", acct_link)
            time.sleep(0.2)
            try:
                acct_link.click()
            except Exception:
                d.execute_script("arguments[0].click();", acct_link)

        # Wait for popup and read balance
        with ErrorContext("reading balance", messenger=self.msgr, alias=self.alias, reraise=False):
            tbl = WebDriverWait(d, 180).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "#dialogtbl table tr.querytr td"))
            )
            available = (tbl.text or "").strip()
            if available:
                self.info(f"💰 Balance: {available}")
                self.last_balance = available

        # Remove modal overlay
        with ErrorContext("removing modal overlay", messenger=self.msgr, alias=self.alias, reraise=False):
            d.execute_script(
                "document.querySelectorAll('.ui-widget-overlay, #dialogtbl').forEach(el => el.remove());"
            )

        # Navigate back to Account statement
        with ErrorContext("navigating back to Account Statement", messenger=self.msgr, alias=self.alias, reraise=False):
            stmt_link = WebDriverWait(d, 60).until(
                EC.element_to_be_clickable((By.LINK_TEXT, "Account statement"))
            )
            d.execute_script("arguments[0].scrollIntoView({block:'center'});", stmt_link)
            time.sleep(0.2)
            try:
                stmt_link.click()
            except Exception:
                d.execute_script("arguments[0].click();", stmt_link)