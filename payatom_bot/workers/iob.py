# payatom_bot/workers/iob.py
"""
Indian Overseas Bank (Retail + Corporate) automation worker.

Supports both retail and corporate banking interfaces with:
- Automatic CAPTCHA solving with 2Captcha integration
- Session management with logged-out detection
- Robust error recovery with retries and screenshots
- CipherBank statement upload integration
- Balance monitoring with alerts
- Graceful shutdown handling for clean stop operations

Architecture:
- Inherits from BaseWorker for common Selenium/Telegram functionality
- Uses ErrorContext for comprehensive error handling
- Thread-safe operations for concurrent worker management
- Race condition protection for clean shutdown
"""
from __future__ import annotations

import os
import re
import time
import logging
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, ElementClickInterceptedException

from ..cipherbank_client import get_cipherbank_client 
from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..error_handler import ErrorContext, safe_operation

logger = logging.getLogger(__name__)


class IOBWorker(BaseWorker):
    """
    Indian Overseas Bank (Retail + Corporate) automation worker.
    
    Determines retail vs corporate mode based on alias suffix (_iobcorp) or
    bank_label in credentials. Handles different login flows accordingly.
    
    Expected credentials (from CSV loader):
        alias: str - Account identifier
        auth_id: str - Canonical user ID (username/login_id/user_id)
        username: str - Raw username field (retail)
        login_id: str - Corporate login ID (corporate)
        user_id: str - Corporate user ID (corporate)
        password: str - Account password
        account_number: str - Bank account number
        bank_label: str - "IOB" or "IOB CORPORATE"
    """

    # Class constants
    LOGIN_URL = "https://netbanking.iob.bank.in/ibanking/html/index.html"
    
    # Timeout values (seconds)
    TIMEOUT_STANDARD = 20
    TIMEOUT_LONG = 60
    TIMEOUT_EXTRA_LONG = 180
    TIMEOUT_CAPTCHA_WAIT = 10
    TIMEOUT_ERROR_DETECTION = 5
    
    # Retry configuration
    MAX_OUTER_RETRIES = 5
    CYCLE_SLEEP_SECONDS = 60
    
    # CAPTCHA configuration
    CAPTCHA_MIN_LENGTH = 6
    CAPTCHA_MAX_LENGTH = 6

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
        """
        Initialize IOB worker.
        
        Args:
            bot: Telegram bot instance
            chat_id: Telegram chat ID for notifications
            alias: Worker alias (account identifier)
            cred: Credential dictionary from CSV loader
            messenger: Messenger instance for notifications
            profile_dir: Chrome profile directory path
            two_captcha: Optional 2Captcha solver instance
        """
        super().__init__(
            bot=bot,
            chat_id=chat_id,
            alias=alias,
            cred=cred,
            messenger=messenger,
            profile_dir=profile_dir,
        )
        self.wait = WebDriverWait(self.driver, self.TIMEOUT_STANDARD)
        self.solver = two_captcha
        self.iob_win: Optional[str] = None
        self._captcha_id: Optional[str] = None
        self.captcha_code: Optional[str] = None

    # ============================================================
    # Main Worker Loop
    # ============================================================

    def run(self) -> None:
        """
        Main worker loop with robust error handling.
        
        Continuously:
        1. Login to IOB (with retry on failure)
        2. Download and upload statements (60s cycle)
        3. Update account balance
        4. Handle session timeouts and errors
        
        Stops after MAX_OUTER_RETRIES consecutive failures.
        Includes graceful shutdown handling to prevent error spam.
        """
        self.info("Starting IOB automation")
        retry_count = 0
        
        try:
            while not self.stop_evt.is_set():
                try:
                    # Fresh login for each outer loop
                    self._login()
                    retry_count = 0  # Reset on successful login

                    # Steady-state loop
                    while not self.stop_evt.is_set():
                        # Check for server-side logout
                        self._check_logged_out_and_cycle()
                        
                        # Check stop event before expensive operations
                        if self.stop_evt.is_set():
                            logger.debug("[%s] Stop event detected - exiting loop", self.alias)
                            break

                        # Download and upload statement
                        self._download_and_upload_statement()

                        # Check again before balance enquiry
                        if self.stop_evt.is_set():
                            logger.debug("[%s] Stop event detected before balance enquiry", self.alias)
                            break
                            
                        self._check_logged_out_and_cycle()

                        # Balance enquiry (best-effort)
                        balance_result = safe_operation(
                            self._balance_enquiry,
                            context=f"balance enquiry for {self.alias}",
                            default=None
                        )
                        
                        if balance_result is None:
                            logger.debug("[%s] Balance enquiry skipped", self.alias)

                        # Check stop event before sleep
                        if self.stop_evt.is_set():
                            logger.debug("[%s] Stop event detected - skipping sleep", self.alias)
                            break
                        
                        # Interruptible sleep
                        self._interruptible_sleep(self.CYCLE_SLEEP_SECONDS)
                        
                except TimeoutException as e:
                    # If stop event is set, this is expected - don't log as error
                    if self.stop_evt.is_set():
                        logger.debug("[%s] Timeout during shutdown (expected)", self.alias)
                        break
                    
                    retry_count += 1
                    logger.warning(
                        "[%s] Timeout/logged-out (retry %d/%d): %s",
                        self.alias,
                        retry_count,
                        self.MAX_OUTER_RETRIES,
                        e
                    )
                    
                    if retry_count > self.MAX_OUTER_RETRIES:
                        self.error(
                            f"Too many failures ({self.MAX_OUTER_RETRIES}). "
                            f"Stopping IOB worker."
                        )
                        return
                    
                    # Screenshot and reset (skip if stopping)
                    if not self.stop_evt.is_set():
                        try:
                            self.screenshot_all_tabs(
                                f"IOB error - retry {retry_count}/{self.MAX_OUTER_RETRIES}"
                            )
                        except Exception:
                            pass
                    
                    self._cycle_tabs()
                    
                except Exception as e:
                    # If stop event is set, suppress Selenium connection errors
                    if self.stop_evt.is_set():
                        error_msg = str(e)
                        # Check if this is a Selenium connection error during shutdown
                        if any(indicator in error_msg for indicator in [
                            "Connection refused",
                            "Failed to establish a new connection",
                            "MaxRetryError",
                            "target machine actively refused",
                            "invalid session id",
                            "chrome not reachable",
                            "Session not created"
                        ]):
                            logger.debug(
                                "[%s] Selenium connection error during shutdown (expected): %s",
                                self.alias,
                                type(e).__name__
                            )
                            break
                    
                    retry_count += 1
                    self.error(
                        f"Loop error (retry {retry_count}/{self.MAX_OUTER_RETRIES}): "
                        f"{type(e).__name__}: {e}"
                    )
                    
                    # Screenshot (skip if stopping)
                    if not self.stop_evt.is_set():
                        try:
                            self.screenshot_all_tabs("IOB error")
                        except Exception:
                            pass

                    if retry_count > self.MAX_OUTER_RETRIES:
                        self.error(
                            f"Too many failures ({self.MAX_OUTER_RETRIES}). "
                            f"Stopping IOB worker."
                        )
                        return

                    self._cycle_tabs()
                    
        finally:
            # Only call stop() if not already stopped
            if not self.stop_evt.is_set():
                self.stop()

    # ============================================================
    # Session Management
    # ============================================================

    def _interruptible_sleep(self, seconds: float) -> None:
        """
        Sleep for specified duration while checking stop event.
        
        Allows immediate response to stop commands during sleep periods.
        
        Args:
            seconds: Number of seconds to sleep
        """
        sleep_end = time.time() + seconds
        while time.time() < sleep_end and not self.stop_evt.is_set():
            time.sleep(0.5)

    def _cycle_tabs(self) -> None:
        """
        Reset browser session by cycling tabs.
        
        Closes all existing tabs, opens a fresh about:blank tab,
        and resets login state. Used for recovery from errors
        or session timeouts.
        
        This method is actively used for error recovery throughout
        the worker lifecycle. Includes protection against shutdown
        race conditions.
        """
        # Don't cycle if stop event is set
        if self.stop_evt.is_set():
            logger.debug("[%s] Stop event set - skipping tab cycle", self.alias)
            return
        
        d = self.driver
        
        with ErrorContext(
            "cycling browser tabs",
            messenger=self.msgr,
            alias=self.alias,
            reraise=False
        ):
            # Check if driver is still alive
            try:
                _ = d.session_id
            except Exception:
                logger.debug("[%s] Driver not available for tab cycling", self.alias)
                return
            
            handles_before = safe_operation(
                lambda: list(d.window_handles),
                context=f"get window handles for {self.alias}",
                default=[]
            )
            
            if not handles_before:
                logger.warning("[%s] No windows to cycle; driver may be closed", self.alias)
                return

            # Check stop event before proceeding
            if self.stop_evt.is_set():
                logger.debug("[%s] Stop event detected during tab cycle prep", self.alias)
                return

            # Open new blank tab
            safe_operation(
                lambda: d.execute_script("window.open('about:blank','_blank');"),
                context=f"open new tab for {self.alias}",
                default=None
            )
            time.sleep(0.5)

            # Find newly opened handle
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
                logger.error("[%s] Failed to locate new tab during cycle", self.alias)
                return

            # Close all old tabs
            for h in handles_before:
                # Check stop event before each close operation
                if self.stop_evt.is_set():
                    logger.debug("[%s] Stop event detected during tab cleanup", self.alias)
                    break
                    
                try:
                    d.switch_to.window(h)
                    d.close()
                except Exception as e:
                    logger.debug("[%s] Failed to close old tab: %s", self.alias, e)

            # Switch to fresh tab and reset state
            try:
                d.switch_to.window(new_handle)
                self.iob_win = new_handle
                self.captcha_code = None
                self.logged_in = False
                self.info("Browser tabs cycled - will re-login on next loop")
            except Exception as e:
                # If stop event is set, this is expected
                if self.stop_evt.is_set():
                    logger.debug("[%s] Tab switch interrupted by stop event", self.alias)
                else:
                    logger.error("[%s] Failed to switch to new tab: %s", self.alias, e)
                    self.stop_evt.set()

    def _check_logged_out_and_cycle(self) -> None:
        """
        Detect server-side logout and force session reset.
        
        Checks for IOB's "You are Logged OUT" message in page source.
        If detected, immediately cycles tabs and raises TimeoutException
        to trigger retry logic.
        
        Raises:
            TimeoutException: If logged-out message detected
        """
        # Skip check if stopping
        if self.stop_evt.is_set():
            return
        
        source = safe_operation(
            lambda: self.driver.page_source,
            context=f"get page source for {self.alias}",
            default=""
        )
        
        if source and "You are Logged OUT of internet banking" in source:
            self.info("Detected logged-out page; cycling tabs and retrying login")
            self._cycle_tabs()
            raise TimeoutException("IOB logged out (server message)")

    # ============================================================
    # Login Flow
    # ============================================================

    def _login(self) -> None:
        """
        Login to IOB with CAPTCHA solving.
        
        Flow:
        1. Navigate to login page
        2. Click "Continue to Internet Banking"
        3. Select Personal/Corporate login mode
        4. Fill credentials (retail or corporate)
        5. Solve CAPTCHA (automatic or manual via Telegram)
        6. Submit and wait for dashboard
        
        Raises:
            RuntimeError: If login fails
            TimeoutException: If page elements not found
        """
        # Check stop event before login attempt
        if self.stop_evt.is_set():
            logger.debug("[%s] Stop event set - skipping login", self.alias)
            return
        
        d = self.driver
        w = self.wait

        # Determine login mode
        is_corp = self._is_corporate_mode()
        role_text = "Corporate Login" if is_corp else "Personal Login"

        with ErrorContext("IOB login", messenger=self.msgr, alias=self.alias):
            # Navigate to login page
            d.get(self.LOGIN_URL)

            # Click continue to internet banking
            w.until(
                EC.element_to_be_clickable(
                    (By.LINK_TEXT, "Continue to Internet Banking Home Page")
                )
            ).click()

            # Select login mode
            w.until(EC.element_to_be_clickable((By.LINK_TEXT, role_text))).click()

            # Fill credentials
            self._fill_login_credentials(is_corp)

            # Solve and submit CAPTCHA
            self._solve_and_submit_captcha()

            # Wait for successful login
            w.until(EC.presence_of_element_located((By.CSS_SELECTOR, "nav.accordian")))
            self.iob_win = d.current_window_handle
            self.logged_in = True
            self.info("Logged in to IOB successfully")

    def _is_corporate_mode(self) -> bool:
        """
        Determine if this is a corporate account.
        
        Returns:
            True if corporate mode, False for retail mode
        """
        bank_label = (self.cred.get("bank_label") or "").upper().strip()
        return (
            bank_label == "IOB CORPORATE" or 
            self.alias.lower().endswith("_iobcorp")
        )

    def _fill_login_credentials(self, is_corporate: bool) -> None:
        """
        Fill login credentials based on account type.
        
        Args:
            is_corporate: True for corporate login, False for retail
        """
        d = self.driver
        
        with ErrorContext(
            "filling login credentials",
            messenger=self.msgr,
            alias=self.alias
        ):
            if is_corporate:
                # Corporate: separate loginId + userId + password
                d.find_element(By.NAME, "loginId").send_keys(
                    self.cred.get("login_id", "")
                )
                d.find_element(By.NAME, "userId").send_keys(
                    self.cred.get("user_id", "")
                )
                d.find_element(By.NAME, "password").send_keys(
                    self.cred["password"]
                )
            else:
                # Retail: loginId + password
                user = self.cred.get("auth_id") or self.cred.get("username") or ""
                d.find_element(By.NAME, "loginId").send_keys(user)
                d.find_element(By.NAME, "password").send_keys(self.cred["password"])

def _solve_and_submit_captcha(self) -> None:
    """
    Solve CAPTCHA and submit login form.
    
    Attempts automatic solving via 2Captcha. Falls back to manual
    solving via Telegram if automatic fails.
    
    Raises:
        TimeoutException: If CAPTCHA solving fails or is incorrect
    """
    # Skip if stopping
    if self.stop_evt.is_set():
        logger.debug("[%s] Stop event set - skipping CAPTCHA solve", self.alias)
        return
    
    d = self.driver
    
    with ErrorContext("solving CAPTCHA", messenger=self.msgr, alias=self.alias):
        # Capture CAPTCHA image
        img = WebDriverWait(d, self.TIMEOUT_CAPTCHA_WAIT).until(
            EC.presence_of_element_located((By.ID, "captchaimg"))
        )
        
        # Scroll into view
        d.execute_script("arguments[0].scrollIntoView(true);", img)
        time.sleep(1)

        # Re-locate after scroll
        img = WebDriverWait(d, self.TIMEOUT_CAPTCHA_WAIT).until(
            EC.visibility_of_element_located((By.ID, "captchaimg"))
        )
        img_bytes = img.screenshot_as_png

        # Attempt automatic solving
        solution = self._solve_captcha_automatic(img_bytes)
        
        if not solution:
            # Fallback to manual solving via Telegram
            self.msgr.send_photo(
                BytesIO(img_bytes),
                f"[{self.alias}] Please solve CAPTCHA for IOB login",
                kind="CAPTCHA",
            )
            raise TimeoutException(
                "CAPTCHA not solved automatically - manual entry required"
            )

        # Fill CAPTCHA
        field = d.find_element(By.NAME, "captchaid")
        field.clear()
        field.send_keys(solution.strip().upper())

        # Submit form
        d.find_element(By.ID, "btnSubmit").click()

        # Check for incorrect CAPTCHA error (with stop event protection)
        self._check_captcha_error()

    def _solve_captcha_automatic(self, img_bytes: bytes) -> Optional[str]:
        """
        Attempt automatic CAPTCHA solving via 2Captcha.
        
        Args:
            img_bytes: CAPTCHA image bytes
            
        Returns:
            Normalized CAPTCHA solution or None if solving failed
        """
        self.info("Attempting automatic CAPTCHA solve via 2Captcha")
        
        solution, cid = (None, None)
        if self.solver and safe_operation(
            lambda: self.solver.key, 
            context="get 2Captcha key", 
            default=None
        ):
            solution, cid = safe_operation(
                lambda: self.solver.solve(
                    img_bytes,
                    min_len=self.CAPTCHA_MIN_LENGTH,
                    max_len=self.CAPTCHA_MAX_LENGTH,
                    regsense=True
                ),
                context="2Captcha solve",
                default=(None, None)
            )

        if solution:
            # Normalize: remove whitespace and uppercase
            normalized = re.sub(r"\s+", "", solution).upper()
            self.captcha_code, self._captcha_id = normalized, cid
            self.info(f"CAPTCHA solved automatically: {normalized}")
            return normalized
        
        return None

def _check_captcha_error(self) -> None:
    """
    Check for incorrect CAPTCHA error message.
    
    Raises:
        TimeoutException: If CAPTCHA was incorrect
    """
    # Skip check if stopping
    if self.stop_evt.is_set():
        logger.debug("[%s] Stop event set - skipping CAPTCHA error check", self.alias)
        return
    
    d = self.driver
    
    try:
        # Check if driver session is still valid
        try:
            _ = d.session_id
        except Exception:
            # Driver session is dead - likely due to stop event
            logger.debug("[%s] Driver session invalid - skipping CAPTCHA check", self.alias)
            return
        
        err_span = WebDriverWait(d, self.TIMEOUT_ERROR_DETECTION).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "div.otpmsg span.red")
            )
        )
        
        if (
            "captcha entered is incorrect" in (err_span.text or "").lower()
            and self._captcha_id
        ):
            self.error("CAPTCHA incorrect - reporting to 2Captcha and retrying")
            if self.solver:
                safe_operation(
                    lambda: self.solver.report_bad(self._captcha_id),
                    context="report bad CAPTCHA",
                    default=None
                )
            self._cycle_tabs()
            raise TimeoutException("CAPTCHA incorrect")
            
    except TimeoutException:
        # No error shown - login successful
        pass
    except Exception as e:
        # If stop event is set, suppress all errors
        if self.stop_evt.is_set():
            logger.debug(
                "[%s] Exception during CAPTCHA check (shutdown in progress): %s",
                self.alias,
                type(e).__name__
            )
        else:
            # Re-raise unexpected errors during normal operation
            raise

    # ============================================================
    # Statement Download and Upload
    # ============================================================

    def _download_and_upload_statement(self) -> None:
        """
        Download statement and upload to CipherBank.
        
        Flow:
        1. Navigate to Account Statement page
        2. Select target account
        3. Set date range (previous day or today based on time)
        4. View and export statement as CSV
        5. Upload to CipherBank with retries
        
        Uses CipherBank for statement processing. AutoBank upload
        is deprecated and has been removed.
        """
        # Check stop event before starting
        if self.stop_evt.is_set():
            logger.debug("[%s] Stop event set - skipping statement download", self.alias)
            return
        
        d = self.driver

        with ErrorContext(
            "downloading and uploading statement",
            messenger=self.msgr,
            alias=self.alias
        ):
            # Navigate to Account Statement
            self._navigate_to_account_statement()

            # Select account
            self._select_account()

            # Set date range
            from_str, to_str = self._calculate_date_range()
            self._set_date_range(from_str, to_str)

            # View transactions
            self._click_view_statement()

            # Export CSV
            csv_path = self._export_statement_csv()

            # Upload to CipherBank
            self._upload_to_cipherbank(csv_path)

    def _navigate_to_account_statement(self) -> None:
        """Navigate to Account Statement page."""
        d = self.driver
        
        stmt_link = WebDriverWait(d, self.TIMEOUT_LONG).until(
            EC.element_to_be_clickable((By.LINK_TEXT, "Account statement"))
        )
        self._safe_click(stmt_link)
        time.sleep(3)

    def _select_account(self) -> None:
        """Select target account from dropdown."""
        acct_sel = self.wait.until(
            EC.element_to_be_clickable((By.ID, "accountNo"))
        )
        dropdown = Select(acct_sel)
        acct_no = (self.cred.get("account_number") or "").strip()
        
        if acct_no:
            for opt in dropdown.options:
                if opt.text.strip().startswith(acct_no):
                    dropdown.select_by_visible_text(opt.text)
                    break

    def _calculate_date_range(self) -> tuple[str, str]:
        """
        Calculate statement date range based on current time.
        
        Uses 6 AM cutover:
        - Before 6 AM: from=yesterday, to=today
        - After 6 AM: from=today, to=today
        
        Returns:
            Tuple of (from_date, to_date) in MM/DD/YYYY format
        """
        now = datetime.now()
        from_dt = now - timedelta(days=1) if now.hour < 6 else now
        to_dt = now
        
        from_str = from_dt.strftime("%m/%d/%Y")
        to_str = to_dt.strftime("%m/%d/%Y")
        
        logger.debug(
            "[%s] Date range: %s to %s",
            self.alias,
            from_str,
            to_str
        )
        
        return from_str, to_str

    def _set_date_range(self, from_str: str, to_str: str) -> None:
        """
        Set from and to dates in statement form.
        
        Args:
            from_str: From date in MM/DD/YYYY format
            to_str: To date in MM/DD/YYYY format
        """
        d = self.driver
        
        # Set From Date
        from_input = self.wait.until(
            EC.presence_of_element_located((By.ID, "fromDate"))
        )
        d.execute_script("arguments[0].removeAttribute('readonly')", from_input)
        d.execute_script("arguments[0].value = arguments[1]", from_input, from_str)

        # Set To Date
        to_input = self.wait.until(
            EC.presence_of_element_located((By.ID, "toDate"))
        )
        d.execute_script("arguments[0].removeAttribute('readonly')", to_input)
        d.execute_script("arguments[0].value = arguments[1]", to_input, to_str)

    def _click_view_statement(self) -> None:
        """Click View button to display statement."""
        d = self.driver
        
        view_btn = self.wait.until(
            EC.element_to_be_clickable((By.ID, "accountstatement_view"))
        )
        self._safe_click(view_btn)

    def _export_statement_csv(self) -> str:
        """
        Export statement as CSV and wait for download.
        
        Returns:
            Path to downloaded CSV file
            
        Raises:
            TimeoutException: If CSV download times out
        """
        d = self.driver
        
        csv_btn = WebDriverWait(d, self.TIMEOUT_STANDARD).until(
            EC.element_to_be_clickable((By.ID, "accountstatement_csvAcctStmt"))
        )
        self._safe_click(csv_btn)

        # Wait for download
        time.sleep(3)
        csv_path = self.wait_newest_file(".csv", timeout=60.0)
        
        if not csv_path:
            raise TimeoutException("Timed out waiting for IOB CSV download")
        
        self.info(f"Downloaded statement: {os.path.basename(csv_path)}")
        time.sleep(5)  # Ensure download fully completes
        
        return csv_path

    def _upload_to_cipherbank(self, csv_path: str) -> None:
        """
        Upload statement to CipherBank with retries.
        
        Args:
            csv_path: Path to CSV file to upload
        """
        # Skip upload if stopping
        if self.stop_evt.is_set():
            logger.debug("[%s] Stop event set - skipping CipherBank upload", self.alias)
            return
        
        max_attempts = 5
        cipherbank = get_cipherbank_client()
        
        if not cipherbank:
            logger.debug(
                "[%s] CipherBank client not available - skipping upload",
                self.alias
            )
            return

        for attempt in range(1, max_attempts + 1):
            # Check stop event before each attempt
            if self.stop_evt.is_set():
                logger.debug(
                    "[%s] Stop event set - aborting CipherBank upload (attempt %d/%d)",
                    self.alias,
                    attempt,
                    max_attempts
                )
                return
            
            with ErrorContext(
                f"uploading to CipherBank (attempt {attempt}/{max_attempts})",
                messenger=self.msgr,
                alias=self.alias,
                reraise=False
            ):
                cipherbank.upload_statement(
                    bank_code=self.cred["bank_label"],
                    account_number=self.cred["account_number"],
                    file_path=csv_path,
                    alias=self.alias,
                )
                self.info(
                    f"CipherBank upload successful (attempt {attempt}/{max_attempts})"
                )
                return  # Success
            
            # Retry delay
            if attempt < max_attempts:
                logger.info("[%s] Retrying CipherBank upload in 2 seconds...", self.alias)
                time.sleep(2)

        # All attempts failed
        self.error(
            f"CipherBank upload failed after {max_attempts} attempts. "
            "Continuing with next cycle."
        )

    # ============================================================
    # Balance Enquiry
    # ============================================================

    def _balance_enquiry(self) -> None:
        """
        Fetch and update account balance.
        
        Flow:
        1. Navigate to Balance Enquiry page
        2. Click account link
        3. Read balance from popup
        4. Close popup and return to Account Statement
        
        This is a best-effort operation - failures won't crash the worker.
        """
        # Skip if stopping
        if self.stop_evt.is_set():
            logger.debug("[%s] Stop event set - skipping balance enquiry", self.alias)
            return
        
        d = self.driver

        with ErrorContext(
            "balance enquiry",
            messenger=self.msgr,
            alias=self.alias,
            reraise=False
        ):
            # Scroll to top
            d.execute_script("window.scrollTo(0, 0);")
            time.sleep(0.5)

            # Navigate to Balance Enquiry
            balance_link = WebDriverWait(d, self.TIMEOUT_LONG).until(
                EC.element_to_be_clickable((By.LINK_TEXT, "Balance Enquiry"))
            )
            self._safe_click(balance_link)

            # Click account link
            self._click_balance_account_link()

            # Read balance from popup
            self._read_balance_popup()

            # Clean up popup
            d.execute_script(
                "document.querySelectorAll('.ui-widget-overlay, #dialogtbl')"
                ".forEach(el => el.remove());"
            )

            # Return to Account Statement
            self._navigate_to_account_statement()

    def _click_balance_account_link(self) -> None:
        """Click account link in Balance Enquiry page."""
        d = self.driver
        acctno = (self.cred.get("account_number") or "").strip()
        
        wait_long = WebDriverWait(d, self.TIMEOUT_EXTRA_LONG)
        
        if acctno:
            acct_link = wait_long.until(
                EC.element_to_be_clickable((
                    By.XPATH,
                    f"//a[contains(@href,'getBalance') and contains(.,'{acctno}')]"
                ))
            )
        else:
            acct_link = wait_long.until(
                EC.element_to_be_clickable((
                    By.XPATH,
                    "//a[contains(@href,'getBalance')]"
                ))
            )

        self._safe_click(acct_link)

    def _read_balance_popup(self) -> None:
        """Read balance from popup dialog."""
        d = self.driver
        
        tbl = WebDriverWait(d, self.TIMEOUT_EXTRA_LONG).until(
            EC.presence_of_element_located((
                By.CSS_SELECTOR,
                "#dialogtbl table tr.querytr td"
            ))
        )
        
        available = (tbl.text or "").strip()
        if available:
            self.info(f"💰: {available}")
            self.last_balance = available

    # ============================================================
    # Helper Methods
    # ============================================================

    def _safe_click(self, element) -> None:
        """
        Click element with fallback to JavaScript click.
        
        Handles ElementClickInterceptedException by attempting
        JavaScript click as fallback.
        
        Args:
            element: WebElement to click
        """
        d = self.driver
        
        # Scroll into view
        d.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
        time.sleep(0.3)
        
        try:
            element.click()
        except ElementClickInterceptedException:
            logger.debug("[%s] Click intercepted - using JavaScript", self.alias)
            d.execute_script("arguments[0].click();", element)
        except Exception:
            # Last resort - force JavaScript click
            d.execute_script("arguments[0].click();", element)