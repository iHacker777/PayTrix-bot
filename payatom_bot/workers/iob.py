# payatom_bot/workers/iob.py
"""
Indian Overseas Bank (Retail + Corporate) automation worker.

Supports both retail and corporate banking interfaces with:
- Automatic CAPTCHA solving with 2Captcha integration
- Session management with logged-out detection
- Robust error recovery with retries and screenshots
- CipherBank statement upload integration
- Balance monitoring with threshold alerts
- Graceful shutdown handling for clean stop operations

Architecture:
- Inherits from BaseWorker for common Selenium/Telegram functionality
- Uses ErrorContext for comprehensive error handling
- Thread-safe operations for concurrent worker management
- Race condition protection for clean shutdown
- Enterprise-grade logging with PII masking
- Comprehensive audit trail for compliance

Example Usage:
    ```python
    from payatom_bot.workers.iob import IOBWorker
    from payatom_bot.messaging import Messenger
    
    # Retail mode
    worker = IOBWorker(
        bot=bot,
        chat_id=12345,
        alias="my_iob_account",
        cred={
            "username": "USER123",
            "password": "******",
            "account_number": "1234567890",
            "bank_label": "IOB"
        },
        messenger=messenger,
        profile_dir="/path/to/profile",
        two_captcha=solver
    )
    
    # Corporate mode
    corporate_worker = IOBWorker(
        bot=bot,
        chat_id=12345,
        alias="company_iobcorp",
        cred={
            "login_id": "CORP123",
            "user_id": "USER456",
            "password": "******",
            "account_number": "9876543210",
            "bank_label": "IOB CORPORATE"
        },
        messenger=messenger,
        profile_dir="/path/to/profile",
        two_captcha=solver
    )
    ```
"""
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
from selenium.common.exceptions import (
    TimeoutException,
    ElementClickInterceptedException,
)
from selenium.webdriver.remote.webelement import WebElement

from ..balance_monitor import parse_balance_amount, THRESHOLDS
from ..cipherbank_client import get_cipherbank_client
from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..error_handler import (
    ErrorContext,
    ErrorMetadata,
    ErrorSeverity,
    ErrorCategory,
    safe_operation,
)
from ..logging_config import log_audit_event


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

    # ============================================================
    # Class Constants
    # ============================================================

    # URLs
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
    
    # Page element identifiers
    CAPTCHA_IMAGE_ID = "captchaimg"
    CAPTCHA_FIELD_NAME = "captchaid"
    SUBMIT_BUTTON_ID = "btnSubmit"
    ACCOUNT_DROPDOWN_ID = "accountNo"
    FROM_DATE_ID = "fromDate"
    TO_DATE_ID = "toDate"
    VIEW_BUTTON_ID = "accountstatement_view"
    CSV_BUTTON_ID = "accountstatement_csvAcctStmt"
    
    # Navigation text
    NAV_CONTINUE_TEXT = "Continue to Internet Banking Home Page"
    NAV_PERSONAL_LOGIN = "Personal Login"
    NAV_CORPORATE_LOGIN = "Corporate Login"
    NAV_ACCOUNT_STATEMENT = "Account statement"
    NAV_BALANCE_ENQUIRY = "Balance Enquiry"
    
    # Error messages
    ERROR_LOGGED_OUT = "You are Logged OUT of internet banking"
    ERROR_CAPTCHA_INCORRECT = "captcha entered is incorrect"

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
            
        Raises:
            ValueError: If required credentials are missing
        """
        super().__init__(
            bot=bot,
            chat_id=chat_id,
            alias=alias,
            cred=cred,
            messenger=messenger,
            profile_dir=profile_dir,
        )
        
        # Validate credentials
        self._validate_credentials()
        
        self.wait = WebDriverWait(self.driver, self.TIMEOUT_STANDARD)
        self.solver = two_captcha
        self.iob_win: Optional[str] = None
        self._captcha_id: Optional[str] = None
        self.captcha_code: Optional[str] = None

    # ============================================================
    # Validation
    # ============================================================

    def _validate_credentials(self) -> None:
        """
        Validate required credentials are present.
        
        Raises:
            ValueError: If required credentials are missing
        """
        required = ["password", "account_number", "bank_label"]
        missing = [k for k in required if not self.cred.get(k)]
        
        if missing:
            raise ValueError(f"Missing required credentials: {missing}")
        
        # Corporate mode requires additional fields
        if self._is_corporate_mode():
            corporate_required = ["login_id", "user_id"]
            missing_corp = [k for k in corporate_required if not self.cred.get(k)]
            if missing_corp:
                raise ValueError(
                    f"Missing corporate credentials: {missing_corp}"
                )

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
                            self.worker_logger.debug(
                                "Stop event detected - exiting loop"
                            )
                            break

                        # Download and upload statement
                        self._download_and_upload_statement()

                        # Check again before balance enquiry
                        if self.stop_evt.is_set():
                            self.worker_logger.debug(
                                "Stop event detected before balance enquiry"
                            )
                            break
                            
                        self._check_logged_out_and_cycle()

                        # Balance enquiry (best-effort)
                        balance_result = safe_operation(
                            self._balance_enquiry,
                            context=f"balance enquiry for {self.alias}",
                            default=None
                        )
                        
                        if balance_result is None:
                            self.worker_logger.debug("Balance enquiry skipped")

                        # Check stop event before sleep
                        if self.stop_evt.is_set():
                            self.worker_logger.debug(
                                "Stop event detected - skipping sleep"
                            )
                            break
                        
                        # Interruptible sleep
                        self._interruptible_sleep(self.CYCLE_SLEEP_SECONDS)
                        
                except TimeoutException as e:
                    # If stop event is set, this is expected - don't log as error
                    if self.stop_evt.is_set():
                        self.worker_logger.debug(
                            "Timeout during shutdown (expected)"
                        )
                        break
                    
                    retry_count += 1
                    self.warning(
                        f"Timeout/logged-out (retry {retry_count}/"
                        f"{self.MAX_OUTER_RETRIES}): {e}"
                    )
                    
                    if retry_count > self.MAX_OUTER_RETRIES:
                        self.error(
                            f"Too many failures ({self.MAX_OUTER_RETRIES}). "
                            "Stopping IOB worker."
                        )
                        return
                    
                    # Screenshot and reset (skip if stopping)
                    if not self.stop_evt.is_set():
                        try:
                            self.screenshot_all_tabs(
                                f"IOB error - retry {retry_count}/"
                                f"{self.MAX_OUTER_RETRIES}"
                            )
                        except Exception:
                            pass
                    
                    self._reset_session()
                    
                except Exception as e:
                    # If stop event is set, suppress Selenium connection errors
                    if self.stop_evt.is_set():
                        if self._is_shutdown_error(e):
                            self.worker_logger.debug(
                                "Selenium connection error during shutdown (expected): %s",
                                type(e).__name__
                            )
                            break
                    
                    retry_count += 1
                    self.error(
                        f"Loop error (retry {retry_count}/"
                        f"{self.MAX_OUTER_RETRIES}): "
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
                            "Stopping IOB worker."
                        )
                        return

                    self._reset_session()
                    
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

    def _reset_session(self) -> None:
        """
        Reset browser session and IOB-specific state.
        
        Calls BaseWorker's tab cycling logic and resets IOB-specific
        attributes.
        """
        super()._cycle_tabs()
        
        # Reset IOB-specific state
        self.iob_win = None
        self.captcha_code = None

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
        
        if source and self.ERROR_LOGGED_OUT in source:
            self.info("Detected logged-out page - resetting session")
            self._reset_session()
            raise TimeoutException("IOB logged out (server message)")

    def _is_shutdown_error(self, error: Exception) -> bool:
        """
        Check if error is expected during shutdown.
        
        Args:
            error: Exception to check
            
        Returns:
            True if error is expected during shutdown
        """
        error_msg = str(error)
        shutdown_indicators = [
            "Connection refused",
            "Failed to establish a new connection",
            "MaxRetryError",
            "target machine actively refused",
            "invalid session id",
            "chrome not reachable",
            "Session not created",
        ]
        
        return any(indicator in error_msg for indicator in shutdown_indicators)

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
            ValueError: If credentials are invalid
        """
        # Check stop event before login attempt
        if self.stop_evt.is_set():
            self.worker_logger.debug("Stop event set - skipping login")
            return
        
        d = self.driver
        w = self.wait

        # Determine login mode
        is_corp = self._is_corporate_mode()
        mode_text = "corporate" if is_corp else "retail"

        with ErrorContext(
            "IOB login",
            messenger=self.msgr,
            alias=self.alias,
            metadata=ErrorMetadata(
                category=ErrorCategory.BANKING,
                severity=ErrorSeverity.HIGH,
                worker_alias=self.alias,
                bank_name=self.cred.get("bank_label"),
                operation="login",
                recoverable=True,
            )
        ):
            # Navigate to login page
            d.get(self.LOGIN_URL)

            # Click continue to internet banking
            w.until(
                EC.element_to_be_clickable(
                    (By.LINK_TEXT, self.NAV_CONTINUE_TEXT)
                )
            ).click()

            # Select login mode
            role_text = (
                self.NAV_CORPORATE_LOGIN if is_corp 
                else self.NAV_PERSONAL_LOGIN
            )
            w.until(
                EC.element_to_be_clickable((By.LINK_TEXT, role_text))
            ).click()

            # Fill credentials
            self._fill_login_credentials(is_corp)

            # Solve and submit CAPTCHA
            self._solve_and_submit_captcha()

            # Wait for successful login
            w.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "nav.accordian"))
            )
            
            self.iob_win = d.current_window_handle
            self.logged_in = True
            
            self.info(f"Logged in successfully ({mode_text} mode)")
            
            # Audit log
            log_audit_event(
                "LOGIN_SUCCESS",
                {
                    "alias": self.alias,
                    "bank": self.cred.get("bank_label"),
                    "account": f"***{self.cred['account_number'][-4:]}",
                    "mode": mode_text,
                }
            )

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
                user = (
                    self.cred.get("auth_id") or 
                    self.cred.get("username") or 
                    ""
                )
                d.find_element(By.NAME, "loginId").send_keys(user)
                d.find_element(By.NAME, "password").send_keys(
                    self.cred["password"]
                )

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
            self.worker_logger.debug("Stop event set - skipping CAPTCHA solve")
            return
        
        d = self.driver
        
        with ErrorContext(
            "solving CAPTCHA",
            messenger=self.msgr,
            alias=self.alias
        ):
            # Capture CAPTCHA image
            img = WebDriverWait(d, self.TIMEOUT_CAPTCHA_WAIT).until(
                EC.presence_of_element_located((By.ID, self.CAPTCHA_IMAGE_ID))
            )
            
            # Scroll into view
            d.execute_script("arguments[0].scrollIntoView(true);", img)
            time.sleep(1)

            # Re-locate after scroll
            img = WebDriverWait(d, self.TIMEOUT_CAPTCHA_WAIT).until(
                EC.visibility_of_element_located((By.ID, self.CAPTCHA_IMAGE_ID))
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
            field = d.find_element(By.NAME, self.CAPTCHA_FIELD_NAME)
            field.clear()
            field.send_keys(solution.strip().upper())

            # Submit form
            d.find_element(By.ID, self.SUBMIT_BUTTON_ID).click()

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
            self.worker_logger.debug(
                "Stop event set - skipping CAPTCHA error check"
            )
            return
        
        d = self.driver
        
        try:
            # Check if driver session is still valid
            try:
                _ = d.session_id
            except Exception:
                # Driver session is dead - likely due to stop event
                self.worker_logger.debug(
                    "Driver session invalid - skipping CAPTCHA check"
                )
                return
            
            err_span = WebDriverWait(d, self.TIMEOUT_ERROR_DETECTION).until(
                EC.presence_of_element_located(
                    (By.CSS_SELECTOR, "div.otpmsg span.red")
                )
            )
            
            if (
                self.ERROR_CAPTCHA_INCORRECT in (err_span.text or "").lower()
                and self._captcha_id
            ):
                self.error("CAPTCHA incorrect - reporting to 2Captcha")
                if self.solver:
                    safe_operation(
                        lambda: self.solver.report_bad(self._captcha_id),
                        context="report bad CAPTCHA",
                        default=None
                    )
                self._reset_session()
                raise TimeoutException("CAPTCHA incorrect")
                
        except TimeoutException:
            # No error shown - login successful
            pass
        except Exception as e:
            # If stop event is set, suppress all errors
            if self.stop_evt.is_set():
                self.worker_logger.debug(
                    "Exception during CAPTCHA check (shutdown in progress): %s",
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
        
        Uses CipherBank for statement processing.
        """
        # Check stop event before starting
        if self.stop_evt.is_set():
            self.worker_logger.debug(
                "Stop event set - skipping statement download"
            )
            return
        
        with ErrorContext(
            "downloading and uploading statement",
            messenger=self.msgr,
            alias=self.alias,
            metadata=ErrorMetadata(
                category=ErrorCategory.BANKING,
                severity=ErrorSeverity.HIGH,
                worker_alias=self.alias,
                bank_name=self.cred.get("bank_label"),
                operation="statement_download",
                recoverable=True,
            )
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

            # Audit log
            log_audit_event(
                "STATEMENT_DOWNLOAD",
                {
                    "alias": self.alias,
                    "bank": self.cred.get("bank_label"),
                    "file": os.path.basename(csv_path),
                    "size_kb": round(os.path.getsize(csv_path) / 1024, 2),
                    "date_range": f"{from_str} to {to_str}",
                }
            )

            # Upload to CipherBank
            self._upload_to_cipherbank(csv_path)

    def _navigate_to_account_statement(self) -> None:
        """Navigate to Account Statement page."""
        d = self.driver
        
        stmt_link = WebDriverWait(d, self.TIMEOUT_LONG).until(
            EC.element_to_be_clickable((By.LINK_TEXT, self.NAV_ACCOUNT_STATEMENT))
        )
        self._safe_click(stmt_link)
        time.sleep(3)

    def _select_account(self) -> None:
        """Select target account from dropdown."""
        acct_sel = self.wait.until(
            EC.element_to_be_clickable((By.ID, self.ACCOUNT_DROPDOWN_ID))
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
        
        self.worker_logger.debug(
            "Date range: %s to %s",
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
        
        with ErrorContext(
            "setting date range",
            messenger=self.msgr,
            alias=self.alias,
            reraise=True
        ):
            # Set From Date
            from_input = self.wait.until(
                EC.presence_of_element_located((By.ID, self.FROM_DATE_ID))
            )
            d.execute_script(
                "arguments[0].removeAttribute('readonly')",
                from_input
            )
            d.execute_script(
                "arguments[0].value = arguments[1]",
                from_input,
                from_str
            )

            # Set To Date
            to_input = self.wait.until(
                EC.presence_of_element_located((By.ID, self.TO_DATE_ID))
            )
            d.execute_script(
                "arguments[0].removeAttribute('readonly')",
                to_input
            )
            d.execute_script(
                "arguments[0].value = arguments[1]",
                to_input,
                to_str
            )

    def _click_view_statement(self) -> None:
        """Click View button to display statement."""
        view_btn = self.wait.until(
            EC.element_to_be_clickable((By.ID, self.VIEW_BUTTON_ID))
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
            EC.element_to_be_clickable((By.ID, self.CSV_BUTTON_ID))
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
            self.worker_logger.debug(
                "Stop event set - skipping CipherBank upload"
            )
            return
        
        max_attempts = 5
        cipherbank = get_cipherbank_client()
        
        if not cipherbank:
            self.worker_logger.debug(
                "CipherBank client not available - skipping upload"
            )
            return

        for attempt in range(1, max_attempts + 1):
            # Check stop event before each attempt
            if self.stop_evt.is_set():
                self.worker_logger.debug(
                    "Stop event set - aborting CipherBank upload "
                    f"(attempt {attempt}/{max_attempts})"
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
                    f"CipherBank upload successful "
                    f"(attempt {attempt}/{max_attempts})"
                )
                
                # Audit log
                log_audit_event(
                    "STATEMENT_UPLOAD",
                    {
                        "alias": self.alias,
                        "bank": self.cred.get("bank_label"),
                        "service": "CipherBank",
                        "file": os.path.basename(csv_path),
                        "attempt": attempt,
                    }
                )
                
                return  # Success
            
            # Retry delay
            if attempt < max_attempts:
                self.info(
                    f"Retrying CipherBank upload in 2 seconds..."
                )
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
        4. Check against thresholds
        5. Close popup and return to Account Statement
        
        This is a best-effort operation - failures won't crash the worker.
        """
        # Skip if stopping
        if self.stop_evt.is_set():
            self.worker_logger.debug(
                "Stop event set - skipping balance enquiry"
            )
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
                EC.element_to_be_clickable(
                    (By.LINK_TEXT, self.NAV_BALANCE_ENQUIRY)
                )
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
        """Read balance from popup dialog and check thresholds."""
        d = self.driver
        
        tbl = WebDriverWait(d, self.TIMEOUT_EXTRA_LONG).until(
            EC.presence_of_element_located((
                By.CSS_SELECTOR,
                "#dialogtbl table tr.querytr td"
            ))
        )
        
        available = (tbl.text or "").strip()
        if available:
            self.info(f"Balance: {available}")
            self.last_balance = available
            
            # Check thresholds and alert if necessary
            self._check_balance_thresholds(available)

    def _check_balance_thresholds(self, balance_text: str) -> None:
        """
        Check balance against configured thresholds.
        
        Args:
            balance_text: Balance text from bank (e.g., "₹50,000.00")
        """
        amount = parse_balance_amount(balance_text)
        
        if not amount:
            return
        
        # Find the highest threshold exceeded
        for threshold in sorted(THRESHOLDS, key=lambda t: t.min_amount, reverse=True):
            if amount >= threshold.min_amount:
                urgency_emoji = {
                    "LOW": "ℹ️",
                    "LOW-MEDIUM": "⚠️",
                    "MEDIUM": "⚠️",
                    "HIGH": "🚨",
                    "CRITICAL": "🔴",
                }.get(threshold.urgency, "⚠️")
                
                self.warning(
                    f"{urgency_emoji} Balance {balance_text} exceeds "
                    f"₹{threshold.min_amount:,.0f} threshold "
                    f"({threshold.urgency} urgency)"
                )
                break

    # ============================================================
    # Helper Methods
    # ============================================================

    def _safe_click(self, element: WebElement) -> None:
        """
        Click element with fallback to JavaScript click.
        
        Handles ElementClickInterceptedException by attempting
        JavaScript click as fallback.
        
        Args:
            element: WebElement to click
        """
        d = self.driver
        
        # Scroll into view
        d.execute_script(
            "arguments[0].scrollIntoView({block:'center'});",
            element
        )
        time.sleep(0.3)
        
        try:
            element.click()
        except ElementClickInterceptedException:
            self.worker_logger.debug("Click intercepted - using JavaScript")
            d.execute_script("arguments[0].click();", element)
        except Exception:
            # Last resort - force JavaScript click
            d.execute_script("arguments[0].click();", element)

    # ============================================================
    # Health Check
    # ============================================================

    def health_check(self) -> dict:
        """
        Return worker health status.
        
        Returns:
            Dict with health metrics
        """
        return {
            "alias": self.alias,
            "logged_in": self.logged_in,
            "last_balance": self.last_balance,
            "stop_event_set": self.stop_evt.is_set(),
            "driver_alive": safe_operation(
                lambda: bool(self.driver.session_id),
                context="check driver status",
                default=False
            ),
            "mode": "corporate" if self._is_corporate_mode() else "retail",
        }