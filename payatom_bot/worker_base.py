# payatom_bot/worker_base.py
"""
Base worker class for bank automation with comprehensive logging.

Provides shared functionality for all bank workers:
- Selenium WebDriver management
- Chrome profile handling
- Telegram notifications via Messenger
- Screenshot capture
- Download monitoring
- Retry logic with error handling
- Worker-specific logging with PII masking
- Audit trail for critical operations
- Graceful shutdown handling
"""
from __future__ import annotations

import logging
import os
import time
import threading
import traceback
from io import BytesIO
from typing import Optional, Callable
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from .messaging import Messenger
from .logging_config import get_logger_for_worker, log_audit_event

# Module-level logger for BaseWorker class itself
logger = logging.getLogger(__name__)


class BaseWorker(threading.Thread):
    """
    Shared Selenium/Telegram scaffolding for all bank workers.
    
    Features:
    - Chrome profile management with session isolation
    - Stop flag for graceful shutdown
    - Retry wrapper with exponential backoff
    - Screenshot capture for all tabs
    - Download monitoring with timeout
    - Worker-specific logging to dedicated log files
    - Automatic audit trail for critical operations
    - Thread-safe operations
    - Race condition protection for clean shutdown
    
    Concrete subclasses should implement their own run() method which calls:
      - self._run_with_retries(step, label)
      - self.screenshot_all_tabs(reason)
      - self.info() and self.error() for logging
    """

    def __init__(
        self,
        *,
        bot,
        chat_id: int,
        alias: str,
        cred: dict,
        messenger: Messenger,
        profile_dir: str,
    ):
        """
        Initialize base worker.
        
        Args:
            bot: Telegram bot instance
            chat_id: Telegram chat ID for notifications
            alias: Worker alias (account identifier)
            cred: Credential dictionary from CSV loader
            messenger: Messenger instance for Telegram notifications
            profile_dir: Chrome profile directory path
        """
        super().__init__(daemon=True)
        
        # Core attributes
        self.bot = bot
        self.chat_id = chat_id
        self.alias = alias
        self.cred = cred
        self.msgr = messenger
        self.profile_dir = profile_dir

        # Set thread name to alias for logging context
        # This allows WorkerContextFilter to automatically add worker_alias to logs
        self.name = alias
        
        # Create worker-specific logger
        # This logger writes to both logs/main.log and logs/workers/{alias}.log
        self.worker_logger = get_logger_for_worker(alias)
        
        # Log worker initialization
        self.worker_logger.info(
            "Initializing worker: bank=%s, account=***%s, profile=%s",
            self.cred.get('bank_label', 'unknown'),
            self.cred.get('account_number', '')[-4:] if self.cred.get('account_number') else 'N/A',
            os.path.basename(profile_dir),
        )

        # Control flags
        self.stop_evt = threading.Event()
        self.logged_in = False
        
        # State tracking
        self.last_balance: Optional[str] = None
        self.last_upload_at: Optional[datetime] = None

        # Setup download directory
        download_root = os.path.join(os.getcwd(), "downloads", alias)
        os.makedirs(download_root, exist_ok=True)
        self.download_dir = download_root
        
        self.worker_logger.debug("Download directory: %s", download_root)

        # Configure Chrome options
        opts = webdriver.ChromeOptions()
        
        # Headless mode (commented for debugging, uncomment for production)
        # opts.add_argument("--headless=new")
        # opts.add_argument("--disable-gpu")
        
        # Profile and window settings
        opts.add_argument(f"--user-data-dir={profile_dir}")
        opts.add_argument("--start-maximized")
        
        # Security and stability
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--allow-insecure-localhost")
        opts.add_argument("--ignore-ssl-errors")
        
        # Suppress DevTools listening message
        opts.add_experimental_option('excludeSwitches', ['enable-logging'])

        # Download preferences
        prefs = {
            "download.default_directory": download_root,
            "download.prompt_for_download": False,
            "profile.default_content_setting_values.automatic_downloads": 1,
        }
        opts.add_experimental_option("prefs", prefs)

        try:
            # Initialize WebDriver
            self.worker_logger.debug("Initializing Chrome WebDriver...")
            self.driver = webdriver.Chrome(options=opts)
            
            # Clear browser data for fresh session
            self.driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
            self.driver.execute_cdp_cmd("Network.clearBrowserCache", {})
            self.driver.execute_script(
                "window.localStorage.clear(); window.sessionStorage.clear();"
            )
            
            self.worker_logger.info("Chrome WebDriver initialized successfully")
            
        except Exception as e:
            self.worker_logger.error(
                "Failed to initialize Chrome WebDriver: %s",
                e,
                exc_info=True
            )
            raise

    # ═══════════════════════════════════════════════════════════
    # Logging Methods
    # ═══════════════════════════════════════════════════════════

    def info(self, msg: str) -> None:
        """
        Log info message and send to Telegram.
        
        Automatically detects upload success and updates last_upload_at.
        Logs to worker-specific log file and sends Telegram notification.
        
        Args:
            msg: Message to log (without worker prefix)
        """
        kind = "INFO"
        
        # Detect successful uploads and update timestamp
        if "AutoBank upload succeeded" in msg or "CipherBank upload successful" in msg:
            try:
                self.last_upload_at = datetime.now()
                kind = "UPLOAD_OK"
                
                # Audit log for uploads
                upload_type = "CipherBank" if "CipherBank" in msg else "AutoBank"
                log_audit_event('STATEMENT_UPLOAD', {
                    'worker': self.alias,
                    'bank': self.cred.get('bank_label', 'unknown'),
                    'account': f"***{self.cred.get('account_number', '')[-4:]}",
                    'upload_type': upload_type,
                })
                
            except Exception as e:
                self.worker_logger.warning("Failed to update upload timestamp: %s", e)
                self.last_upload_at = None
        
        # Log to worker-specific log file
        self.worker_logger.info(msg)
        
        # Send to Telegram
        self.msgr.send_event(f"[{self.alias}] {msg}", kind)

    def error(self, msg: str) -> None:
        """
        Log error message and send to Telegram.
        
        Logs to worker-specific log file with ERROR level and sends
        Telegram notification with error formatting.
        
        Args:
            msg: Error message to log (without worker prefix)
        """
        # Log to worker-specific log file
        self.worker_logger.error(msg)
        
        # Send to Telegram
        self.msgr.send_event(f"[{self.alias}] {msg}", "ERROR")

    def debug(self, msg: str) -> None:
        """
        Log debug message (worker log only, no Telegram).
        
        Args:
            msg: Debug message to log
        """
        self.worker_logger.debug(msg)

    def warning(self, msg: str) -> None:
        """
        Log warning message (worker log only, no Telegram).
        
        Args:
            msg: Warning message to log
        """
        self.worker_logger.warning(msg)

    # ═══════════════════════════════════════════════════════════
    # Control Methods
    # ═══════════════════════════════════════════════════════════

    def stop(self) -> None:
        """
        Stop worker gracefully.
        
        Sets stop event flag and closes browser. Logs shutdown event
        to audit trail. Includes protection against duplicate quit()
        calls and checks driver availability before closing.
        """
        if not self.stop_evt.is_set():
            self.worker_logger.info("Stopping worker...")
            
            # Audit log for worker stop
            log_audit_event('WORKER_STOP', {
                'worker': self.alias,
                'bank': self.cred.get('bank_label', 'unknown'),
            })
        
        self.stop_evt.set()
        
        # Check if driver is still alive before attempting to quit
        try:
            # Try to access driver session to verify it's still active
            _ = self.driver.session_id
            self.driver.quit()
            self.worker_logger.debug("Chrome WebDriver closed")
        except AttributeError:
            # Driver doesn't have session_id attribute (already quit or never initialized)
            self.worker_logger.debug("WebDriver already closed or not initialized")
        except Exception as e:
            # Any other error during quit - log at debug level to avoid spam
            # This is expected during shutdown race conditions
            error_msg = str(e)
            if any(indicator in error_msg for indicator in [
                "invalid session id",
                "Session not created",
                "no such session",
                "chrome not reachable"
            ]):
                self.worker_logger.debug("WebDriver session already terminated")
            else:
                self.worker_logger.debug("WebDriver cleanup: %s", str(e))

    # ═══════════════════════════════════════════════════════════
    # Retry Wrapper
    # ═══════════════════════════════════════════════════════════

    def _run_with_retries(
        self,
        func: Callable[[], None],
        label: str,
        *,
        max_retries: int = 3,
        retry_sleep: float = 5.0,
    ) -> None:
        """
        Run function with automatic retries and error handling.
        
        Features:
        - Configurable retry count
        - Exponential backoff (optional)
        - Screenshot capture on failure
        - Detailed error logging
        - Telegram notification on failure
        - Graceful handling of stop events
        
        Args:
            func: Function to execute (should take no arguments)
            label: Human-readable operation description for logging
            max_retries: Maximum number of retry attempts
            retry_sleep: Base sleep time between retries (seconds)
            
        Raises:
            Exception: Re-raises the last exception if all retries fail
        """
        attempt = 0

        while not self.stop_evt.is_set() and attempt < max_retries:
            try:
                # Execute the function
                self.worker_logger.debug(
                    "Executing: %s (attempt %d/%d)",
                    label,
                    attempt + 1,
                    max_retries
                )
                
                result = func()
                
                # Success - log if this was a retry
                if attempt > 0:
                    self.worker_logger.info(
                        "✅ %s succeeded after %d retry(s)",
                        label,
                        attempt
                    )
                
                return result
                
            except Exception as e:
                attempt += 1
                
                # Check if this is a shutdown-related error
                if self.stop_evt.is_set():
                    error_msg = str(e)
                    # Suppress common Selenium errors during shutdown
                    if any(indicator in error_msg for indicator in [
                        "Connection refused",
                        "Failed to establish a new connection",
                        "MaxRetryError",
                        "target machine actively refused",
                        "invalid session id",
                        "chrome not reachable"
                    ]):
                        self.worker_logger.debug(
                            "Selenium error during shutdown (expected): %s - %s",
                            label,
                            type(e).__name__
                        )
                        raise  # Re-raise to exit retry loop
                
                # Format detailed error message
                tb = traceback.format_exc()
                
                self.worker_logger.error(
                    "Failed: %s (attempt %d/%d) - %s: %s",
                    label,
                    attempt,
                    max_retries,
                    type(e).__name__,
                    str(e)
                )
                self.worker_logger.debug("Traceback:\n%s", tb)
                
                # Send error to Telegram (skip if stopping)
                if not self.stop_evt.is_set():
                    msg = (
                        "⚠️ Oops! There seems to be an issue.\n"
                        "Please contact the dev team with the details below.\n\n"
                        f"Context: {label}\n"
                        f"Attempt: {attempt}/{max_retries}\n"
                        f"Error: {type(e).__name__}: {e}\n"
                        f"Traceback:\n{tb}"
                    )
                    self.error(msg)

                # Take screenshots for debugging (skip if stopping)
                if not self.stop_evt.is_set():
                    try:
                        self.screenshot_all_tabs(
                            f"{label} failure (attempt {attempt}/{max_retries})"
                        )
                    except Exception as screenshot_error:
                        self.worker_logger.warning(
                            "Failed to capture screenshots: %s",
                            screenshot_error
                        )

                # Check if we should retry
                if attempt >= max_retries:
                    self.worker_logger.error(
                        "❌ %s failed after %d attempts - giving up",
                        label,
                        max_retries
                    )
                    # Bubble up to caller
                    raise
                
                if self.stop_evt.is_set():
                    self.worker_logger.debug("Stop event set - aborting retries for %s", label)
                    raise

                # Sleep before retry (could add exponential backoff here)
                sleep_time = retry_sleep
                self.worker_logger.info(
                    "Retrying %s in %.1f seconds...",
                    label,
                    sleep_time
                )
                
                # Interruptible sleep - check stop event periodically
                sleep_end = time.time() + sleep_time
                while time.time() < sleep_end and not self.stop_evt.is_set():
                    time.sleep(0.5)

    # ═══════════════════════════════════════════════════════════
    # Screenshot Helper
    # ═══════════════════════════════════════════════════════════

    def screenshot_all_tabs(self, reason: str = "") -> None:
        """
        Capture screenshots of all browser tabs.
        
        Takes screenshots of all open tabs and sends them to Telegram
        for debugging. Useful for diagnosing errors in headless mode.
        Gracefully handles stop events and driver issues.
        
        Args:
            reason: Description of why screenshot was taken
        """
        # Skip if stop event is set
        if self.stop_evt.is_set():
            self.worker_logger.debug("Stop event set - skipping screenshots")
            return
        
        # Check if driver is still alive
        try:
            _ = self.driver.session_id
        except Exception:
            self.worker_logger.debug("Driver not available for screenshots")
            return
        
        self.worker_logger.debug("Capturing screenshots of all tabs: %s", reason)
        
        screenshot_count = 0
        
        try:
            handles = self.driver.window_handles
        except Exception as e:
            self.worker_logger.warning("Cannot access window handles: %s", e)
            return
        
        for h in handles:
            # Check stop event before each screenshot
            if self.stop_evt.is_set():
                break
                
            try:
                self.driver.switch_to.window(h)
                
                # Get page info
                title = self.driver.title or "unknown tab"
                url = self.driver.current_url
                
                # Capture screenshot
                png = self.driver.get_screenshot_as_png()
                bio = BytesIO(png)
                
                # Build caption
                caption = f"[{self.alias}] 📸 {title}"
                if reason:
                    caption += f" — {reason}"
                
                # Send to Telegram
                self.msgr.send_photo(bio, caption, kind="ERROR")
                
                screenshot_count += 1
                
                self.worker_logger.debug(
                    "Screenshot captured: tab=%s, url=%s",
                    title,
                    url
                )
                
            except Exception as e:
                self.worker_logger.warning(
                    "Failed to capture screenshot for tab: %s",
                    e
                )
                continue
        
        if screenshot_count > 0:
            self.worker_logger.info(
                "Captured %d screenshot(s): %s",
                screenshot_count,
                reason or "manual capture"
            )
        else:
            self.worker_logger.warning("No screenshots captured")

    # ═══════════════════════════════════════════════════════════
    # Download Helper
    # ═══════════════════════════════════════════════════════════

    def wait_newest_file(
        self,
        suffix: str,
        timeout: float = 60.0,
    ) -> Optional[str]:
        """
        Wait for a new file with given suffix to appear in download directory.
        
        Polls the worker's download directory until a file with the specified
        suffix appears, then returns its full path. Useful for waiting for
        downloads to complete. Respects stop event for graceful shutdown.
        
        Args:
            suffix: File extension to look for (e.g., '.csv', '.xls')
            timeout: Maximum time to wait in seconds
            
        Returns:
            Full path to the newest file, or None if timeout occurs or stop event set
        """
        self.worker_logger.debug(
            "Waiting for file with suffix '%s' (timeout: %.0fs)",
            suffix,
            timeout
        )
        
        deadline = time.time() + timeout
        suffix = suffix.lower()
        latest_path: Optional[str] = None
        
        # Record existing files at start
        try:
            existing_files = set(os.listdir(self.download_dir))
        except FileNotFoundError:
            existing_files = set()
            self.worker_logger.warning(
                "Download directory not found: %s",
                self.download_dir
            )

        while time.time() < deadline and not self.stop_evt.is_set():
            try:
                files = [
                    f
                    for f in os.listdir(self.download_dir)
                    if f.lower().endswith(suffix)
                ]
            except FileNotFoundError:
                files = []

            if files:
                # Find newest file
                latest = max(
                    files,
                    key=lambda f: os.path.getctime(
                        os.path.join(self.download_dir, f)
                    ),
                )
                latest_path = os.path.join(self.download_dir, latest)
                
                # Check if it's a new file
                if latest not in existing_files:
                    file_size = os.path.getsize(latest_path)
                    self.worker_logger.info(
                        "Found new file: %s (%.1f KB)",
                        latest,
                        file_size / 1024
                    )
                    break

            time.sleep(1.0)
        
        if self.stop_evt.is_set():
            self.worker_logger.debug("Stop event set - aborting file wait")
            return None
        
        if latest_path:
            return latest_path
        else:
            self.worker_logger.warning(
                "Timeout waiting for file with suffix '%s' after %.0fs",
                suffix,
                timeout
            )
            return None

    # ═══════════════════════════════════════════════════════════
    # Tab Cycling (Recovery Helper)
    # ═══════════════════════════════════════════════════════════

    def _cycle_tabs(self) -> None:
        """
        Reset browser session by cycling tabs.
        
        Closes all existing tabs, opens a fresh about:blank tab,
        and resets login state. Used for recovery from errors
        or session timeouts.
        
        This is a common recovery pattern used by many workers.
        Includes protection against race conditions during shutdown.
        """
        # Don't cycle if stop event is set
        if self.stop_evt.is_set():
            self.worker_logger.debug("Stop event set - skipping tab cycle")
            return
        
        # Check if driver is still alive
        try:
            _ = self.driver.session_id
        except Exception:
            self.worker_logger.debug("Driver not available for tab cycling")
            return
        
        self.worker_logger.info("Cycling browser tabs to reset session")
        
        try:
            handles_before = list(self.driver.window_handles)
            
            if not handles_before:
                self.worker_logger.warning("No windows to cycle - driver may be closed")
                return

            # Check stop event before proceeding
            if self.stop_evt.is_set():
                self.worker_logger.debug("Stop event detected during tab cycle prep")
                return

            # Open new blank tab
            self.driver.execute_script("window.open('about:blank','_blank');")
            time.sleep(0.5)

            # Find newly opened handle
            handles_after = list(self.driver.window_handles)
            
            new_handle = None
            for h in handles_after:
                if h not in handles_before:
                    new_handle = h
                    break

            if not new_handle:
                self.worker_logger.error("Failed to locate new tab during cycle")
                return

            # Close all old tabs
            closed_count = 0
            for h in handles_before:
                # Check stop event before each close operation
                if self.stop_evt.is_set():
                    self.worker_logger.debug("Stop event detected during tab cleanup")
                    break
                    
                try:
                    self.driver.switch_to.window(h)
                    self.driver.close()
                    closed_count += 1
                except Exception as e:
                    self.worker_logger.debug("Failed to close old tab: %s", e)

            # Switch to fresh tab and reset state
            try:
                self.driver.switch_to.window(new_handle)
                self.logged_in = False
                
                self.worker_logger.info(
                    "Browser tabs cycled: closed %d tabs, will re-login on next attempt",
                    closed_count
                )
            except Exception as e:
                # If stop event is set, this is expected
                if self.stop_evt.is_set():
                    self.worker_logger.debug("Tab switch interrupted by stop event")
                else:
                    self.worker_logger.error(
                        "Failed to switch to new tab: %s",
                        e,
                        exc_info=True
                    )
                    # Set stop flag if tab cycling fails critically
                    self.stop_evt.set()
            
        except Exception as e:
            # If stop event is set, this is expected - don't log as error
            if self.stop_evt.is_set():
                self.worker_logger.debug("Tab cycle interrupted by stop event")
            else:
                self.worker_logger.error(
                    "Failed to cycle tabs: %s",
                    e,
                    exc_info=True
                )
                # Set stop flag if tab cycling fails critically
                self.stop_evt.set()