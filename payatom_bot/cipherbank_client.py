# payatom_bot/cipherbank_client.py
"""
CipherBank API client with automatic JWT token refresh.
Global token shared across all workers for concurrent uploads.

Features comprehensive error handling integrated with existing error_handler.py:
- All errors formatted using format_exception_message()
- Critical errors sent to Telegram via Messenger
- Uses ErrorContext for automatic error reporting
- Thread-safe for concurrent uploads
"""
from __future__ import annotations

import logging
import os
import threading
import time
import traceback
from datetime import datetime
from typing import Optional, Dict, Any

import requests

from .error_handler import (
    ErrorContext,
    safe_operation,
    format_exception_message,
)

logger = logging.getLogger(__name__)

# Bank code to parser key mapping
PARSER_KEY_MAP = {
    "IOB": "iob",
    "IOB CORPORATE": "iob",
    "TMB": "tmb",
    "KGB": "kgb",
    "IDBI": "idbi",
    "IDFC": "idfc",
    "CANARA": "canara",
}

class CipherBankClient:
    """
    Global CipherBank API client with automatic token refresh.
    
    Features:
    - Automatic token refresh 2 minutes before expiry
    - Thread-safe for concurrent uploads from multiple workers
    - Comprehensive error handling with Telegram alerts
    - Integrated with existing error handling patterns
    """
    
    # Refresh token 2 minutes before expiry
    REFRESH_BEFORE_EXPIRY_SECONDS = 120
    
    def __init__(
        self,
        auth_base_url: str,      # CHANGED: was just base_url
        upload_base_url: str,    # NEW: separate domain for uploads
        username: str,
        password: str,
        messenger,
    ):
        """
        Initialize CipherBank client.
        
        Args:
            base_url: CipherBank API base URL (e.g., "https://testing.thepaytrix.com/api")
            username: Authentication username
            password: Authentication password
            messenger: Messenger instance for alerts (uses existing system)
        """
        self.auth_base_url = auth_base_url.rstrip('/')      # 🔹 CHANGED
        self.upload_base_url = upload_base_url.rstrip('/')  # 🔹 NEW
        self.username = username
        self.password = password
        self.msgr = messenger
        
        # Thread-safe token storage
        self._lock = threading.RLock()
        self._token: Optional[str] = None
        self._token_expiry_ms: Optional[int] = None
        self._user_info: Dict[str, Any] = {}
        
        # Background refresh
        self._refresh_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._refresh_failures = 0
        self._max_failures = 5
        
        logger.info(
            "CipherBank client initialized for user: %s (auth: %s, upload: %s)",
            username,
            self.auth_base_url,
            self.upload_base_url
        )
    
    def start(self) -> None:
        """
        Start client with initial login and background token refresh.
        
        Raises:
            RuntimeError: If initial login fails
        """
        with ErrorContext(
            "CipherBank client startup",
            messenger=self.msgr,
            alias="CipherBank",
            reraise=True
        ):
            logger.info("🔐 Starting CipherBank client...")
            
            # Initial login with error handling
            self._perform_login()
            
            # Start background refresh
            self._stop_flag.clear()
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop,
                daemon=True,
                name="CipherBank-Refresh"
            )
            self._refresh_thread.start()
            
            logger.info("✅ CipherBank client started - token valid until %s", self._get_expiry_str())
            
            # Send success notification
            if self.msgr:
                self.msgr.send_event(
                    f"✅ <b>CipherBank Connected</b>\n\n"
                    f"<b>User:</b> {self.username}\n"
                    f"<b>Token valid until:</b> {self._get_expiry_str()}\n"  # 🔹 ADD THIS
                    f"<b>Auth API:</b> {self.auth_base_url}\n"
                    f"<b>Upload API:</b> {self.upload_base_url}",
                    kind="START"
                )
    
    def stop(self) -> None:
        """Stop background token refresh with error handling."""
        with ErrorContext(
            "CipherBank client shutdown",
            messenger=self.msgr,
            alias="CipherBank",
            reraise=False
        ):
            logger.info("Stopping CipherBank client...")
            self._stop_flag.set()
            
            if self._refresh_thread and self._refresh_thread.is_alive():
                self._refresh_thread.join(timeout=5.0)
            
            logger.info("✅ CipherBank client stopped")
    
    def get_token(self) -> str:
        """
        Get current valid JWT token (thread-safe).
        
        Returns:
            Current JWT token string
            
        Raises:
            RuntimeError: If no valid token available
        """
        with self._lock:
            if not self._token:
                error_msg = "No CipherBank token available - client may not be started"
                self._send_error_alert(
                    "Token Access Error",
                    RuntimeError(error_msg),
                    context="get_token"
                )
                raise RuntimeError(error_msg)
            
            # Check if expired (with 10s grace period for clock skew)
            if self._token_expiry_ms:
                now_ms = int(time.time() * 1000)
                if now_ms >= (self._token_expiry_ms - 10000):
                    error_msg = f"CipherBank token has expired (expired at {self._get_expiry_str()})"
                    self._send_error_alert(
                        "Token Expired",
                        RuntimeError(error_msg),
                        context="get_token"
                    )
                    raise RuntimeError(error_msg)
            
            return self._token
    
    def get_user_info(self) -> Dict[str, Any]:
        """Get user information from last login (thread-safe)."""
        with self._lock:
            return self._user_info.copy()
    def get_username(self) -> str:
        """Get authenticated username (thread-safe)."""
        with self._lock:
            return self._user_info.get("username", "")
    def _perform_login(self) -> None:
        """
        Perform login to CipherBank and store token.
        Uses existing error handling patterns with comprehensive error reporting.
        
        Raises:
            RuntimeError: If login fails
        """
        url = f"{self.auth_base_url}/auth/login"
        payload = {
            "username": self.username,
            "password": self.password,
        }
        
        with ErrorContext(
            "CipherBank authentication",
            messenger=self.msgr,
            alias="CipherBank",
            reraise=True
        ):
            logger.info("🔐 Authenticating with CipherBank as %s...", self.username)
            
            # Make login request with safe_operation wrapper
            response = safe_operation(
                lambda: requests.post(
                    url,
                    json=payload,
                    timeout=30,
                    headers={"Content-Type": "application/json"}
                ),
                context=f"CipherBank login request to {url}",
                default=None,
                log_errors=True
            )
            
            if response is None:
                error = RuntimeError(
                    f"Failed to connect to CipherBank at {self.auth_base_url}\n"  # 🔹 CHANGED
                    "Please check:\n"
                    "• Network connectivity\n"
                    "• CipherBank URL is correct\n"
                    "• Firewall/proxy settings"
                )
                self._send_error_alert("Connection Failed", error, context="login")
                raise error
            
            # Handle non-200 status codes
            if response.status_code != 200:
                error_msg = f"CipherBank login failed: HTTP {response.status_code}"
                
                # Try to extract error details from response
                error_details = self._extract_error_details(response)
                if error_details:
                    error_msg += f"\n\n<b>Server Response:</b>\n{error_details}"
                
                # Add troubleshooting suggestions
                if response.status_code == 401:
                    error_msg += (
                        "\n\n<b>Possible Causes:</b>\n"
                        "• Incorrect username or password\n"
                        "• Account locked or disabled\n"
                        "• Credentials expired"
                    )
                elif response.status_code == 403:
                    error_msg += (
                        "\n\n<b>Possible Causes:</b>\n"
                        "• Account doesn't have required permissions\n"
                        "• IP address blocked\n"
                        "• API access disabled"
                    )
                elif response.status_code == 404:
                    error_msg += (
                        "\n\n<b>Possible Causes:</b>\n"
                        "• Incorrect API URL\n"
                        f"• Login endpoint not found at {url}"
                    )
                elif response.status_code >= 500:
                    error_msg += (
                        "\n\n<b>Server Error:</b>\n"
                        "CipherBank server is experiencing issues.\n"
                        "Will retry automatically."
                    )
                
                error = RuntimeError(error_msg)
                self._send_error_alert("Login Failed", error, context="login")
                raise error
            
            # Parse and validate response
            try:
                data = response.json()
            except ValueError as e:
                error_msg = (
                    f"CipherBank returned invalid JSON response\n"
                    f"Response: {response.text[:200]}"
                )
                error = RuntimeError(error_msg)
                self._send_error_alert("Invalid Response", error, context="login")
                raise error from e
            
            # Validate response structure
            required_fields = ["token", "tokenExpirationMillis"]
            missing = [f for f in required_fields if f not in data]
            if missing:
                error_msg = (
                    f"CipherBank response missing required fields: {', '.join(missing)}\n\n"
                    f"<b>Expected:</b> {', '.join(required_fields)}\n"
                    f"<b>Received:</b> {', '.join(data.keys())}\n\n"
                    "This may indicate an API version mismatch."
                )
                error = RuntimeError(error_msg)
                self._send_error_alert("Invalid Login Response", error, context="login")
                raise error
            
            # Store token info (thread-safe)
            with self._lock:
                self._token = data["token"]
                self._token_expiry_ms = data["tokenExpirationMillis"]
                self._user_info = {
                    "username": data.get("username"),
                    "name": data.get("name"),
                    "email": data.get("email"),
                    "userType": data.get("userType"),
                    "roles": data.get("roles", []),
                    "tokenValidityMillis": data.get("tokenValidityMillis"),
                }
                
                # Reset failure counter on success
                old_failures = self._refresh_failures
                self._refresh_failures = 0
            
            logger.info(
                "✅ CipherBank authenticated - token expires at %s",
                self._get_expiry_str()
            )
            
            # Send recovery notification if recovering from failures
            if old_failures > 0 and self.msgr:
                self.msgr.send_event(
                    f"✅ <b>CipherBank Authentication Recovered</b>\n\n"
                    f"Successfully logged in after {old_failures} failed attempts.\n"
                    f"Token valid until: {self._get_expiry_str()}",
                    kind="INFO"
                )
    
    def _refresh_loop(self) -> None:
        """
        Background thread that monitors and refreshes token.
        Comprehensive error handling with escalating alerts.
        """
        logger.info("CipherBank token refresh loop started")
        
        while not self._stop_flag.is_set():
            try:
                # Calculate time until refresh
                with self._lock:
                    if not self._token_expiry_ms:
                        logger.warning("No token expiry set - waiting 60s")
                        self._stop_flag.wait(60)
                        continue
                    
                    now_ms = int(time.time() * 1000)
                    time_until_expiry_s = (self._token_expiry_ms - now_ms) / 1000.0
                    time_until_refresh_s = time_until_expiry_s - self.REFRESH_BEFORE_EXPIRY_SECONDS
                
                if time_until_refresh_s > 0:
                    # Wait (check every 10s for stop signal)
                    wait_time = min(time_until_refresh_s, 10)
                    self._stop_flag.wait(wait_time)
                    continue
                
                # Time to refresh
                logger.info("🔄 Refreshing CipherBank token (%.0fs until expiry)", time_until_expiry_s)
                
                try:
                    self._perform_login()
                    
                except Exception as e:
                    self._refresh_failures += 1
                    
                    logger.error(
                        "❌ Token refresh failed (%d/%d): %s",
                        self._refresh_failures,
                        self._max_failures,
                        e
                    )
                    
                    # Send escalating alerts with formatted error messages
                    if self.msgr:
                        if self._refresh_failures >= self._max_failures:
                            # Critical failure - format full error message
                            error_msg = format_exception_message(
                                e,
                                f"CipherBank Token Refresh (Failed {self._refresh_failures}/{self._max_failures} times)",
                                include_traceback=True,
                                max_tb_lines=10
                            )
                            
                            critical_msg = (
                                f"🔴🔴🔴 <b>CRITICAL ALERT</b> 🔴🔴🔴\n\n"
                                f"<b>CipherBank Token Refresh Failed</b>\n\n"
                                f"<b>Status:</b> Max failures reached ({self._max_failures})\n"
                                f"<b>Impact:</b> All CipherBank uploads will fail\n"
                                f"<b>Required Action:</b> Manual intervention needed\n\n"
                                f"<b>Troubleshooting:</b>\n"
                                f"• Check CipherBank credentials in .env\n"
                                f"• Verify CipherBank service is online\n"
                                f"• Check network connectivity\n"
                                f"• Review error details below\n\n"
                                f"{error_msg}"
                            )
                            
                            self.msgr.send_event(critical_msg, kind="ERROR")
                            
                        elif self._refresh_failures >= 3:
                            # Warning level - simpler message
                            self.msgr.send_event(
                                f"⚠️ <b>CipherBank Token Refresh Failing</b>\n\n"
                                f"<b>Attempt:</b> {self._refresh_failures}/{self._max_failures}\n"
                                f"<b>Error:</b> {type(e).__name__}: {str(e)}\n\n"
                                f"Will retry in 30 seconds...",
                                kind="ERROR"
                            )
                    
                    if self._refresh_failures >= self._max_failures:
                        logger.critical("🛑 Max refresh failures reached - stopping refresh loop")
                        break
                    
                    # Exponential backoff: 30s, 60s, 90s...
                    backoff_time = min(30 * self._refresh_failures, 120)
                    logger.info("Retrying in %ds...", backoff_time)
                    self._stop_flag.wait(backoff_time)
                
            except Exception as e:
                # Unexpected error in refresh loop itself
                logger.exception("Unexpected error in CipherBank refresh loop: %s", e)
                
                if self.msgr:
                    error_msg = format_exception_message(
                        e,
                        "CipherBank Refresh Loop",
                        include_traceback=True,
                        max_tb_lines=10
                    )
                    self.msgr.send_event(
                        f"⚠️ <b>CipherBank Refresh Loop Error</b>\n\n{error_msg}",
                        kind="ERROR"
                    )
                
                self._stop_flag.wait(60)
        
        logger.info("CipherBank token refresh loop stopped")
    
    def _get_expiry_str(self) -> str:
        """Get formatted expiry time string (thread-safe)."""
        with self._lock:
            if not self._token_expiry_ms:
                return "unknown"
            expiry_dt = datetime.fromtimestamp(self._token_expiry_ms / 1000.0)
            return expiry_dt.strftime("%Y-%m-%d %H:%M:%S")
    
    def upload_statement(
        self,
        bank_code: str,
        account_number: str,
        file_path: str,
        alias: str = "unknown",
    ) -> None:
        """
        Upload bank statement to CipherBank.
        Thread-safe - multiple workers can call simultaneously with different files.
        
        Args:
            bank_code: Bank identifier code
            account_number: Account number
            file_path: Path to statement file
            alias: Worker alias (for logging and error context)
            
        Raises:
            RuntimeError: If upload fails
        """
        with ErrorContext(
            f"CipherBank upload for {alias}",
            messenger=self.msgr,
            alias=alias,
            reraise=True
        ):
            url = f"{self.upload_base_url}/statements/upload"  # CHANGED
            
            # Validate file exists before attempting upload
            if not os.path.exists(file_path):
                error = FileNotFoundError(
                    f"Statement file not found: {file_path}\n"
                    f"Worker: {alias}\n"
                    f"Bank: {bank_code}"
                )
                self._send_error_alert(
                    f"Upload Failed - File Not Found ({alias})",
                    error,
                    context=f"upload for {alias}"
                )
                raise error
            
            # Get file size for logging
            file_size = os.path.getsize(file_path)
            file_size_kb = file_size / 1024
            
            # Get current token (thread-safe)
            try:
                token = self.get_token()
            except RuntimeError as e:
                # Token error already sends its own alert
                raise
            
            masked_account = account_number[-4:] if len(account_number) >= 4 else account_number
            logger.info(
                "[%s] Uploading to CipherBank: %s - Account ***%s (%.1f KB)",
                alias,
                bank_code,
                masked_account,
                file_size_kb
            )
            
            # Prepare and execute multipart upload with comprehensive error handling
            try:
                with open(file_path, 'rb') as f:
                    file_name = os.path.basename(file_path)
                    # Get parser key from mapping, fallback to bank_code
                    parser_key = PARSER_KEY_MAP.get(bank_code, bank_code)
                    # Get authenticated username
                    username = self.get_username()
                    if not username:
                        logger.warning(
                            "[%s] No username available for upload - using default",
                            alias
                        )
                        username = self.username  # Fallback to login username
                    files = {
                        'file': (file_name, f, 'application/octet-stream')
                    }
                    data = {
                        'bankCode': bank_code,
                        'accountNumber': account_number,
                        'parserKey': parser_key,  # ADDED
                        'username': username, 
                    }
                    headers = {
                        'Authorization': f'Bearer {token}',
                    }
                    
                    # Make request with timeout
                    response = safe_operation(
                        lambda: requests.post(
                            url,
                            files=files,
                            data=data,
                            headers=headers,
                            timeout=60,
                        ),
                        context=f"CipherBank upload request for {alias}",
                        default=None,
                        log_errors=True
                    )
                    
                    if response is None:
                        error = RuntimeError(
                            f"Failed to upload to CipherBank\n"
                            f"Worker: {alias}\n"
                            f"Bank: {bank_code}\n"
                            f"File: {file_name}\n\n"
                            f"Network error or timeout"
                        )
                        self._send_error_alert(
                            f"Upload Failed ({alias})",
                            error,
                            context=f"upload for {alias}"
                        )
                        raise error
                    
                    # Handle token expiry (401)
                    if response.status_code == 401:
                        error_msg = (
                            f"Token expired during upload\n"
                            f"Worker: {alias}\n"
                            f"Bank: {bank_code}\n\n"
                            f"Token will be refreshed automatically.\n"
                            f"Please retry upload on next cycle."
                        )
                        logger.warning("[%s] %s", alias, error_msg)
                        
                        # Don't send alert for 401 - this is expected and will recover
                        raise RuntimeError(error_msg)
                    
                    # Handle other errors
                    if response.status_code not in (200, 201):
                        error_details = self._extract_error_details(response)
                        error_msg = (
                            f"CipherBank upload failed: HTTP {response.status_code}\n"
                            f"Worker: {alias}\n"
                            f"Bank: {bank_code}\n"
                            f"Account: ***{masked_account}\n"
                            f"File: {file_name} ({file_size_kb:.1f} KB)\n\n"
                        )
                        
                        if error_details:
                            error_msg += f"<b>Server Response:</b>\n{error_details}\n\n"
                        
                        # Add troubleshooting for common errors
                        if response.status_code == 400:
                            error_msg += (
                                "<b>Possible Causes:</b>\n"
                                "• Invalid file format\n"
                                "• Missing required fields\n"
                                "• Invalid bank code or account number"
                            )
                        elif response.status_code == 413:
                            error_msg += (
                                "<b>Possible Causes:</b>\n"
                                f"• File too large ({file_size_kb:.1f} KB)\n"
                                "• Server upload limit exceeded"
                            )
                        elif response.status_code >= 500:
                            error_msg += (
                                "<b>Server Error:</b>\n"
                                "CipherBank server is experiencing issues.\n"
                                "Will retry automatically."
                            )
                        
                        error = RuntimeError(error_msg)
                        self._send_error_alert(
                            f"Upload Failed ({alias})",
                            error,
                            context=f"upload for {alias}"
                        )
                        raise error
                    
                    logger.info("[%s] ✅ CipherBank upload successful", alias)
                    
            except FileNotFoundError:
                # Already handled above
                raise
            except requests.Timeout as e:
                error_msg = (
                    f"CipherBank upload timeout after 60 seconds\n"
                    f"Worker: {alias}\n"
                    f"Bank: {bank_code}\n"
                    f"File: {os.path.basename(file_path)} ({file_size_kb:.1f} KB)\n\n"
                    f"The file may be too large or network is slow."
                )
                error = RuntimeError(error_msg)
                self._send_error_alert(
                    f"Upload Timeout ({alias})",
                    error,
                    context=f"upload for {alias}"
                )
                raise error from e
            except requests.RequestException as e:
                error_msg = (
                    f"CipherBank network error during upload\n"
                    f"Worker: {alias}\n"
                    f"Bank: {bank_code}\n"
                    f"Error: {type(e).__name__}: {e}"
                )
                error = RuntimeError(error_msg)
                self._send_error_alert(
                    f"Upload Network Error ({alias})",
                    error,
                    context=f"upload for {alias}"
                )
                raise error from e
    
    def _extract_error_details(self, response: requests.Response) -> str:
        """
        Extract error details from HTTP response.
        
        Args:
            response: HTTP response object
            
        Returns:
            Formatted error details string, or empty string if none
        """
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                # Common error response patterns
                if 'message' in error_data:
                    return f"<code>{error_data['message']}</code>"
                elif 'error' in error_data:
                    return f"<code>{error_data['error']}</code>"
                elif 'detail' in error_data:
                    return f"<code>{error_data['detail']}</code>"
                else:
                    # Return entire JSON
                    import json
                    return f"<pre>{json.dumps(error_data, indent=2)[:300]}</pre>"
            else:
                return f"<code>{str(error_data)[:200]}</code>"
        except Exception:
            # Not JSON or parsing failed - return raw text
            text = response.text[:200]
            if text:
                return f"<code>{text}</code>"
            return ""
    
    def _send_error_alert(
        self,
        title: str,
        error: Exception,
        context: str,
    ) -> None:
        """
        Send formatted error alert via Telegram.
        Uses existing error formatting from error_handler.py.
        
        Args:
            title: Error title/summary
            error: The exception that occurred
            context: Context where error occurred
        """
        if not self.msgr:
            return
        
        try:
            # Use existing error formatting
            error_msg = format_exception_message(
                error,
                f"CipherBank - {context}",
                include_traceback=False,  # Don't include traceback for user-facing errors
                max_tb_lines=5
            )
            
            # Send via messenger
            self.msgr.send_event(
                f"🚨 <b>{title}</b>\n\n{error_msg}",
                kind="ERROR"
            )
            
        except Exception as e:
            # Error sending error - log but don't raise
            logger.exception("Failed to send CipherBank error alert: %s", e)


# Global singleton instance
_global_client: Optional[CipherBankClient] = None
_global_lock = threading.Lock()


def get_cipherbank_client() -> Optional[CipherBankClient]:
    """
    Get the global CipherBank client instance.
    
    Returns:
        Global CipherBank client, or None if not initialized
    """
    with _global_lock:
        return _global_client


def initialize_cipherbank_client(
    auth_base_url: str,      # CHANGED: was base_url
    upload_base_url: str,    # NEW
    username: str,
    password: str,
    messenger,
) -> CipherBankClient:
    """
    Initialize global CipherBank client with comprehensive error handling.
    
    Args:
        auth_base_url: CipherBank auth API base URL (e.g., https://testing.thepaytrix.com/api)
        upload_base_url: CipherBank upload API base URL (e.g., https://cipher.thepaytrix.com/api)
        username: Authentication username
        password: Authentication password
        messenger: Messenger instance for alerts
        
    Returns:
        Initialized client
        
    Raises:
        RuntimeError: If initialization fails
    """
    global _global_client
    
    with ErrorContext(
        "CipherBank client initialization",
        messenger=messenger,
        alias="CipherBank",
        reraise=True
    ):
        with _global_lock:
            if _global_client is not None:
                logger.warning("CipherBank client already initialized - stopping old instance")
                safe_operation(
                    lambda: _global_client.stop(),
                    context="stop old CipherBank client",
                    log_errors=True
                )
            
            _global_client = CipherBankClient(
                auth_base_url=auth_base_url,      # CHANGED
                upload_base_url=upload_base_url,  # NEW
                username=username,
                password=password,
                messenger=messenger,
            )
            
            _global_client.start()
            
            return _global_client


def shutdown_cipherbank_client() -> None:
    """Shutdown global CipherBank client with error handling."""
    global _global_client
    
    with _global_lock:
        if _global_client is not None:
            safe_operation(
                lambda: _global_client.stop(),
                context="shutdown CipherBank client",
                log_errors=True
            )
            _global_client = None
            logger.info("CipherBank client shutdown complete")