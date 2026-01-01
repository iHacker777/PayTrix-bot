# payatom_bot/error_handler.py
"""
Enterprise-grade error handling and reporting for PayTrix Bot.

Provides professional, context-aware error messages with:
- Severity-based formatting and routing
- Integration with Messenger priority system
- Smart traceback filtering and formatting
- Error fingerprinting for deduplication
- Actionable recovery suggestions
- Async/sync context manager support
"""
from __future__ import annotations

import functools
import hashlib
import html
import logging
import re
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Any, TYPE_CHECKING, Dict, List

from telegram.constants import ParseMode

if TYPE_CHECKING:
    from telegram import Update, Bot
    from telegram.ext import ContextTypes
    from .messaging import Messenger

logger = logging.getLogger(__name__)


# ============================================================
# Error Categories and Severity Levels
# ============================================================

class ErrorCategory(Enum):
    """Error categories for routing and formatting."""
    AUTHENTICATION = "auth"          # Login failures, token expiry
    NETWORK = "network"              # Connection, timeout, rate limit
    CAPTCHA = "captcha"              # CAPTCHA solving failures
    VALIDATION = "validation"        # Bad config, missing credentials
    FILE_SYSTEM = "filesystem"       # Download, upload, file access
    BANKING = "banking"              # Bank-specific errors
    SYSTEM = "system"                # Critical system failures
    UNKNOWN = "unknown"              # Uncategorized errors


class ErrorSeverity(Enum):
    """Error severity levels (maps to Messenger priority)."""
    CRITICAL = 1    # System failure, requires immediate action
    HIGH = 2        # Service degradation, auth failures
    MEDIUM = 3      # Recoverable errors, retries ongoing
    LOW = 4         # Transient issues, auto-recovering


@dataclass
class ErrorMetadata:
    """Rich error context for enhanced reporting."""
    category: ErrorCategory
    severity: ErrorSeverity
    worker_alias: Optional[str] = None
    bank_name: Optional[str] = None
    operation: Optional[str] = None
    attempt: Optional[int] = None
    max_attempts: Optional[int] = None
    recoverable: bool = True
    fingerprint: Optional[str] = None  # For deduplication


# ============================================================
# Error Classification
# ============================================================

def classify_error(
    error: BaseException,
    context: str,
) -> tuple[ErrorCategory, ErrorSeverity]:
    """
    Automatically classify error based on type and context.
    
    Args:
        error: The exception that occurred
        context: Context string describing where error occurred
        
    Returns:
        Tuple of (category, severity)
    """
    error_type = type(error).__name__
    error_msg = str(error).lower()
    context_lower = context.lower()
    
    # Critical system failures
    if any(x in error_msg for x in ["system failure", "critical", "shutdown"]):
        return ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL
    
    # Authentication errors
    if any(x in context_lower for x in ["login", "auth", "token", "jwt"]):
        if "expired" in error_msg or "unauthorized" in error_msg:
            return ErrorCategory.AUTHENTICATION, ErrorSeverity.HIGH
        return ErrorCategory.AUTHENTICATION, ErrorSeverity.MEDIUM
    
    # CAPTCHA errors
    if "captcha" in context_lower or "captcha" in error_msg:
        return ErrorCategory.CAPTCHA, ErrorSeverity.MEDIUM
    
    # Network errors
    if error_type in ["ConnectionError", "Timeout", "TimeoutException", 
                      "RetryAfter", "NetworkError", "RequestException"]:
        return ErrorCategory.NETWORK, ErrorSeverity.MEDIUM
    
    # File system errors
    if error_type in ["FileNotFoundError", "PermissionError", "IOError"]:
        return ErrorCategory.FILE_SYSTEM, ErrorSeverity.HIGH
    
    # Validation errors
    if error_type in ["ValueError", "KeyError", "RuntimeError"] and \
       any(x in error_msg for x in ["missing", "invalid", "empty", "required"]):
        return ErrorCategory.VALIDATION, ErrorSeverity.HIGH
    
    # Banking/worker errors
    if any(x in context_lower for x in ["statement", "download", "upload", 
                                         "balance", "transaction"]):
        return ErrorCategory.BANKING, ErrorSeverity.MEDIUM
    
    # Default: unknown, medium severity
    return ErrorCategory.UNKNOWN, ErrorSeverity.MEDIUM


def generate_error_fingerprint(
    error: BaseException,
    context: str,
    alias: Optional[str] = None,
) -> str:
    """
    Generate unique fingerprint for error deduplication.
    
    Creates a hash based on:
    - Error type
    - Error message (normalized)
    - Context
    - Worker alias
    
    Args:
        error: The exception
        context: Context string
        alias: Optional worker alias
        
    Returns:
        16-character hexadecimal fingerprint
    """
    # Normalize error message (remove numbers, timestamps, paths)
    msg = str(error)
    msg = re.sub(r'\d+', 'N', msg)  # Replace numbers
    msg = re.sub(r'/[^\s]+', '/PATH', msg)  # Replace paths
    msg = re.sub(r'\d{2}:\d{2}:\d{2}', 'HH:MM:SS', msg)  # Replace times
    
    # Create fingerprint components
    components = [
        type(error).__name__,
        msg[:100],  # First 100 chars of normalized message
        context,
        alias or "",
    ]
    
    fingerprint_str = "|".join(components)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


# ============================================================
# Recovery Suggestions
# ============================================================

def get_recovery_suggestions(
    category: ErrorCategory,
    error: BaseException,
    metadata: Optional[ErrorMetadata] = None,
) -> List[str]:
    """
    Get actionable recovery suggestions based on error category.
    
    Args:
        category: Error category
        error: The exception
        metadata: Optional error metadata
        
    Returns:
        List of recovery suggestion strings
    """
    suggestions: List[str] = []
    error_msg = str(error).lower()
    
    if category == ErrorCategory.AUTHENTICATION:
        suggestions.extend([
            "• Verify credentials in CSV file are correct",
            "• Check if account is locked or password expired",
            "• Use <code>/stop {alias}</code> then <code>/run {alias}</code> to restart",
        ])
        if "token" in error_msg or "jwt" in error_msg:
            suggestions.append("• Token will auto-refresh - wait 2-5 minutes")
    
    elif category == ErrorCategory.NETWORK:
        suggestions.extend([
            "• Check internet connectivity",
            "• Verify bank website is accessible",
            "• Wait for automatic retry (exponential backoff)",
        ])
        if "rate limit" in error_msg:
            suggestions.append("• System will auto-throttle requests")
    
    elif category == ErrorCategory.CAPTCHA:
        suggestions.extend([
            "• Check 2Captcha API balance: https://2captcha.com",
            "• Manual CAPTCHA will be sent to Telegram if auto-solve fails",
            "• Verify 2Captcha API key in .env file",
        ])
    
    elif category == ErrorCategory.FILE_SYSTEM:
        suggestions.extend([
            "• Check disk space: <code>df -h</code>",
            "• Verify downloads/ directory is writable",
            "• Clear old files if needed",
        ])
    
    elif category == ErrorCategory.VALIDATION:
        suggestions.extend([
            "• Review .env configuration file",
            "• Use <code>/list</code> to verify credentials",
            "• Use <code>/edit {alias}</code> to update credentials",
        ])
    
    elif category == ErrorCategory.BANKING:
        if metadata and metadata.attempt and metadata.max_attempts:
            if metadata.attempt < metadata.max_attempts:
                suggestions.append(
                    f"• Automatic retry {metadata.attempt}/{metadata.max_attempts} in progress"
                )
        suggestions.extend([
            "• Check if bank website is undergoing maintenance",
            "• Use <code>/status {alias}</code> to capture screenshots",
            "• Review screenshots for unexpected popups or errors",
        ])
    
    elif category == ErrorCategory.SYSTEM:
        suggestions.extend([
            "• Contact administrator immediately",
            "• Review system logs for root cause",
            "• Consider restarting the bot if issue persists",
        ])
    
    # Add worker-specific suggestion
    if metadata and metadata.worker_alias:
        alias = metadata.worker_alias
        if not any("{alias}" in s for s in suggestions):
            suggestions.append(
                f"• Worker: <code>{alias}</code> - "
                f"use <code>/stop {alias}</code> to stop if needed"
            )
    
    return suggestions


# ============================================================
# Smart Traceback Filtering
# ============================================================

def filter_traceback(tb_lines: List[str], max_lines: int = 15) -> str:
    """
    Filter and format traceback to highlight relevant information.
    
    Removes:
    - Selenium WebDriver internals
    - Telegram bot framework internals
    - Threading/asyncio noise
    
    Highlights:
    - PayTrix bot code
    - The actual error location
    
    Args:
        tb_lines: Raw traceback lines
        max_lines: Maximum lines to include
        
    Returns:
        Filtered and formatted traceback
    """
    # Patterns to filter out (framework noise)
    skip_patterns = [
        r'site-packages/selenium/',
        r'site-packages/telegram/',
        r'site-packages/urllib3/',
        r'lib/python\d+\.\d+/',
        r'<frozen ',
    ]
    
    # Patterns to highlight (our code)
    highlight_patterns = [
        r'payatom_bot/',
        r'workers/',
        r'handlers/',
    ]
    
    filtered_lines: List[str] = []
    current_frame: List[str] = []
    keep_frame = False
    
    for line in tb_lines:
        # Check if this is a new frame
        if line.strip().startswith('File "'):
            # Process previous frame
            if current_frame and keep_frame:
                filtered_lines.extend(current_frame)
            
            # Start new frame
            current_frame = [line]
            
            # Determine if we should keep this frame
            keep_frame = not any(
                re.search(pattern, line) for pattern in skip_patterns
            )
            
            # Always keep if it's our code
            if any(re.search(pattern, line) for pattern in highlight_patterns):
                keep_frame = True
                # Highlight our code
                current_frame[0] = ">>> " + current_frame[0]
        else:
            current_frame.append(line)
    
    # Process last frame
    if current_frame and keep_frame:
        filtered_lines.extend(current_frame)
    
    # Ensure we don't exceed max lines
    if len(filtered_lines) > max_lines:
        # Keep first few and last few
        keep_start = max_lines // 2
        keep_end = max_lines - keep_start - 1
        
        filtered_lines = (
            filtered_lines[:keep_start] +
            [f"... ({len(filtered_lines) - max_lines} lines omitted) ...\n"] +
            filtered_lines[-keep_end:]
        )
    
    return "".join(filtered_lines)


# ============================================================
# Enhanced Error Formatting
# ============================================================

def format_exception_message(
    error: BaseException,
    context: str,
    *,
    metadata: Optional[ErrorMetadata] = None,
    include_traceback: bool = True,
    include_suggestions: bool = True,
    max_tb_lines: int = 15,
) -> str:
    """
    Format exception into professional, context-aware error message.
    
    Features:
    - Severity-based formatting
    - Smart traceback filtering
    - Actionable recovery suggestions
    - Worker context enrichment
    - Error fingerprinting for deduplication
    
    Args:
        error: The exception that occurred
        context: Description of where/what was happening
        metadata: Optional rich error context
        include_traceback: Whether to include traceback
        include_suggestions: Whether to include recovery suggestions
        max_tb_lines: Maximum traceback lines
        
    Returns:
        Formatted HTML message for Telegram
    """
    # Auto-classify if no metadata provided
    if metadata is None:
        category, severity = classify_error(error, context)
        metadata = ErrorMetadata(
            category=category,
            severity=severity,
        )
    
    # Generate fingerprint
    if not metadata.fingerprint:
        metadata.fingerprint = generate_error_fingerprint(
            error, 
            context, 
            metadata.worker_alias
        )
    
    # Build header based on severity
    header = _format_error_header(metadata.severity, metadata.category)
    
    # Context section with enrichment
    context_section = _format_context_section(context, metadata)
    
    # Error details
    error_section = (
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<b>⚠️ Error Details:</b>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"<b>Type:</b> <code>{html.escape(type(error).__name__)}</code>\n"
        f"<b>Message:</b> <code>{html.escape(str(error))}</code>\n"
    )
    
    # Traceback section
    traceback_section = ""
    if include_traceback:
        tb_lines = traceback.format_exception(
            type(error), error, error.__traceback__
        )
        filtered_tb = filter_traceback(tb_lines, max_tb_lines)
        
        traceback_section = (
            f"\n<b>━━━━━━━━━━━━━━━━━━━</b>\n"
            f"<b>🔍 Technical Details:</b>\n"
            f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
            f"<pre>{html.escape(filtered_tb)}</pre>\n"
        )
    
    # Recovery suggestions
    suggestions_section = ""
    if include_suggestions:
        suggestions = get_recovery_suggestions(
            metadata.category, 
            error, 
            metadata
        )
        
        if suggestions:
            suggestions_section = (
                f"\n<b>━━━━━━━━━━━━━━━━━━━</b>\n"
                f"<b>💡 Recovery Steps:</b>\n"
                f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
                + "\n".join(suggestions) + "\n"
            )
    
    # Footer with fingerprint
    footer = (
        f"\n<b>━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<i>Error ID: {metadata.fingerprint}</i>\n"
        f"<i>Automated Error Report</i>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━</b>"
    )
    
    return (
        header + 
        context_section + 
        error_section + 
        traceback_section + 
        suggestions_section + 
        footer
    )


def _format_error_header(severity: ErrorSeverity, category: ErrorCategory) -> str:
    """Format error header based on severity."""
    if severity == ErrorSeverity.CRITICAL:
        return (
            "🔴🔴🔴 <b>CRITICAL SYSTEM ERROR</b> 🔴🔴🔴\n\n"
            "⚠️ <b>IMMEDIATE ATTENTION REQUIRED</b> ⚠️\n\n"
        )
    elif severity == ErrorSeverity.HIGH:
        return (
            "🚨 <b>High Priority Error</b> 🚨\n\n"
            f"Category: {category.name}\n\n"
        )
    elif severity == ErrorSeverity.MEDIUM:
        return (
            "⚠️ <b>Error Detected</b>\n\n"
            f"Category: {category.name}\n\n"
        )
    else:  # LOW
        return (
            "ℹ️ <b>Recoverable Issue</b>\n\n"
            f"Category: {category.name}\n\n"
        )


def _format_context_section(context: str, metadata: ErrorMetadata) -> str:
    """Format context section with enrichment."""
    section = (
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<b>📍 Context:</b>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"<b>Operation:</b> {html.escape(context)}\n"
    )
    
    if metadata.worker_alias:
        section += f"<b>Worker:</b> <code>{metadata.worker_alias}</code>\n"
    
    if metadata.bank_name:
        section += f"<b>Bank:</b> {metadata.bank_name}\n"
    
    if metadata.operation:
        section += f"<b>Step:</b> {metadata.operation}\n"
    
    if metadata.attempt and metadata.max_attempts:
        section += (
            f"<b>Retry:</b> {metadata.attempt}/{metadata.max_attempts} "
            f"{'(retrying...)' if metadata.attempt < metadata.max_attempts else '(max reached)'}\n"
        )
    
    section += "\n"
    return section


# ============================================================
# Messenger Integration
# ============================================================

async def notify_error_to_telegram(
    bot: Bot,
    chat_id: int,
    error: BaseException,
    context: str,
    *,
    metadata: Optional[ErrorMetadata] = None,
    include_traceback: bool = True,
) -> None:
    """
    Send formatted error notification to Telegram with smart splitting.
    
    Args:
        bot: Telegram bot instance
        chat_id: Chat ID to send to
        error: The exception
        context: Context description
        metadata: Optional error metadata
        include_traceback: Whether to include traceback
    """
    message = format_exception_message(
        error,
        context,
        metadata=metadata,
        include_traceback=include_traceback,
    )
    
    try:
        # Split if needed (Telegram 4096 char limit)
        if len(message) > 4000:
            await _send_split_message(bot, chat_id, error, context, metadata)
        else:
            await bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
    except Exception as notify_error:
        logger.exception(
            "Failed to send error notification to Telegram: %s",
            notify_error,
        )


async def _send_split_message(
    bot: Bot,
    chat_id: int,
    error: BaseException,
    context: str,
    metadata: Optional[ErrorMetadata],
) -> None:
    """Send error in multiple parts if too long."""
    # Part 1: Header + Context + Error (no traceback)
    part1 = format_exception_message(
        error,
        context,
        metadata=metadata,
        include_traceback=False,
        include_suggestions=True,
    )
    
    await bot.send_message(
        chat_id=chat_id,
        text=part1,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )
    
    # Part 2: Traceback only
    tb_text = "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )
    filtered_tb = filter_traceback(tb_text.split("\n"), max_lines=30)
    
    traceback_msg = (
        f"<b>🔍 Full Traceback (Error ID: {metadata.fingerprint if metadata else 'N/A'}):</b>\n\n"
        f"<pre>{html.escape(filtered_tb[:3500])}</pre>"
    )
    
    await bot.send_message(
        chat_id=chat_id,
        text=traceback_msg,
        parse_mode=ParseMode.HTML,
    )


# ============================================================
# Handler Exception Handling
# ============================================================

async def handle_handler_exception(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    error: BaseException,
    handler_name: str,
) -> None:
    """
    Handle exceptions in Telegram handlers with rich context.
    
    Args:
        update: Telegram update
        context: Callback context
        error: The exception
        handler_name: Handler name
    """
    logger.exception(
        "Exception in handler '%s': %s",
        handler_name,
        error,
    )
    
    metadata = ErrorMetadata(
        category=ErrorCategory.SYSTEM,
        severity=ErrorSeverity.HIGH,
        operation=handler_name,
        recoverable=True,
    )
    
    message = format_exception_message(
        error, 
        f"Telegram handler: {handler_name}",
        metadata=metadata,
    )
    
    # Try to reply
    try:
        if update.effective_message:
            # Truncate if needed for reply
            if len(message) > 4000:
                message = format_exception_message(
                    error,
                    f"Telegram handler: {handler_name}",
                    metadata=metadata,
                    include_traceback=False,
                )
            
            await update.effective_message.reply_text(
                message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return
    except Exception as reply_error:
        logger.exception("Failed to reply to message: %s", reply_error)
    
    # Fallback: send to chat
    try:
        if update.effective_chat:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
    except Exception as send_error:
        logger.exception("Failed to send error message: %s", send_error)


# ============================================================
# Decorators
# ============================================================

def telegram_handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    Decorator for Telegram handlers with comprehensive error handling.
    
    Usage:
        @telegram_handler_error_wrapper
        async def my_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
            # handler code
    """
    @functools.wraps(handler_func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        try:
            return await handler_func(update, context, *args, **kwargs)
        except Exception as e:
            await handle_handler_exception(
                update,
                context,
                e,
                handler_func.__name__,
            )
    
    return wrapper


def worker_method_error_wrapper(method: Callable) -> Callable:
    """
    Decorator for worker methods with enhanced error reporting.
    
    Usage:
        class MyWorker(BaseWorker):
            @worker_method_error_wrapper
            def _some_method(self):
                # method code
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as e:
            # Build rich metadata
            metadata = ErrorMetadata(
                category=ErrorCategory.BANKING,
                severity=ErrorSeverity.MEDIUM,
                worker_alias=getattr(self, 'alias', None),
                bank_name=getattr(self, 'cred', {}).get('bank_label'),
                operation=method.__name__,
                recoverable=True,
            )
            
            context = f"{self.__class__.__name__}.{method.__name__}"
            if metadata.worker_alias:
                context = f"[{metadata.worker_alias}] {context}"
            
            # Log with full context
            logger.exception(
                "Exception in %s: %s",
                context,
                e,
            )
            
            # Send via messenger if available
            if hasattr(self, "msgr") and self.msgr:
                message = format_exception_message(e, context, metadata=metadata)
                try:
                    # Map severity to Messenger kind
                    kind = {
                        ErrorSeverity.CRITICAL: "ERROR",
                        ErrorSeverity.HIGH: "ERROR",
                        ErrorSeverity.MEDIUM: "ERROR",
                        ErrorSeverity.LOW: "INFO",
                    }.get(metadata.severity, "ERROR")
                    
                    self.msgr.send_event(message, kind=kind)
                except Exception as msg_error:
                    logger.exception(
                        "Failed to send error via messenger: %s",
                        msg_error,
                    )
            
            # Screenshot if possible
            if hasattr(self, "screenshot_all_tabs"):
                try:
                    self.screenshot_all_tabs(f"Error in {method.__name__}")
                except Exception as screenshot_error:
                    logger.exception(
                        "Failed to take error screenshot: %s",
                        screenshot_error,
                    )
            
            # Re-raise
            raise
    
    return wrapper


# ============================================================
# Context Managers
# ============================================================

class ErrorContext:
    """
    Sync context manager for error handling with automatic reporting.
    
    Usage:
        with ErrorContext("processing data", messenger=msgr, alias="test"):
            # code that might fail
    """
    
    def __init__(
        self,
        context: str,
        *,
        messenger: Optional[Messenger] = None,
        alias: Optional[str] = None,
        bank: Optional[str] = None,
        operation: Optional[str] = None,
        reraise: bool = True,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
    ):
        self.context = context
        self.messenger = messenger
        self.metadata = ErrorMetadata(
            category=category or ErrorCategory.UNKNOWN,
            severity=severity or ErrorSeverity.MEDIUM,
            worker_alias=alias,
            bank_name=bank,
            operation=operation,
        )
        self.reraise = reraise
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return False
        
        # Auto-classify if not specified
        if self.metadata.category == ErrorCategory.UNKNOWN:
            category, severity = classify_error(exc_val, self.context)
            self.metadata.category = category
            self.metadata.severity = severity
        
        # Build full context
        full_context = self.context
        if self.metadata.worker_alias:
            full_context = f"[{self.metadata.worker_alias}] {full_context}"
        
        # Log
        logger.exception(
            "Exception in %s: %s",
            full_context,
            exc_val,
        )
        
        # Send via messenger
        if self.messenger:
            message = format_exception_message(
                exc_val, 
                full_context,
                metadata=self.metadata,
            )
            try:
                # Map to messenger kind
                kind = {
                    ErrorSeverity.CRITICAL: "ERROR",
                    ErrorSeverity.HIGH: "ERROR",
                    ErrorSeverity.MEDIUM: "ERROR",
                    ErrorSeverity.LOW: "INFO",
                }.get(self.metadata.severity, "ERROR")
                
                self.messenger.send_event(message, kind=kind)
            except Exception as msg_error:
                logger.exception(
                    "Failed to send error via messenger: %s",
                    msg_error,
                )
        
        # Return True to suppress, False to propagate
        return not self.reraise


class AsyncErrorContext:
    """
    Async context manager for error handling in async code.
    
    Usage:
        async with AsyncErrorContext("async operation", messenger=msgr):
            # async code that might fail
    """
    
    def __init__(
        self,
        context: str,
        *,
        messenger: Optional[Messenger] = None,
        alias: Optional[str] = None,
        bank: Optional[str] = None,
        operation: Optional[str] = None,
        reraise: bool = True,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
    ):
        # Delegate to sync version for most logic
        self._sync_context = ErrorContext(
            context,
            messenger=messenger,
            alias=alias,
            bank=bank,
            operation=operation,
            reraise=reraise,
            category=category,
            severity=severity,
        )
    
    async def __aenter__(self):
        self._sync_context.__enter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self._sync_context.__exit__(exc_type, exc_val, exc_tb)


# ============================================================
# Safe Operation Utilities
# ============================================================

def safe_operation(
    operation: Callable,
    *args,
    context: str = "operation",
    default: Any = None,
    log_errors: bool = True,
    **kwargs,
) -> Any:
    """
    Execute operation safely with automatic error logging.
    
    Args:
        operation: Function to execute
        *args: Arguments to pass
        context: Operation description
        default: Return value on failure
        log_errors: Whether to log errors
        **kwargs: Keyword arguments to pass
        
    Returns:
        Result or default on failure
    """
    try:
        return operation(*args, **kwargs)
    except Exception as e:
        if log_errors:
            logger.exception(
                "Safe operation '%s' failed: %s",
                context,
                e,
            )
        return default


async def safe_async_operation(
    operation: Callable,
    *args,
    context: str = "async operation",
    default: Any = None,
    log_errors: bool = True,
    **kwargs,
) -> Any:
    """
    Execute async operation safely with automatic error logging.
    
    Args:
        operation: Async function to execute
        *args: Arguments to pass
        context: Operation description
        default: Return value on failure
        log_errors: Whether to log errors
        **kwargs: Keyword arguments to pass
        
    Returns:
        Result or default on failure
    """
    try:
        return await operation(*args, **kwargs)
    except Exception as e:
        if log_errors:
            logger.exception(
                "Safe async operation '%s' failed: %s",
                context,
                e,
            )
        return default