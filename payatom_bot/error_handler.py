# payatom_bot/error_handler.py
"""
Centralized error handling and formatting for the Autobot V2 system.

Provides uniform, professional error messages across all components with
proper logging, Telegram notifications, and user-friendly formatting.
"""
from __future__ import annotations

import functools
import html
import logging
import traceback
from typing import Callable, Optional, Any, TYPE_CHECKING

from telegram.constants import ParseMode

if TYPE_CHECKING:
    from telegram import Update, Bot
    from telegram.ext import ContextTypes
    from .messaging import Messenger

logger = logging.getLogger(__name__)

# Contact information for support
SUPPORT_CONTACT = "@pablo_escobar999"
SUPPORT_EMAIL = "support@moshano.in"


def format_exception_message(
    error: BaseException,
    context: str,
    *,
    include_traceback: bool = True,
    max_tb_lines: int = 15,
) -> str:
    """
    Format an exception into a professional, user-friendly message.

    Args:
        error: The exception that occurred
        context: Description of where/what was happening when error occurred
        include_traceback: Whether to include the full traceback
        max_tb_lines: Maximum number of traceback lines to include

    Returns:
        Formatted HTML message ready for Telegram
    """
    # Header with emoji and friendly message
    header = (
        "🚨 <b>Oops! An Unexpected Error Occurred</b>\n\n"
        "An unhandled exception has occurred in the system. "
        "If this issue persists, please contact our support team:\n"
        f"• Telegram: {html.escape(SUPPORT_CONTACT)}\n"
        f"• Email: {html.escape(SUPPORT_EMAIL)}\n\n"
    )

    # Context and error type
    error_info = (
        f"<b>📍 Context:</b> <code>{html.escape(context)}</code>\n"
        f"<b>⚠️ Error Type:</b> <code>{html.escape(type(error).__name__)}</code>\n"
        f"<b>💬 Message:</b> <code>{html.escape(str(error))}</code>\n"
    )

    # Traceback if requested
    tb_section = ""
    if include_traceback:
        tb_lines = traceback.format_exception(type(error), error, error.__traceback__)
        tb_text = "".join(tb_lines)

        # Limit traceback length
        tb_split = tb_text.split("\n")
        if len(tb_split) > max_tb_lines:
            tb_displayed = "\n".join(tb_split[:max_tb_lines])
            tb_displayed += f"\n... ({len(tb_split) - max_tb_lines} more lines)"
        else:
            tb_displayed = tb_text

        tb_section = (
            f"\n<b>🔍 Technical Details:</b>\n"
            f"<pre>{html.escape(tb_displayed)}</pre>"
        )

    return header + error_info + tb_section


async def notify_error_to_telegram(
    bot: Bot,
    chat_id: int,
    error: BaseException,
    context: str,
    *,
    include_traceback: bool = True,
) -> None:
    """
    Send a formatted error notification to Telegram.

    Args:
        bot: Telegram bot instance
        chat_id: Chat ID to send the message to
        error: The exception that occurred
        context: Description of where/what was happening
        include_traceback: Whether to include the full traceback
    """
    message = format_exception_message(
        error,
        context,
        include_traceback=include_traceback,
    )

    try:
        # Split message if too long (Telegram limit is ~4096 characters)
        if len(message) > 4000:
            # Send header and error info first
            header_msg = format_exception_message(
                error,
                context,
                include_traceback=False,
            )
            await bot.send_message(
                chat_id=chat_id,
                text=header_msg,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )

            # Then send traceback separately
            tb_text = "".join(
                traceback.format_exception(type(error), error, error.__traceback__)
            )
            await bot.send_message(
                chat_id=chat_id,
                text=f"<b>🔍 Full Traceback:</b>\n<pre>{html.escape(tb_text[:3800])}</pre>",
                parse_mode=ParseMode.HTML,
            )
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


async def handle_handler_exception(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    error: BaseException,
    handler_name: str,
) -> None:
    """
    Handle exceptions that occur in Telegram handlers.

    Args:
        update: The Telegram update that triggered the handler
        context: The callback context
        error: The exception that occurred
        handler_name: Name of the handler for logging
    """
    logger.exception(
        "Exception in handler '%s': %s",
        handler_name,
        error,
    )

    message = format_exception_message(error, handler_name)

    # Try to reply to the message that caused the error
    try:
        if update.effective_message:
            await update.effective_message.reply_text(
                message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return
    except Exception as reply_error:
        logger.exception("Failed to reply to message: %s", reply_error)

    # Fallback: send to the chat
    try:
        if update.effective_chat:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
    except Exception as send_error:
        logger.exception("Failed to send error message to chat: %s", send_error)


def telegram_handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    Decorator to wrap Telegram handlers with uniform error handling.

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
    Decorator to wrap worker methods with error handling and reporting.

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
            # Get method context
            context = f"{self.__class__.__name__}.{method.__name__} [{self.alias}]"

            # Log the error
            logger.exception(
                "Exception in %s: %s",
                context,
                e,
            )

            # Format and send error message via worker's messenger
            if hasattr(self, "msgr") and hasattr(self, "alias"):
                message = format_exception_message(e, context)
                try:
                    self.msgr.send_event(message, kind="ERROR")
                except Exception as msg_error:
                    logger.exception(
                        "Failed to send error via messenger: %s",
                        msg_error,
                    )

            # Take screenshot if possible
            if hasattr(self, "screenshot_all_tabs"):
                try:
                    self.screenshot_all_tabs(f"Error in {method.__name__}")
                except Exception as screenshot_error:
                    logger.exception(
                        "Failed to take error screenshot: %s",
                        screenshot_error,
                    )

            # Re-raise to allow caller to handle
            raise

    return wrapper


class ErrorContext:
    """
    Context manager for error handling with automatic logging and reporting.

    Usage:
        with ErrorContext("processing user data", messenger=msgr, alias="test_alias"):
            # code that might fail
    """

    def __init__(
        self,
        context: str,
        *,
        messenger: Optional[Messenger] = None,
        alias: Optional[str] = None,
        reraise: bool = True,
    ):
        self.context = context
        self.messenger = messenger
        self.alias = alias
        self.reraise = reraise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return False

        # Build full context
        full_context = self.context
        if self.alias:
            full_context = f"[{self.alias}] {full_context}"

        # Log the error
        logger.exception(
            "Exception in %s: %s",
            full_context,
            exc_val,
        )

        # Send via messenger if available
        if self.messenger:
            message = format_exception_message(exc_val, full_context)
            try:
                self.messenger.send_event(message, kind="ERROR")
            except Exception as msg_error:
                logger.exception(
                    "Failed to send error via messenger: %s",
                    msg_error,
                )

        # Return True to suppress exception, False to propagate
        return not self.reraise


def safe_operation(
    operation: Callable,
    *args,
    context: str = "operation",
    default: Any = None,
    log_errors: bool = True,
    **kwargs,
) -> Any:
    """
    Execute an operation safely, catching and logging any exceptions.

    Args:
        operation: Function to execute
        *args: Arguments to pass to the operation
        context: Description of the operation for logging
        default: Value to return if operation fails
        log_errors: Whether to log errors
        **kwargs: Keyword arguments to pass to the operation

    Returns:
        Result of operation, or default value if it fails
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
    Execute an async operation safely, catching and logging any exceptions.

    Args:
        operation: Async function to execute
        *args: Arguments to pass to the operation
        context: Description of the operation for logging
        default: Value to return if operation fails
        log_errors: Whether to log errors
        **kwargs: Keyword arguments to pass to the operation

    Returns:
        Result of operation, or default value if it fails
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
