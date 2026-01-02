# payatom_bot/handlers/captcha.py
"""
CAPTCHA and OTP handler for PayTrix Bot.

Automatically detects and distributes OTP codes and CAPTCHA solutions to
active worker instances via Telegram message monitoring.

Features:
- Automatic OTP detection (6-digit numeric codes)
- CAPTCHA solution detection (4-8 alphanumeric characters)
- Thread-safe worker registry access
- Comprehensive validation and error handling
- Audit logging for security compliance
- Integration with existing error handling framework
- PII-safe logging with masked codes

Architecture:
- Monitors all non-command Telegram messages
- Extracts OTP/CAPTCHA codes using validated regex patterns
- Distributes codes to all active workers via attribute injection
- Provides immediate feedback on successful application

Security Considerations:
- Codes are consumed immediately by workers
- No persistent storage of sensitive codes
- Comprehensive audit trail for compliance
- Safe attribute access with hasattr checks
- Exception handling prevents system disruption
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from telegram import Update
from telegram.ext import ContextTypes, MessageHandler, filters

from ..error_handler import (
    ErrorContext,
    ErrorCategory,
    ErrorMetadata,
    ErrorSeverity,
    telegram_handler_error_wrapper,
    safe_operation,
)
from ..logging_config import log_audit_event

logger = logging.getLogger(__name__)

# Validation patterns
OTP_PATTERN = re.compile(r"\b(\d{6})\b")
CAPTCHA_PATTERN = re.compile(r"^[A-Za-z0-9]{4,8}$")

# Code type constants
CODE_TYPE_OTP = "OTP"
CODE_TYPE_CAPTCHA = "CAPTCHA"


# ============================================================
# Registry Access
# ============================================================


def _get_worker_registry(context: ContextTypes.DEFAULT_TYPE) -> Dict[str, object]:
    """
    Retrieve worker registry from application context.
    
    Args:
        context: Telegram callback context
        
    Returns:
        Dictionary mapping alias to worker instances
    """
    registry = context.application.bot_data.get("workers")
    
    if not isinstance(registry, dict):
        logger.warning(
            "Worker registry not found in bot_data - creating empty registry"
        )
        registry = {}
        context.application.bot_data["workers"] = registry
    
    return registry  # type: ignore[return-value]


# ============================================================
# Code Detection and Validation
# ============================================================


def _detect_code(text: str) -> Optional[Tuple[str, str]]:
    """
    Detect OTP or CAPTCHA code in message text.
    
    Priority:
    1. OTP (6-digit numeric) - more specific, checked first
    2. CAPTCHA (4-8 alphanumeric) - broader pattern, fallback
    
    Args:
        text: Raw message text to analyze
        
    Returns:
        Tuple of (code, code_type) or None if no valid code detected
        
    Examples:
        >>> _detect_code("Your OTP is 123456")
        ("123456", "OTP")
        >>> _detect_code("CAPTCHA: ABC123")
        ("ABC123", "CAPTCHA")
        >>> _detect_code("Hello world")
        None
    """
    if not text:
        return None
    
    # Try OTP first (6-digit numeric)
    otp_match = OTP_PATTERN.search(text)
    if otp_match:
        code = otp_match.group(1)
        logger.debug("OTP code detected in message")
        return (code, CODE_TYPE_OTP)
    
    # Try CAPTCHA (4-8 alphanumeric, no spaces)
    cleaned_text = text.replace(" ", "").strip()
    
    if CAPTCHA_PATTERN.fullmatch(cleaned_text):
        # Normalize to uppercase for consistency
        code = cleaned_text.upper()
        logger.debug("CAPTCHA code detected in message")
        return (code, CODE_TYPE_CAPTCHA)
    
    # No valid code detected
    return None


def _apply_code_to_worker(
    worker: object,
    code: str,
    code_type: str,
    alias: str
) -> Optional[str]:
    """
    Apply OTP or CAPTCHA code to worker instance.
    
    Safely sets the appropriate attribute on the worker using hasattr
    checks to prevent AttributeError exceptions.
    
    Args:
        worker: Worker instance
        code: The code to apply
        code_type: Either CODE_TYPE_OTP or CODE_TYPE_CAPTCHA
        alias: Worker alias for logging
        
    Returns:
        Success message if applied, None otherwise
        
    Thread Safety:
        Safe to call from Telegram handler thread. Workers poll these
        attributes from their own threads, so no locking required.
    """
    try:
        # Apply based on code type
        if code_type == CODE_TYPE_OTP:
            if hasattr(worker, "otp_code"):
                setattr(worker, "otp_code", code)
                logger.debug("Applied OTP code to worker: %s", alias)
                return f"{alias}: OTP"
        
        # CAPTCHA codes are always applied (all workers have captcha_code)
        if hasattr(worker, "captcha_code"):
            setattr(worker, "captcha_code", code)
            logger.debug("Applied CAPTCHA code to worker: %s", alias)
            
            # Return message only if not already applied as OTP
            if code_type == CODE_TYPE_CAPTCHA:
                return f"{alias}: CAPTCHA"
            elif code_type == CODE_TYPE_OTP:
                # Also applied as CAPTCHA (dual application)
                return f"{alias}: OTP+CAPTCHA"
    
    except Exception as e:
        logger.warning(
            "Failed to apply %s code to worker %s: %s",
            code_type,
            alias,
            e
        )
    
    return None


# ============================================================
# Main Handler
# ============================================================


@telegram_handler_error_wrapper
async def otp_or_captcha_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
) -> None:
    """
    Detect and distribute OTP/CAPTCHA codes from Telegram messages.
    
    Monitors all text messages (excluding commands) for:
    - 6-digit OTP codes
    - 4-8 character alphanumeric CAPTCHA solutions
    
    Automatically distributes detected codes to all active workers
    that support the respective code type.
    
    Args:
        update: Telegram update with message
        context: Callback context with application data
    """
    # Extract and validate message text
    if not update.effective_message or not update.effective_message.text:
        return
    
    text = update.effective_message.text.strip()
    if not text:
        return
    
    # Detect code
    detection_result = safe_operation(
        lambda: _detect_code(text),
        context="detect OTP/CAPTCHA code",
        default=None,
        log_errors=False,  # Not an error if no code detected
    )
    
    if not detection_result:
        # No valid code in message - silently ignore
        return
    
    code, code_type = detection_result
    
    # Get worker registry
    workers = _get_worker_registry(context)
    
    if not workers:
        logger.debug(
            "No active workers - %s code ignored: %s",
            code_type,
            "***" + code[-3:] if len(code) >= 3 else "***"
        )
        return
    
    # Apply code to all applicable workers
    applied_workers: List[str] = []
    
    for alias, worker in list(workers.items()):
        result = safe_operation(
            lambda w=worker, a=alias: _apply_code_to_worker(
                w, code, code_type, a
            ),
            context=f"apply {code_type} to {alias}",
            default=None,
            log_errors=True,
        )
        
        if result:
            applied_workers.append(result)
    
    # Send feedback if code was applied
    if applied_workers:
        # Mask code for security (show last 3 chars only)
        masked_code = "***" + code[-3:] if len(code) >= 3 else "***"
        
        # Format success message
        worker_list = ", ".join(applied_workers)
        message = f"Applied {code_type} code {masked_code} to: {worker_list}"
        
        # Send confirmation
        await safe_operation(
            lambda: update.effective_message.reply_text(message),
            context="send code application confirmation",
            default=None,
            log_errors=True,
        )
        
        # Audit log for code application
        log_audit_event(
            f"{code_type}_CODE_APPLIED",
            {
                "code_type": code_type,
                "code_masked": masked_code,
                "workers": [w.split(":")[0] for w in applied_workers],
                "count": len(applied_workers),
                "user_id": update.effective_user.id if update.effective_user else "unknown",
            },
            level=logging.INFO,
        )
        
        logger.info(
            "%s code applied to %d worker(s): %s",
            code_type,
            len(applied_workers),
            ", ".join([w.split(":")[0] for w in applied_workers])
        )
    else:
        # Code detected but no applicable workers
        logger.debug(
            "%s code detected but no workers support it (active: %d)",
            code_type,
            len(workers)
        )


# ============================================================
# Registration
# ============================================================


def register_captcha_handlers(app) -> None:
    """
    Register CAPTCHA/OTP handler with Telegram application.
    
    Captures all non-command text messages and processes them for
    OTP/CAPTCHA code detection.
    
    Args:
        app: Telegram Application instance
        
    Note:
        To restrict to specific chats, add additional filters:
        filters.TEXT & ~filters.COMMAND & filters.Chat(chat_id=ALLOWED_CHAT_ID)
    """
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            otp_or_captcha_handler
        )
    )
    
    logger.info("CAPTCHA/OTP handler registered successfully")
    
    # Audit log
    log_audit_event(
        'CAPTCHA_HANDLER_REGISTERED',
        {
            'handler': 'otp_or_captcha_handler',
            'filters': 'TEXT & ~COMMAND',
        },
        level=logging.INFO,
    )