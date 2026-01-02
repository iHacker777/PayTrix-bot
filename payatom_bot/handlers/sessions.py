# payatom_bot/handlers/sessions.py
"""
Enterprise-grade session management handlers for PayTrix Bot.

This module provides comprehensive Telegram command handlers for managing
worker lifecycles, monitoring operations, and system status reporting.

Commands:
    Worker Management:
    - /run <alias> [from dd/mm/yyyy to dd/mm/yyyy] - Start worker(s)
    - /stop <alias>... - Stop worker(s)
    - /stopall - Stop all workers
    - /status <alias> - Capture status screenshots
    
    Monitoring & Status:
    - /running - List running workers
    - /active - Check workers with upload status
    - /balance [alias...] - Show account balances
    
    Balance Alert Management:
    - /alerts - Show balance monitoring status
    - /reset_alerts <alias|all> - Reset balance alerts
    - /balances [alias...] - Check balances with alert status
    
    File Operations:
    - /file <alias> - Retrieve latest statement file

Features:
    - Automatic worker lifecycle management
    - Date range support for KGB workers
    - Real-time balance monitoring
    - Comprehensive audit trail
    - Thread-safe operations
    - Professional error handling
    - Smart retry logic with screenshots
    - Balance threshold tracking

Security:
    - Account numbers masked in all outputs
    - Comprehensive audit logging for all operations
    - Thread-safe credential access
    - Secure file handling with validation
    - PII protection in logs

Industry Standards:
    - Comprehensive error handling with rich context
    - Audit trail for compliance
    - Professional messaging format
    - Thread-safe registry operations
    - Proper resource cleanup
"""
from __future__ import annotations

import html
import inspect
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from ..balance_monitor import THRESHOLDS, parse_balance_amount
from ..captcha_solver import TwoCaptcha
from ..config import Settings
from ..error_handler import (
    ErrorCategory,
    ErrorMetadata,
    ErrorSeverity,
    safe_operation,
    telegram_handler_error_wrapper,
)
from ..logging_config import log_audit_event

# Workers
from ..workers.canara import CanaraWorker
from ..workers.idbi import IDBIWorker
from ..workers.idfc import IDFCWorker
from ..workers.iob import IOBWorker
from ..workers.kgb import KGBWorker
from ..workers.tmb import TMBWorker

logger = logging.getLogger(__name__)


# ============================================================
# Worker Registry Management
# ============================================================

def _get_registry(context: ContextTypes.DEFAULT_TYPE) -> Dict[str, object]:
    """
    Get or create the worker registry from bot_data.
    
    Thread-safe access to the global worker registry. Creates the registry
    if it doesn't exist.
    
    Args:
        context: Telegram context containing application data
        
    Returns:
        Worker registry dictionary mapping aliases to worker instances
    """
    reg = context.application.bot_data.get("workers")
    if reg is None:
        reg = {}
        context.application.bot_data["workers"] = reg
    return reg


def _normalize_bank_label(label: str) -> str:
    """
    Normalize bank label for consistent comparison.
    
    Handles variations in bank names like "IOB" vs "Indian Overseas Bank"
    and ensures consistent formatting.
    
    Args:
        label: Raw bank label from credentials
        
    Returns:
        Normalized uppercase bank label
    """
    if not label:
        return ""
    lbl = label.strip().upper().replace("&", "AND")
    return " ".join(lbl.split())


# Worker class registry
WORKER_BY_BANK: Dict[str, Any] = {
    "TMB": TMBWorker,
    "IOB": IOBWorker,
    "IOB CORPORATE": IOBWorker,
    "KGB": KGBWorker,
    "KERALA GRAMIN BANK": KGBWorker,
    "IDBI": IDBIWorker,
    "IDFC": IDFCWorker,
    "CANARA": CanaraWorker,
}

# Bank name aliases for flexibility
_ALIASES = {
    "INDIAN OVERSEAS BANK": "IOB",
    "IOB CORP": "IOB CORPORATE",
    "IOB-CORPORATE": "IOB CORPORATE",
    "CNRB": "CANARA",
}


def _pick_worker_class(bank_label: str) -> Tuple[Optional[type], str]:
    """
    Select the appropriate worker class for a bank label.
    
    Args:
        bank_label: Bank name from credentials
        
    Returns:
        Tuple of (WorkerClass or None, normalized_bank_label)
    """
    lbl = _normalize_bank_label(bank_label)
    lbl = _ALIASES.get(lbl, lbl)
    return WORKER_BY_BANK.get(lbl), lbl


def _instantiate_worker(worker_cls: type, common_kwargs: Dict[str, Any]) -> Any:
    """
    Instantiate a worker with only the parameters it accepts.
    
    Uses introspection to pass only the parameters that the worker's
    __init__ method actually accepts, avoiding TypeErrors.
    
    Args:
        worker_cls: Worker class to instantiate
        common_kwargs: Dictionary of all available parameters
        
    Returns:
        Instantiated worker instance
    """
    sig = inspect.signature(worker_cls.__init__)
    allowed = {k: v for k, v in common_kwargs.items() if k in sig.parameters}
    return worker_cls(**allowed)


# ============================================================
# Date Range Parsing
# ============================================================

def _parse_date(s: str) -> datetime:
    """
    Parse date from dd/mm/yyyy or dd/mm/yy format.
    
    Args:
        s: Date string to parse
        
    Returns:
        Parsed datetime object
        
    Raises:
        ValueError: If date format is invalid
    """
    s = s.strip()
    for fmt in ("%d/%m/%Y", "%d/%m/%y"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Invalid date format: {s} (expected dd/mm/yyyy)")


def _extract_aliases_and_range(
    args: List[str]
) -> Tuple[List[str], Optional[Tuple[datetime, datetime]]]:
    """
    Extract aliases and optional date range from command arguments.
    
    Supports two formats:
    - /run alias1 alias2 alias3
    - /run alias1 from dd/mm/yyyy to dd/mm/yyyy
    
    Args:
        args: Command arguments list
        
    Returns:
        Tuple of (aliases_list, date_range_tuple or None)
        
    Raises:
        ValueError: If date range format is invalid
    """
    if not args:
        return [], None

    try:
        from_idx = next(i for i, t in enumerate(args) if t.lower() == "from")
    except StopIteration:
        # No range - all args are aliases
        return args, None

    aliases = [t for t in args[:from_idx] if t.lower() not in {"from", "to"}]

    try:
        to_idx = next(
            i
            for i, t in enumerate(args[from_idx + 1 :], start=from_idx + 1)
            if t.lower() == "to"
        )
    except StopIteration:
        raise ValueError(
            "Missing 'to' in date range. "
            "Use: /run <alias> from dd/mm/yyyy to dd/mm/yyyy"
        )

    if to_idx - from_idx != 2 or len(args) <= to_idx + 1:
        raise ValueError(
            "Invalid range format. "
            "Use: /run <alias> from dd/mm/yyyy to dd/mm/yyyy"
        )

    dt_from = _parse_date(args[from_idx + 1])
    dt_to = _parse_date(args[to_idx + 1])

    if dt_to < dt_from:
        raise ValueError("'to' date cannot be before 'from' date")

    return aliases, (dt_from, dt_to)


# ============================================================
# Helper Functions
# ============================================================

def _mask_account_number(account: str | int | None) -> str:
    """
    Mask account number showing only last 4 digits.
    
    Provides consistent masking format across the application for
    displaying account numbers in logs and messages.
    
    Args:
        account: Account number to mask (string or int)
        
    Returns:
        Masked account number (e.g., "****1234")
    """
    s = str(account or "").strip()
    return ("****" + s[-4:]) if len(s) >= 4 else s or "—"


def _format_time_delta(delta: timedelta) -> str:
    """
    Format timedelta as human-readable string.
    
    Args:
        delta: Time difference to format
        
    Returns:
        Formatted string (e.g., '2h 15m 30s')
    """
    total = int(delta.total_seconds())
    if total < 0:
        total = 0
    mins, secs = divmod(total, 60)
    hours, mins = divmod(mins, 60)

    parts: List[str] = []
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _escape_markdown(text: str) -> str:
    """
    Escape special characters for Telegram MarkdownV2.
    
    Args:
        text: Text to escape
        
    Returns:
        Escaped text safe for Markdown
    """
    return text.replace("_", r"\_").replace("*", r"\*").replace("`", r"\`")


# ============================================================
# Worker Management
# ============================================================

def start_worker_for_alias(
    context: ContextTypes.DEFAULT_TYPE,
    alias: str,
    date_range: Optional[Tuple[datetime, datetime]] = None,
) -> str:
    """
    Start a worker for the given alias with comprehensive error handling.
    
    Creates and starts a new worker instance for the specified account.
    Handles worker class selection, parameter preparation, and provides
    detailed status reporting.
    
    Features:
    - Validates alias existence
    - Checks for already-running workers
    - Selects appropriate worker class
    - Configures worker parameters
    - Logs audit trail
    - Handles date ranges for KGB workers
    
    Args:
        context: Telegram context with application data
        alias: Account alias to start
        date_range: Optional date range tuple (from_date, to_date) for KGB
        
    Returns:
        Status message describing the operation result
        
    Security:
        - Account numbers masked in messages
        - Audit logging for worker starts
        - Credential validation
    """
    try:
        app = context.application
        settings: Settings = app.bot_data["settings"]
        messenger = app.bot_data["messenger"]
        creds_by_alias: Dict[str, dict] = app.bot_data.get("creds_by_alias", {})

        alias = alias.strip()
        if not alias:
            return "❌ Alias was empty"

        # Validate credential exists
        cred = creds_by_alias.get(alias)
        if not cred:
            return f"❌ Unknown alias `{alias}`. Check your credentials CSV."

        workers = _get_registry(context)
        existing = workers.get(alias)

        # Check if already running
        if existing and safe_operation(
            lambda: existing.is_alive(),
            context=f"check if {alias} is alive",
            default=False,
        ):
            return f"⚠️ `{alias}` is already running"

        # Find appropriate worker class
        worker_cls, norm_bank = _pick_worker_class(cred.get("bank_label", ""))
        if not worker_cls:
            return (
                f"⏸️ `{alias}` uses unsupported bank `{cred.get('bank_label', 'unknown')}`.\n"
                f"Supported banks: {', '.join(WORKER_BY_BANK.keys())}"
            )

        # Build profile directory
        profile_dir = os.path.join(settings.profile_root, alias)

        # Prepare worker parameters
        common_kwargs = dict(
            bot=app.bot,
            chat_id=settings.telegram_chat_id,
            alias=alias,
            cred=cred,
            messenger=messenger,
            profile_dir=profile_dir,
            two_captcha=(
                TwoCaptcha(settings.two_captcha_key)
                if settings.two_captcha_key
                else None
            ),
        )

        # Instantiate and configure worker
        try:
            worker = _instantiate_worker(worker_cls, common_kwargs)

            # Apply date range for KGB workers
            if isinstance(worker, KGBWorker) and date_range:
                worker.from_dt, worker.to_dt = date_range

            worker.start()
            workers[alias] = worker

            # Log worker start
            logger.info("Started worker: alias=%s, bank=%s", alias, norm_bank)

            # Audit trail for worker lifecycle
            log_audit_event(
                "WORKER_STARTED",
                {
                    "alias": alias,
                    "bank": norm_bank,
                    "account_masked": _mask_account_number(
                        cred.get("account_number", "")
                    ),
                    "has_date_range": bool(date_range),
                },
                level=logging.INFO,
            )

        except Exception as e:
            logger.exception("Failed to start worker for %s", alias)
            return (
                f"❌ Failed to start `{alias}` ({norm_bank})\n"
                f"Error: {type(e).__name__}: {str(e)}"
            )

        # Success message
        if isinstance(worker, KGBWorker) and date_range:
            f, t = date_range
            return (
                f"✅ Started `{alias}` ({norm_bank})\n"
                f"📅 Date range: {f:%d/%m/%Y} → {t:%d/%m/%Y}"
            )
        return f"✅ Started `{alias}` ({norm_bank})"

    except Exception as e:
        logger.exception("Unexpected error starting worker for %s", alias)
        return f"❌ Unexpected error starting `{alias}`: {str(e)}"


# ============================================================
# Telegram Command Handlers
# ============================================================


@telegram_handler_error_wrapper
async def run_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Start one or more workers with optional date range.
    
    Command: /run <alias> [from dd/mm/yyyy to dd/mm/yyyy]
    
    Examples:
        /run madras_tmb
        /run madras_tmb kochi_iob
        /run kochi_kgb from 01/01/2025 to 15/01/2025
    """
    try:
        aliases, dr = _extract_aliases_and_range(context.args or [])
    except ValueError as e:
        await update.message.reply_text(
            f"❌ {e}\n\n"
            f"**Usage:**\n"
            f"`/run <alias>` or\n"
            f"`/run <alias> from dd/mm/yyyy to dd/mm/yyyy`",
            parse_mode="Markdown",
        )
        return

    if not aliases:
        await update.message.reply_text(
            "**Usage:**\n"
            "`/run <alias>` - Start a worker\n"
            "`/run <alias1> <alias2>` - Start multiple workers\n"
            "`/run <alias> from dd/mm/yyyy to dd/mm/yyyy` - Start with date range (KGB only)",
            parse_mode="Markdown",
        )
        return

    lines: List[str] = []
    for alias in aliases:
        msg = start_worker_for_alias(context, alias, date_range=dr)
        lines.append(msg)

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@telegram_handler_error_wrapper
async def stop_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Stop one or more running workers.
    
    Command: /stop <alias> [<alias2> ...]
    
    Examples:
        /stop madras_tmb
        /stop madras_tmb kochi_iob
    """
    if not context.args:
        await update.message.reply_text(
            "**Usage:**\n"
            "`/stop <alias>` - Stop a worker\n"
            "`/stop <alias1> <alias2>` - Stop multiple workers",
            parse_mode="Markdown",
        )
        return

    workers = _get_registry(context)
    lines: List[str] = []

    for alias in context.args:
        alias = alias.strip()
        w = workers.get(alias)

        if not w or not safe_operation(
            lambda: w.is_alive(), context=f"check if {alias} is alive", default=False
        ):
            lines.append(f"ℹ️ `{alias}` is not running")
            continue

        try:
            w.stop()
            w.join(timeout=5.0)
            workers.pop(alias, None)
            lines.append(f"🛑 Stopped `{alias}`")
            
            logger.info("Stopped worker: alias=%s", alias)

            # Audit trail for worker stop
            log_audit_event(
                "WORKER_STOPPED",
                {
                    "alias": alias,
                    "method": "command",
                },
                level=logging.INFO,
            )

        except Exception as e:
            logger.exception("Error stopping worker %s", alias)
            lines.append(f"⚠️ Error stopping `{alias}`: {type(e).__name__}")
            workers.pop(alias, None)  # Remove anyway

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@telegram_handler_error_wrapper
async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Capture screenshots of worker tabs for debugging.
    
    Command: /status <alias>
    
    Example:
        /status madras_tmb
    """
    if not context.args:
        await update.message.reply_text(
            "**Usage:** `/status <alias>`", parse_mode="Markdown"
        )
        return

    alias = context.args[0]
    w = _get_registry(context).get(alias)

    if not w:
        await update.message.reply_text(
            f"❌ `{alias}` is not running", parse_mode="Markdown"
        )
        return

    try:
        w.screenshot_all_tabs(f"Status requested for {alias}")
        await update.message.reply_text(
            f"📸 Captured status screenshots for `{alias}`", parse_mode="Markdown"
        )
        
        # Audit log for status check
        log_audit_event(
            "WORKER_STATUS_CHECK",
            {"alias": alias, "method": "screenshot"},
            level=logging.INFO,
        )

    except Exception as e:
        logger.exception("Failed to capture status for %s", alias)
        await update.message.reply_text(
            f"⚠️ Failed to capture status for `{alias}`: {type(e).__name__}",
            parse_mode="Markdown",
        )


@telegram_handler_error_wrapper
async def stopall_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Stop all running workers.
    
    Command: /stopall
    
    Security: Comprehensive audit logging of bulk operations
    """
    workers = _get_registry(context)
    stopped = []
    errors = []

    for alias, w in list(workers.items()):
        try:
            if safe_operation(
                lambda: w.is_alive(),
                context=f"check if {alias} is alive",
                default=False,
            ):
                w.stop()
                w.join(timeout=5.0)
                stopped.append(alias)
                logger.info("Stopped worker: alias=%s", alias)
        except Exception as e:
            logger.exception("Error stopping worker %s", alias)
            errors.append(alias)
        finally:
            workers.pop(alias, None)

    if not stopped and not errors:
        await update.message.reply_text(
            "ℹ️ No workers were running", parse_mode="Markdown"
        )
    else:
        parts = []
        if stopped:
            parts.append("🧹 Stopped: " + ", ".join(f"`{a}`" for a in stopped))
        if errors:
            parts.append("⚠️ Errors: " + ", ".join(f"`{a}`" for a in errors))
        await update.message.reply_text("\n".join(parts), parse_mode="Markdown")

    # Audit trail for bulk stop
    if stopped or errors:
        log_audit_event(
            "WORKERS_BULK_STOP",
            {
                "stopped_count": len(stopped),
                "error_count": len(errors),
                "stopped_aliases": ",".join(stopped) if stopped else "none",
            },
            level=logging.WARNING if errors else logging.INFO,
        )


@telegram_handler_error_wrapper
async def running_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    List all currently running workers.
    
    Command: /running
    
    Displays workers grouped with their bank information.
    """
    workers = _get_registry(context)
    active = [
        a
        for a, w in workers.items()
        if safe_operation(
            lambda: w.is_alive(), context=f"check if {a} is alive", default=False
        )
    ]

    if not active:
        await update.message.reply_text("😴 No active workers", parse_mode="Markdown")
        return

    creds_by_alias: Dict[str, dict] = context.application.bot_data.get(
        "creds_by_alias", {}
    )
    decorated = []

    for a in active:
        bank = _normalize_bank_label(creds_by_alias.get(a, {}).get("bank_label", ""))
        decorated.append(f"`{a}` ({bank})" if bank else f"`{a}`")

    await update.message.reply_text(
        "🟢 **Running workers:**\n" + "\n".join(f"  • {d}" for d in decorated),
        parse_mode="Markdown",
    )


@telegram_handler_error_wrapper
async def active_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Check active workers with AutoBank upload status.
    
    Command: /active
    
    Shows which workers are running and when they last uploaded to AutoBank.
    Highlights workers that haven't uploaded in >5 minutes as potential issues.
    """
    workers = _get_registry(context)
    running = {
        alias: w
        for alias, w in workers.items()
        if safe_operation(
            lambda: w.is_alive(), context=f"check if {alias} is alive", default=False
        )
    }

    if not running:
        await update.message.reply_text("😴 No active workers", parse_mode="Markdown")
        return

    creds_by_alias: Dict[str, dict] = context.application.bot_data.get(
        "creds_by_alias", {}
    )
    now = datetime.now()
    threshold = timedelta(minutes=5)

    ok_lines: List[str] = []
    bad_lines: List[str] = []

    for alias, w in running.items():
        bank = _normalize_bank_label(creds_by_alias.get(alias, {}).get("bank_label", ""))
        label = f"`{alias}`" + (f" ({bank})" if bank else "")

        last_upload = safe_operation(
            lambda: w.last_upload_at,
            context=f"get last_upload_at for {alias}",
            default=None,
        )

        if not last_upload:
            bad_lines.append(f"❌ {label} — no AutoBank upload recorded yet")
            continue

        age = now - last_upload
        ago_str = _format_time_delta(age)
        last_str = last_upload.strftime("%H:%M:%S")

        if age > threshold:
            bad_lines.append(
                f"⛔ {label} — last upload at *{last_str}* ({ago_str} ago; >5 min)"
            )
        else:
            ok_lines.append(f"🟢 {label} — last upload at *{last_str}* ({ago_str} ago)")

    lines: List[str] = []
    if ok_lines:
        lines.append("✅ **Active with recent uploads:**")
        lines.extend(ok_lines)
    if bad_lines:
        if lines:
            lines.append("")
        lines.append("⚠️ **Issues detected:**")
        lines.extend(bad_lines)

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@telegram_handler_error_wrapper
async def balance_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Show balances for running workers.
    
    Command: /balance [alias...]
    
    Examples:
        /balance - Show all balances
        /balance madras_tmb - Show specific balance
        /balance madras_tmb kochi_iob - Show multiple balances
    """
    workers = _get_registry(context)
    creds_by_alias: Dict[str, dict] = context.application.bot_data.get(
        "creds_by_alias", {}
    )

    targets = context.args if context.args else list(workers.keys())

    if not targets:
        await update.message.reply_text("😴 No active workers", parse_mode="Markdown")
        return

    lines: list[str] = []

    for alias in targets:
        w = workers.get(alias)

        if not w or not safe_operation(
            lambda: w.is_alive(), context=f"check if {alias} is alive", default=False
        ):
            lines.append(f"`{alias}` — not running")
            continue

        cred = creds_by_alias.get(alias, {})
        bank = cred.get("bank_label", "?")
        bal = (
            safe_operation(
                lambda: w.last_balance,
                context=f"get balance for {alias}",
                default="loading...",
            )
            or "loading..."
        )

        # Escape special Markdown characters
        safe_alias = _escape_markdown(alias)
        safe_balance = _escape_markdown(bal)

        lines.append(f"**{safe_alias}** ({bank}) | 💰 **{safe_balance}**")

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


# ============================================================
# Balance Alert Management Commands
# ============================================================


@telegram_handler_error_wrapper
async def alerts_status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Show balance monitoring status and active alerts.
    
    Command: /alerts
    
    Displays:
    - Monitor running status
    - Alert group configuration
    - Check interval
    - Currently triggered alerts per alias
    - Threshold configuration
    """
    balance_monitor = context.application.bot_data.get("balance_monitor")

    if not balance_monitor:
        await update.message.reply_text(
            "❌ Balance monitor not initialized", parse_mode="Markdown"
        )
        return

    status = balance_monitor.get_status()

    if not status["running"]:
        await update.message.reply_text(
            "⚠️ **Balance Monitor Status**\n\n"
            "Status: ⏸️ Not Running\n"
            f"Alert Groups: {status['alert_groups']} configured\n\n"
            "ℹ️ Monitor is not active. Ensure ALERT_GROUP_IDS is configured.",
            parse_mode="Markdown",
        )
        return

    # Build status message
    lines = [
        "📊 **Balance Monitor Status**\n",
        f"Status: ✅ Running",
        f"Alert Groups: {status['alert_groups']} group(s)",
        f"Check Interval: {status['check_interval']} seconds ({status['check_interval']//60} min)",
        f"Monitored Aliases: {status['monitored_aliases']}",
        f"Total Alerts Triggered: {status['total_alerts']}\n",
    ]

    # Show triggered alerts per alias
    if balance_monitor.triggered_thresholds:
        lines.append("**🔔 Active Alerts:**")

        creds_by_alias = context.application.bot_data.get("creds_by_alias", {})

        for alias in sorted(balance_monitor.triggered_thresholds.keys()):
            thresholds = sorted(balance_monitor.triggered_thresholds[alias])
            cred = creds_by_alias.get(alias, {})
            bank = cred.get("bank_label", "")

            threshold_str = ", ".join(f"₹{t:,}" for t in thresholds)

            if bank:
                lines.append(f"  • `{alias}` ({bank}): {threshold_str}")
            else:
                lines.append(f"  • `{alias}`: {threshold_str}")
    else:
        lines.append("✅ No alerts triggered (all accounts below thresholds)")

    # Threshold information
    lines.extend(
        [
            "",
            "**📈 Configured Thresholds:**",
            "  • ₹50,000 - Low Priority",
            "  • ₹60,000 - Low-Medium Priority",
            "  • ₹70,000 - Medium Priority ⚠️",
            "  • ₹90,000 - High Priority 🚨",
            "  • ₹100,000+ - CRITICAL 🔴",
        ]
    )

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@telegram_handler_error_wrapper
async def reset_alerts_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Reset balance alerts for an alias or all aliases.
    
    Command: /reset_alerts <alias|all>
    
    Use this after transferring funds to receive alerts again when
    the account balance crosses thresholds.
    
    Examples:
        /reset_alerts madras_tmb
        /reset_alerts all
    
    Enhanced Features:
    - Includes user context in audit logs
    - Tracks who triggered the reset
    - Professional logging with user information
    """
    if not context.args:
        await update.message.reply_text(
            "**Usage:**\n"
            "`/reset_alerts <alias>` - Reset alerts for one alias\n"
            "`/reset_alerts all` - Reset alerts for all aliases\n\n"
            "ℹ️ Use this after transferring funds from an account.",
            parse_mode="Markdown",
        )
        return

    balance_monitor = context.application.bot_data.get("balance_monitor")
    if not balance_monitor:
        await update.message.reply_text(
            "❌ Balance monitor not initialized", parse_mode="Markdown"
        )
        return

    # Get user context for audit logging
    user_id = update.effective_user.id if update.effective_user else None
    username = update.effective_user.username if update.effective_user else None
    chat_id = update.effective_chat.id if update.effective_chat else None

    target = context.args[0].strip().lower()

    if target == "all":
        # Reset all alerts with user context
        count = len(balance_monitor.triggered_thresholds)
        
        # Store aliases before clearing
        reset_aliases = list(balance_monitor.triggered_thresholds.keys())
        
        # Clear all
        balance_monitor.triggered_thresholds.clear()
        balance_monitor.last_alert_time.clear()

        await update.message.reply_text(
            f"✅ Reset balance alerts for **all** aliases\n" 
            f"({count} alias(es) cleared)",
            parse_mode="Markdown",
        )
        
        # Enhanced audit log with user context
        log_audit_event(
            "BALANCE_ALERTS_BULK_RESET",
            {
                "count": count,
                "reset_aliases": reset_aliases,
                "user_id": user_id,
                "username": username,
                "chat_id": chat_id,
            },
            level=logging.INFO,
        )
        
        # Enhanced logging with user context
        logger.info(
            "Reset all balance alerts (%d aliases) - triggered by user_id=%s, username=%s",
            count,
            user_id,
            username or 'unknown',
        )

    else:
        # Reset specific alias with user context
        alias = context.args[0].strip()

        if alias in balance_monitor.triggered_thresholds:
            # Use enhanced reset method with user context
            balance_monitor.reset_alerts_for_alias(
                alias=alias,
                user_id=user_id,
                username=username,
                chat_id=chat_id,
            )
            
            await update.message.reply_text(
                f"✅ Reset balance alerts for `{alias}`\n\n"
                "ℹ️ New alerts will be sent when thresholds are crossed again.",
                parse_mode="Markdown",
            )
        else:
            await update.message.reply_text(
                f"ℹ️ No active alerts for `{alias}`", 
                parse_mode="Markdown",
            )

@telegram_handler_error_wrapper
async def check_balances_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Check current balances with detailed threshold analysis.
    
    Command: /balances [alias...]
    
    Shows current balance, nearest threshold, distance to next threshold,
    and whether alerts are active for each account.
    
    Examples:
        /balances - Check all balances
        /balances madras_tmb - Check specific balance
    """
    workers = _get_registry(context)
    creds_by_alias = context.application.bot_data.get("creds_by_alias", {})
    balance_monitor = context.application.bot_data.get("balance_monitor")

    targets = context.args if context.args else list(workers.keys())

    if not targets:
        await update.message.reply_text("😴 No active workers", parse_mode="Markdown")
        return

    lines = ["💰 **Balance Status Check**\n"]

    for alias in targets:
        w = workers.get(alias)

        if not w or not safe_operation(
            lambda: w.is_alive(), context=f"check if {alias} is alive", default=False
        ):
            lines.append(f"⚪ `{alias}` - not running")
            continue

        cred = creds_by_alias.get(alias, {})
        bank = cred.get("bank_label", "?")

        balance_str = (
            safe_operation(
                lambda: w.last_balance,
                context=f"get balance for {alias}",
                default="N/A",
            )
            or "N/A"
        )

        # Parse numeric balance
        balance_num = parse_balance_amount(balance_str)

        if balance_num is None:
            lines.append(f"🟡 `{alias}` ({bank}) - {balance_str}")
            continue

        # Check which thresholds are crossed
        triggered = []
        next_threshold = None

        for threshold in THRESHOLDS:
            if balance_num >= threshold.amount:
                triggered.append(f"₹{threshold.amount:,}")
            elif next_threshold is None:
                next_threshold = threshold

        # Determine status icon
        status_icon = (
            "🔴"
            if balance_num >= 100_000
            else "🟠"
            if balance_num >= 70_000
            else "🟡"
            if balance_num >= 50_000
            else "🟢"
        )

        balance_formatted = f"₹{balance_num:,.2f}"

        status_line = f"{status_icon} `{alias}` ({bank}) - **{balance_formatted}**"

        if triggered:
            status_line += f"\n   ⚠️ Crossed: {', '.join(triggered)}"

        if next_threshold and balance_num < next_threshold.amount:
            remaining = next_threshold.amount - balance_num
            status_line += (
                f"\n   📊 Next: ₹{next_threshold.amount:,} (₹{remaining:,.2f} away)"
            )

        # Check if alerts are active
        if balance_monitor and alias in balance_monitor.triggered_thresholds:
            alert_count = len(balance_monitor.triggered_thresholds[alias])
            status_line += f"\n   🔔 {alert_count} alert(s) sent"

        lines.append(status_line)

    await update.message.reply_text("\n\n".join(lines), parse_mode="Markdown")


@telegram_handler_error_wrapper
async def file_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Send the latest downloaded statement file for an alias.
    
    Command: /file <alias>
    
    Searches the worker's download directory for the most recent
    statement file and sends it via Telegram.
    
    Supported formats: CSV, XLS, XLSX
    
    Example:
        /file madras_tmb
    """
    if not context.args:
        await update.message.reply_text(
            "**Usage:** `/file <alias>`\n\n"
            "Send the latest downloaded statement file for the specified alias.",
            parse_mode="Markdown",
        )
        return

    alias = context.args[0].strip()

    # Validate alias exists
    creds_by_alias = context.application.bot_data.get("creds_by_alias", {})
    if alias not in creds_by_alias:
        await update.message.reply_text(
            f"❌ Unknown alias `{alias}`.\n" "Use `/list` to see available aliases.",
            parse_mode="Markdown",
        )
        return

    # Construct download directory path
    download_dir = os.path.join(os.getcwd(), "downloads", alias)

    if not os.path.exists(download_dir):
        await update.message.reply_text(
            f"❌ No downloads found for `{alias}`.\n"
            "The worker may not have run yet or the download directory doesn't exist.",
            parse_mode="Markdown",
        )
        return

    # Find the latest statement file
    try:
        # Look for common statement file extensions
        statement_files = []
        for ext in [".csv", ".xls", ".xlsx"]:
            pattern_files = [
                f for f in os.listdir(download_dir) if f.lower().endswith(ext)
            ]
            statement_files.extend(
                [os.path.join(download_dir, f) for f in pattern_files]
            )

        if not statement_files:
            await update.message.reply_text(
                f"❌ No statement files found for `{alias}`.\n"
                "The worker may not have downloaded any files yet.",
                parse_mode="Markdown",
            )
            return

        # Get the most recent file
        latest_file = max(statement_files, key=os.path.getmtime)
        file_name = os.path.basename(latest_file)
        file_size = os.path.getsize(latest_file)
        file_time = datetime.fromtimestamp(os.path.getmtime(latest_file))

        # Format file info
        size_kb = file_size / 1024
        time_str = file_time.strftime("%d/%m/%Y %H:%M:%S")

        # Get bank info
        cred = creds_by_alias.get(alias, {})
        bank = cred.get("bank_label", "")

        # Send status message
        status_msg = (
            f"📄 Sending latest statement for `{alias}`"
            + (f" ({bank})" if bank else "")
            + "...\n\n"
            f"**File:** `{file_name}`\n"
            f"**Size:** {size_kb:.2f} KB\n"
            f"**Downloaded:** {time_str}"
        )

        await update.message.reply_text(status_msg, parse_mode="Markdown")

        # Send the file
        with open(latest_file, "rb") as f:
            await update.message.reply_document(
                document=f, filename=file_name, caption=f"📊 Latest statement for {alias}"
            )

        logger.info("Sent file %s for alias %s to user", file_name, alias)

        # Audit log for file retrieval
        log_audit_event(
            "FILE_RETRIEVED",
            {
                "alias": alias,
                "filename": file_name,
                "size_kb": round(size_kb, 2),
                "user_id": update.effective_user.id if update.effective_user else "unknown",
            },
            level=logging.INFO,
        )

    except Exception as e:
        logger.exception("Error sending file for alias %s", alias)
        await update.message.reply_text(
            f"❌ Failed to send file for `{alias}`\n"
            f"Error: {type(e).__name__}: {str(e)}",
            parse_mode="Markdown",
        )


# ============================================================
# Handler Registration
# ============================================================


def register_session_handlers(app: Application, settings: Settings) -> None:
    """
    Register all session management command handlers.
    
    Registers handlers for:
    - Worker management (run, stop, stopall, status)
    - Monitoring (running, active, balance)
    - Balance alerts (alerts, reset_alerts, balances)
    - File operations (file)
    
    Args:
        app: Telegram application instance
        settings: Application settings
    """
    # Worker management
    app.add_handler(CommandHandler("run", run_cmd))
    app.add_handler(CommandHandler("stop", stop_cmd))
    app.add_handler(CommandHandler("stopall", stopall_cmd))
    app.add_handler(CommandHandler("status", status_cmd))

    # Monitoring
    app.add_handler(CommandHandler("running", running_cmd))
    app.add_handler(CommandHandler("active", active_cmd))
    app.add_handler(CommandHandler("balance", balance_cmd))

    # Balance alert management
    app.add_handler(CommandHandler("alerts", alerts_status_cmd))
    app.add_handler(CommandHandler("reset_alerts", reset_alerts_cmd))
    app.add_handler(CommandHandler("balances", check_balances_cmd))

    # File operations
    app.add_handler(CommandHandler("file", file_cmd))

    logger.info(
        "Registered session management handlers: "
        "worker management, monitoring, balance alerts, file operations"
    )