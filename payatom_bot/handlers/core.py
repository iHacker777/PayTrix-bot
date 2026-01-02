# payatom_bot/handlers/core.py
"""
Core command handlers for PayTrix Bot.

Provides essential bot commands:
- /start: Initial greeting and bot status
- /help: Comprehensive command reference with categorized commands
- /version: Bot version and system information (optional)

Features:
- Integration with existing error handling (@telegram_handler_error_wrapper)
- Professional documentation following project standards
- Comprehensive help text organized by functional categories
- Audit logging for critical operations
- No excessive emojis (professional banking system)
"""
from __future__ import annotations

import logging
import platform
import sys
from datetime import datetime
from typing import Optional

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from ..config import Settings
from ..error_handler import telegram_handler_error_wrapper
from ..logging_config import log_audit_event

logger = logging.getLogger(__name__)

# Version information (update this with each release)
__version__ = "2.0.0"
__release_date__ = "2025-01-02"


# ============================================================
# Command Handlers
# ============================================================

@telegram_handler_error_wrapper
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /start command - Initial bot greeting.
    
    Provides welcome message and directs user to /help for full command list.
    Logs audit event for bot startup interaction.
    
    Args:
        update: Telegram update object
        context: Callback context
    """
    user = update.effective_user
    
    # Audit log for user interaction
    log_audit_event(
        event_type='BOT_START_COMMAND',
        details={
            'user_id': user.id,
            'username': user.username or 'N/A',
            'first_name': user.first_name or 'N/A',
        },
        level=logging.INFO,
    )
    
    welcome_message = (
        "<b>PayTrix Bot - Banking Automation System</b>\n\n"
        "This is the official RPA bot for automated bank statement downloads "
        "and financial data processing.\n\n"
        "<b>Status:</b> Online and operational\n\n"
        "Use /help to view all available commands and get started."
    )
    
    await update.message.reply_text(
        welcome_message,
        parse_mode=ParseMode.HTML,
    )
    
    logger.info(
        "User initiated /start command: user_id=%s, username=%s",
        user.id,
        user.username or 'N/A',
    )


@telegram_handler_error_wrapper
async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /help command - Display comprehensive command reference.
    
    Provides organized command list grouped by functionality:
    - Session Management (run, stop, status monitoring)
    - Account Management (credentials, configuration)
    - Balance Monitoring (alerts, thresholds)
    - File Management (statement downloads)
    - System Commands (help, version, diagnostics)
    
    Args:
        update: Telegram update object
        context: Callback context
    """
    help_text = (
        "<b>📋 PayTrix Bot - Command Reference</b>\n\n"
        
        # Session Management
        "<b>━━━ Session Management ━━━</b>\n"
        "<b>/run</b> <code>&lt;alias&gt;</code> - Start worker for account\n"
        "  • Single: <code>/run madras_tmb</code>\n"
        "  • Multiple: <code>/run acc1 acc2 acc3</code>\n"
        "  • Date range: <code>/run acc1 from 01/01/2025 to 31/01/2025</code>\n\n"
        
        "<b>/stop</b> <code>&lt;alias&gt;</code> - Stop worker(s)\n"
        "  • Single: <code>/stop madras_tmb</code>\n"
        "  • Multiple: <code>/stop acc1 acc2</code>\n\n"
        
        "<b>/stopall</b> - Stop all running workers\n\n"
        
        "<b>/running</b> - List all active workers\n\n"
        
        "<b>/active</b> - Check upload status of workers\n"
        "  • Shows last CipherBank upload timestamp\n"
        "  • Highlights workers with stale uploads\n\n"
        
        "<b>/status</b> <code>&lt;alias&gt;</code> - Capture worker screenshots\n\n"
        
        # Account Management
        "<b>━━━ Account Management ━━━</b>\n"
        "<b>/list</b> or <b>/aliases</b> - Show all configured accounts\n"
        "  • Displays bank, account number (masked)\n"
        "  • Shows current worker status\n\n"
        
        "<b>/add</b> - Add new account credentials\n"
        "  • Format: <code>/add alias,username,password,account</code>\n"
        "  • IOB Corporate: <code>/add alias,login,user,pass,account</code>\n\n"
        
        "<b>/edit</b> <code>&lt;alias&gt;</code> - Edit account credentials\n"
        "  • Interactive menu for field selection\n"
        "  • Secure password handling\n\n"
        
        "<b>/view</b> <code>&lt;alias&gt;</code> - View full credentials\n"
        "  • Requires confirmation\n"
        "  • Auto-deletes after 60 seconds\n\n"
        
        # Balance Monitoring
        "<b>━━━ Balance Monitoring ━━━</b>\n"
        "<b>/balance</b> [alias...] - Show account balances\n"
        "  • All: <code>/balance</code>\n"
        "  • Specific: <code>/balance acc1 acc2</code>\n\n"
        
        "<b>/balances</b> - Detailed balance check with thresholds\n\n"
        
        "<b>/alerts</b> - View alert system status\n"
        "  • Shows monitoring configuration\n"
        "  • Lists active alerts\n\n"
        
        "<b>/reset_alerts</b> <code>&lt;alias&gt;</code> - Reset balance alerts\n"
        "  • After fund transfers\n"
        "  • Use 'all' to reset everything\n\n"
        
        # File Management
        "<b>━━━ File Management ━━━</b>\n"
        "<b>/file</b> <code>&lt;alias&gt;</code> - Download latest statement\n"
        "  • Retrieves most recent downloaded file\n"
        "  • Shows file metadata\n\n"
        
        # System Commands
        "<b>━━━ System Commands ━━━</b>\n"
        "<b>/start</b> - Initial bot greeting\n"
        "<b>/help</b> - Show this help message\n"
        "<b>/version</b> - Display bot version info\n\n"
        
        # Alert Thresholds Reference
        "<b>━━━ Balance Alert Thresholds ━━━</b>\n"
        "• ₹50,000 - Low priority (monitor)\n"
        "• ₹60,000 - Low-medium (watch closely)\n"
        "• ₹70,000 - Medium (transfer urgently)\n"
        "• ₹90,000 - High (immediate action)\n"
        "• ₹100,000+ - <b>CRITICAL</b> (stop operations)\n\n"
        
        # Support Information
        "<b>━━━ Support ━━━</b>\n"
        "For technical issues or credential access,\n"
        "contact your manager or IT team.\n\n"
        
        "<i>PayTrix Bot v{version} - {release_date}</i>"
    ).format(version=__version__, release_date=__release_date__)
    
    await update.message.reply_text(
        help_text,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )
    
    logger.debug(
        "User requested /help: user_id=%s",
        update.effective_user.id,
    )


@telegram_handler_error_wrapper
async def version_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /version command - Display bot version and system information.
    
    Shows:
    - Bot version and release date
    - Python version
    - System platform
    - Uptime (if available)
    
    Args:
        update: Telegram update object
        context: Callback context
    """
    # Get application start time from bot_data if available
    app_start_time: Optional[datetime] = context.application.bot_data.get('app_start_time')
    
    uptime_str = "Unknown"
    if app_start_time:
        uptime_delta = datetime.now() - app_start_time
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if days > 0:
            uptime_str = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            uptime_str = f"{hours}h {minutes}m"
        else:
            uptime_str = f"{minutes}m {seconds}s"
    
    version_info = (
        "<b>PayTrix Bot - System Information</b>\n\n"
        f"<b>Version:</b> {__version__}\n"
        f"<b>Release Date:</b> {__release_date__}\n"
        f"<b>Python:</b> {sys.version.split()[0]}\n"
        f"<b>Platform:</b> {platform.system()} {platform.release()}\n"
        f"<b>Uptime:</b> {uptime_str}\n\n"
        "<i>Enterprise Banking Automation System</i>"
    )
    
    await update.message.reply_text(
        version_info,
        parse_mode=ParseMode.HTML,
    )
    
    logger.debug(
        "User requested /version: user_id=%s",
        update.effective_user.id,
    )


# ============================================================
# Handler Registration
# ============================================================

def register_core_handlers(app: Application, settings: Settings) -> None:
    """
    Register core command handlers with the Telegram application.
    
    Registers:
    - /start - Initial greeting
    - /help - Comprehensive command reference
    - /version - System version information
    
    Args:
        app: Telegram application instance
        settings: Application settings (for future use)
    """
    # Core commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("version", version_cmd))
    
    logger.info("Core handlers registered: /start, /help, /version")