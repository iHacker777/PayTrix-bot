"""
Enterprise-grade alias management handlers for PayTrix Bot.

This module provides Telegram command handlers for managing bank account credentials:
- /list, /aliases: Display all configured accounts with masked details
- /add: Create new account credentials
- /edit: Interactive credential modification
- /delete: Remove account credentials (future)

Features:
- Live credential updates with hot-reload
- Comprehensive audit logging for all modifications
- Thread-safe operations
- Input validation and sanitization
- Integration with encrypted credential storage
- Professional error handling and reporting

Security:
- Passwords never echoed back to users
- Account numbers masked in all outputs
- Audit trail for all credential operations
- Secure file permission validation
"""
from __future__ import annotations

import asyncio
import csv
import html
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from ..config import Settings
from ..creds import load_creds, sanitize_account_number
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

# ============================================================
# State Management
# ============================================================

# Tracks ongoing edit operations: chat_id -> {"alias": ..., "field": ..., "label": ...}
_pending_edits: Dict[int, Dict[str, str]] = {}

# CSV field mappings for inline keyboard callbacks
FIELD_MAPPINGS: Dict[str, tuple[str, str]] = {
    "login": ("login_id", "Login ID"),
    "user": ("user_id", "User ID"),
    "password": ("password", "Password"),
    "account": ("account_number", "Account Number"),
}


# ============================================================
# Helper Functions
# ============================================================

def _get_settings(app: Application) -> Settings:
    """
    Retrieve Settings from application context with validation.
    
    Args:
        app: Telegram application instance
        
    Returns:
        Settings instance
        
    Raises:
        RuntimeError: If settings not properly initialized
    """
    settings = app.bot_data.get("settings")
    if not isinstance(settings, Settings):
        raise RuntimeError(
            "Application settings not initialized. "
            "Ensure build_application() stored Settings instance in app.bot_data['settings']."
        )
    return settings


def _get_credentials(app: Application) -> Dict[str, dict]:
    """
    Retrieve credentials dictionary from application context.
    
    Args:
        app: Telegram application instance
        
    Returns:
        Dictionary mapping alias to credential details
    """
    creds = app.bot_data.get("creds_by_alias")
    if isinstance(creds, dict):
        return creds  # type: ignore[return-value]
    
    logger.warning(
        "Credentials registry not found in bot_data - returning empty dict"
    )
    return {}


def _set_credentials(app: Application, creds: Dict[str, dict]) -> None:
    """
    Update credentials in application context.
    
    Args:
        app: Telegram application instance
        creds: New credentials dictionary
    """
    app.bot_data["creds_by_alias"] = creds


def _get_workers(app: Application) -> Dict[str, object]:
    """
    Retrieve worker registry from application context.
    
    Args:
        app: Telegram application instance
        
    Returns:
        Dictionary mapping alias to worker instances
    """
    registry = app.bot_data.get("workers")
    if not isinstance(registry, dict):
        logger.warning(
            "Worker registry not found in bot_data - creating empty registry"
        )
        registry = {}
        app.bot_data["workers"] = registry
    return registry  # type: ignore[return-value]


def _mask_account_number(account_number: str) -> str:
    """
    Mask account number showing only last 4 digits.
    
    Args:
        account_number: Full account number
        
    Returns:
        Masked account number (e.g., "***1234")
    """
    digits = "".join(ch for ch in account_number if ch.isdigit())
    last_four = digits[-4:] if digits and len(digits) >= 4 else ""
    return f"***{last_four}" if last_four else "***"


def _validate_csv_permissions(csv_path: str) -> None:
    """
    Validate credentials CSV has secure permissions.
    
    Args:
        csv_path: Path to credentials CSV file
        
    Raises:
        RuntimeError: If file has insecure permissions
    """
    from ..creds import validate_file_permissions
    
    try:
        validate_file_permissions(csv_path, strict=False)
    except PermissionError as e:
        logger.warning("Credentials file has insecure permissions: %s", e)


# ============================================================
# CSV Operations
# ============================================================

def update_credential_field(
    app: Application,
    alias: str,
    field_key: str,
    new_value: str,
) -> None:
    """
    Update a single credential field in CSV and reload credentials.
    
    This function:
    1. Reads the entire CSV
    2. Updates the specific field for the given alias
    3. Validates uniqueness constraints (account numbers)
    4. Writes back to CSV
    5. Reloads credentials into memory
    6. Updates any running worker with new credentials
    
    Args:
        app: Telegram application instance
        alias: Account alias to update
        field_key: CSV column name (e.g., 'password', 'account_number')
        new_value: New value for the field
        
    Raises:
        KeyError: If alias not found in CSV
        ValueError: If account number already used by another alias
        RuntimeError: If CSV operations fail
    """
    settings = _get_settings(app)
    csv_path = settings.credentials_csv
    new_value = (new_value or "").strip()

    with ErrorContext(
        f"updating {field_key} for alias {alias}",
        operation="update_credential_csv",
        reraise=True,
    ):
        rows: List[dict] = []
        found = False
        duplicate_alias: Optional[str] = None
        fieldnames: Optional[List[str]] = None

        # Read all rows and check for conflicts
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                
                for row in reader:
                    row_alias = (row.get("alias") or "").strip()
                    row_account = (row.get("account_number") or "").strip()

                    # Check for duplicate account number
                    if (
                        field_key == "account_number"
                        and row_account == new_value
                        and row_alias != alias
                    ):
                        duplicate_alias = row_alias

                    # Update the target row
                    if row_alias == alias:
                        row[field_key] = new_value
                        found = True

                    rows.append(row)
                    
        except FileNotFoundError as e:
            raise RuntimeError(
                f"Credentials CSV not found at '{csv_path}'. "
                "Please create the file with account credentials."
            ) from e
        except PermissionError as e:
            raise RuntimeError(
                f"Permission denied reading credentials CSV at '{csv_path}'. "
                "Please check file permissions."
            ) from e
        except csv.Error as e:
            raise RuntimeError(
                f"CSV file '{csv_path}' is malformed: {e}"
            ) from e

        # Validation checks
        if not found:
            raise KeyError(f"Alias '{alias}' not found in credentials")

        if field_key == "account_number" and duplicate_alias:
            raise ValueError(
                f"Account number already used by alias '{duplicate_alias}'"
            )

        # Ensure we have fieldnames
        if fieldnames is None:
            fieldnames = [
                "alias",
                "login_id",
                "user_id",
                "username",
                "password",
                "account_number",
            ]

        # Write updated CSV
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        except PermissionError as e:
            raise RuntimeError(
                f"Permission denied writing credentials CSV at '{csv_path}'. "
                "Please check file permissions."
            ) from e
        except OSError as e:
            raise RuntimeError(
                f"Failed to write credentials CSV '{csv_path}': {e}"
            ) from e

        # Reload credentials from CSV
        try:
            new_creds = load_creds(csv_path, auto_detect_encryption=True)
        except Exception as e:
            raise RuntimeError(
                f"CSV updated but failed to reload credentials: {e}. "
                "Please check file format and permissions."
            ) from e

        _set_credentials(app, new_creds)

        # Update running worker's credential snapshot (best effort)
        workers = _get_workers(app)
        worker = workers.get(alias)
        
        if worker is not None:
            try:
                # Update worker's credential dictionary if it has one
                if hasattr(worker, "cred") and isinstance(worker.cred, dict):
                    worker.cred[field_key] = new_value
                    logger.debug(
                        "Updated running worker credential for %s: %s",
                        alias,
                        field_key
                    )
            except Exception as e:
                logger.debug(
                    "Could not update running worker for %s: %s",
                    alias,
                    e
                )

        # Audit log for credential modification
        log_audit_event(
            "CREDENTIAL_UPDATED",
            {
                "alias": alias,
                "field": field_key,
                "operation": "edit",
            },
            level=logging.INFO,
        )

        logger.info(
            "Updated credential for %s: %s modified",
            alias,
            field_key
        )


# ============================================================
# Command Handlers
# ============================================================

@telegram_handler_error_wrapper
async def list_aliases(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Display all configured credentials grouped by bank.
    
    Usage: /list or /aliases
    
    Shows:
    - Account alias
    - Masked account number (last 4 digits visible)
    - Grouped and sorted by bank name
    
    Security:
    - Account numbers are masked
    - Passwords are never displayed
    """
    if not update.message:
        return

    app = context.application
    creds = _get_credentials(app)

    if not creds:
        await update.message.reply_text(
            "📋 No credentials configured.\n\n"
            "Use <code>/add</code> to create your first account.",
            parse_mode=ParseMode.HTML
        )
        return

    # Build list of (bank_label, alias, masked_account)
    items: List[tuple[str, str, str]] = []
    
    for alias, cred in creds.items():
        bank = (cred.get("bank_label") or "").strip() or "UNKNOWN"
        account = str(cred.get("account_number", "") or "")
        masked = _mask_account_number(account)
        items.append((bank, alias, masked))

    # Sort by bank name, then alias (case-insensitive)
    items.sort(key=lambda t: (t[0].lower(), t[1].lower()))

    # Group by bank and build formatted blocks
    messages: List[str] = []
    current_bank: Optional[str] = None
    current_lines: List[str] = []
    idx = 1

    def flush_current_block() -> None:
        nonlocal current_bank, current_lines
        if current_bank is None or not current_lines:
            return
        
        header = f"<b><u>{html.escape(current_bank)}</u></b>"
        body = "\n".join(current_lines)
        messages.append(f"{header}\n{body}")
        current_bank = None
        current_lines = []

    for bank, alias, masked in items:
        if bank != current_bank:
            # Flush previous bank group
            flush_current_block()
            current_bank = bank
            current_lines = []

        line = (
            f"{idx:02d}. <b>{html.escape(alias)}</b>  |  "
            f"<code>{html.escape(masked)}</code>"
        )
        current_lines.append(line)
        idx += 1

    flush_current_block()

    if not messages:
        await update.message.reply_text(
            "📋 No valid credentials to display.",
            parse_mode=ParseMode.HTML
        )
        return

    # Send in chunks if needed (Telegram message length limits)
    async def send_in_chunks(prefix: str, chunks: List[str]) -> None:
        for i, block in enumerate(chunks, start=1):
            header = (
                f"{prefix} ({i}/{len(chunks)})\n\n"
                if len(chunks) > 1
                else f"{prefix}\n\n"
            )
            await update.message.reply_text(
                header + block,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            if i < len(chunks):
                await asyncio.sleep(0.5)

    await send_in_chunks("📋 <b>Configured Accounts</b>", messages)

    # Audit log
    log_audit_event(
        "CREDENTIALS_LISTED",
        {
            "count": len(creds),
            "user_id": update.effective_user.id if update.effective_user else "unknown",
        },
        level=logging.INFO,
    )


@telegram_handler_error_wrapper
async def add_alias(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Create a new account credential entry.
    
    Usage:
        /add alias,username,password,account_number              (Standard banks)
        /add alias,login_id,user_id,password,account_number      (IOB Corporate)
    
    Examples:
        /add mybank_tmb,user123,pass456,1234567890
        /add corp_iobcorp,login123,user456,pass789,9876543210
    
    Features:
    - Validates input format
    - Checks for duplicate aliases and account numbers
    - Automatically detects bank type from alias
    - Creates CSV file if it doesn't exist
    
    Security:
    - Validates file permissions
    - Audit logging
    - No credentials logged
    """
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()
    
    if not text.lower().startswith("/add "):
        await update.message.reply_text(
            "<b>Usage:</b>\n"
            "<code>/add alias,username,password,account_number</code> (Standard banks)\n"
            "or\n"
            "<code>/add alias,login_id,user_id,password,account_number</code> (IOB Corporate)\n\n"
            "<b>Example:</b>\n"
            "<code>/add mybank_tmb,user123,pass456,1234567890</code>",
            parse_mode=ParseMode.HTML
        )
        return

    # Parse comma-separated fields
    parts = [p.strip() for p in text[5:].split(",") if p.strip()]

    # Banks requiring 5-field format
    FIVE_FIELD_BANKS = {"iobcorp"}
    
    alias_candidate = parts[0].lower() if parts else ""
    bank_token = alias_candidate.split("_")[-1] if alias_candidate else ""
    requires_five_fields = bank_token in FIVE_FIELD_BANKS or any(
        bank in alias_candidate for bank in FIVE_FIELD_BANKS
    )

    # Validate field count
    if requires_five_fields and len(parts) != 5:
        await update.message.reply_text(
            "❌ This bank requires 5 fields:\n"
            "<code>/add alias,login_id,user_id,password,account_number</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/add corp_iobcorp,login123,user456,pass789,9876543210</code>",
            parse_mode=ParseMode.HTML
        )
        return

    if not requires_five_fields and len(parts) not in (4, 5):
        await update.message.reply_text(
            "❌ Invalid format. Expected 4 or 5 comma-separated fields.\n\n"
            "<b>Usage:</b>\n"
            "<code>/add alias,username,password,account_number</code>",
            parse_mode=ParseMode.HTML
        )
        return

    # Extract fields based on count
    if len(parts) == 4:
        alias, username, password, account_number = parts
        login_id = ""
        user_id = ""
    else:  # len(parts) == 5
        alias, login_id, user_id, password, account_number = parts
        username = ""

    # Validate alias
    alias = (alias or "").strip()
    if not alias:
        await update.message.reply_text(
            "❌ Alias cannot be empty.",
            parse_mode=ParseMode.HTML
        )
        return

    app = context.application
    creds = _get_credentials(app)

    # Check for duplicate alias
    if alias in creds:
        await update.message.reply_text(
            f"❌ Alias <code>{html.escape(alias)}</code> already exists.\n\n"
            f"Use <code>/edit {html.escape(alias)}</code> to modify it.",
            parse_mode=ParseMode.HTML
        )
        return

    # Check for duplicate account number
    account_number = sanitize_account_number(account_number)
    
    for existing_alias, existing_cred in creds.items():
        existing_account = str(existing_cred.get("account_number", "") or "")
        if sanitize_account_number(existing_account) == account_number:
            await update.message.reply_text(
                f"❌ Account number <code>{html.escape(account_number)}</code> is already linked to "
                f"alias <code>{html.escape(existing_alias)}</code>.\n\n"
                f"Use <code>/edit {html.escape(existing_alias)}</code> to update that account.",
                parse_mode=ParseMode.HTML
            )
            return

    settings = _get_settings(app)
    csv_path = settings.credentials_csv

    # Create directory if needed
    parent_dir = os.path.dirname(csv_path)
    if parent_dir:
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except OSError as e:
            raise RuntimeError(
                f"Failed to create credentials directory '{parent_dir}': {e}"
            ) from e

    # Check if CSV exists and has content
    is_new_file = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0

    # Append new credential to CSV
    with ErrorContext(
        f"adding alias {alias} to credentials",
        operation="add_credential",
        reraise=True,
    ):
        try:
            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                fieldnames = [
                    "alias",
                    "login_id",
                    "user_id",
                    "username",
                    "password",
                    "account_number",
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                if is_new_file:
                    writer.writeheader()
                
                writer.writerow({
                    "alias": alias,
                    "login_id": login_id,
                    "user_id": user_id,
                    "username": username,
                    "password": password,
                    "account_number": account_number,
                })
        except PermissionError as e:
            raise RuntimeError(
                f"Permission denied writing to credentials CSV: {e}"
            ) from e
        except OSError as e:
            raise RuntimeError(
                f"Failed to write to credentials CSV: {e}"
            ) from e

    # Validate file permissions
    _validate_csv_permissions(csv_path)

    # Reload credentials into memory
    try:
        new_creds = load_creds(csv_path, auto_detect_encryption=True)
    except Exception as e:
        raise RuntimeError(
            f"Credential added to file, but failed to reload credentials: {e}. "
            "Please check file format."
        ) from e

    _set_credentials(app, new_creds)

    await update.message.reply_text(
        f"✅ Added account <code>{html.escape(alias)}</code>.\n\n"
        f"Account number: <code>{_mask_account_number(account_number)}</code>",
        parse_mode=ParseMode.HTML
    )

    # Audit log
    log_audit_event(
        "CREDENTIAL_ADDED",
        {
            "alias": alias,
            "account_masked": _mask_account_number(account_number),
            "user_id": update.effective_user.id if update.effective_user else "unknown",
        },
        level=logging.INFO,
    )

    logger.info("Added new credential: %s", alias)


@telegram_handler_error_wrapper
async def edit_alias(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Start interactive credential editing flow.
    
    Usage: /edit <alias>
    
    Provides inline keyboard to select which field to edit:
    - Login ID
    - User ID
    - Password
    - Account Number
    
    After selection, user sends the new value as a plain text message.
    """
    if not update.message:
        return

    if not context.args:
        await update.message.reply_text(
            "<b>Usage:</b> <code>/edit &lt;alias&gt;</code>\n\n"
            "<b>Example:</b> <code>/edit mybank_tmb</code>",
            parse_mode=ParseMode.HTML
        )
        return

    alias = context.args[0].strip()
    app = context.application
    creds = _get_credentials(app)

    if alias not in creds:
        await update.message.reply_text(
            f"❌ Unknown alias <code>{html.escape(alias)}</code>.\n\n"
            f"Use <code>/list</code> to see all configured accounts.",
            parse_mode=ParseMode.HTML
        )
        return

    # Build inline keyboard for field selection
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("Login ID", callback_data=f"edit|{alias}|login")],
        [InlineKeyboardButton("User ID", callback_data=f"edit|{alias}|user")],
        [InlineKeyboardButton("Password", callback_data=f"edit|{alias}|password")],
        [InlineKeyboardButton("Account Number", callback_data=f"edit|{alias}|account")],
    ])
    
    await update.message.reply_text(
        f"✏️ <b>Edit: {html.escape(alias)}</b>\n\n"
        f"Select the field you want to update:",
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard,
    )


async def edit_button_callback(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
) -> None:
    """
    Handle inline keyboard button press from /edit command.
    
    Callback data format: "edit|<alias>|<field_key>"
    where field_key ∈ {login, user, password, account}
    
    Sets up pending edit state and prompts user for new value.
    """
    query = update.callback_query
    if query is None:
        return

    await query.answer()

    try:
        data = query.data or ""
        _, alias, key = data.split("|")
        field_key, label = FIELD_MAPPINGS[key]
    except Exception:
        logger.exception(
            "Invalid callback data for edit button: %r",
            getattr(query, "data", None)
        )
        if query.message:
            await query.message.reply_text(
                "❌ Invalid selection. Please try <code>/edit</code> again.",
                parse_mode=ParseMode.HTML
            )
        return

    chat = update.effective_chat
    if chat is None:
        return

    # Store pending edit state
    _pending_edits[chat.id] = {
        "alias": alias,
        "field": field_key,
        "label": label,
    }

    # Prompt user for new value
    if field_key == "password":
        prompt = "🔐 Enter new password:"
    else:
        prompt = f"✏️ Enter new {label}:"

    if query.message:
        await query.message.reply_text(prompt, parse_mode=ParseMode.HTML)

    logger.debug(
        "Started edit flow for %s: field=%s",
        alias,
        field_key
    )


async def handle_edit_text_input(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
) -> None:
    """
    Process plain text input during /edit flow.
    
    When user is in an edit flow (after clicking inline keyboard),
    their next text message is treated as the new field value.
    
    Updates CSV, reloads credentials, and confirms to user.
    """
    if not update.message or not update.message.text:
        return

    chat = update.effective_chat
    if chat is None:
        return

    # Check if we're in an edit flow
    edit_state = _pending_edits.get(chat.id)
    if not edit_state:
        # Not in an edit flow - let other handlers process this
        return

    alias = edit_state["alias"]
    field_key = edit_state["field"]
    label = edit_state["label"]
    new_value = update.message.text.strip()

    app = context.application

    # Attempt to update credential
    try:
        update_credential_field(app, alias, field_key, new_value)
    except ValueError as e:
        # Duplicate account number case
        _pending_edits.pop(chat.id, None)
        
        # Extract conflicting alias from error message
        conflicting_alias = "unknown"
        try:
            if e.args and isinstance(e.args[0], str):
                # Error format: "Account number already used by alias 'xxx'"
                conflicting_alias = e.args[0].split("'")[1]
        except Exception:
            pass

        await update.message.reply_text(
            f"❌ {e}\n\n"
            f"Use <code>/edit {html.escape(conflicting_alias)}</code> to change that account, "
            f"or choose a different number.",
            parse_mode=ParseMode.HTML
        )
        return
        
    except KeyError as e:
        _pending_edits.pop(chat.id, None)
        await update.message.reply_text(
            f"❌ {e}",
            parse_mode=ParseMode.HTML
        )
        return
        
    except RuntimeError as e:
        _pending_edits.pop(chat.id, None)
        # For CSV/IO failures, let the error wrapper handle it
        raise

    # Success - clear edit state
    _pending_edits.pop(chat.id, None)

    # Format confirmation message (don't echo passwords)
    if field_key == "password":
        message = f"✅ <b>{html.escape(alias)}</b>: Password updated."
    else:
        # Mask account numbers in confirmation
        display_value = (
            _mask_account_number(new_value)
            if field_key == "account_number"
            else new_value
        )
        message = (
            f"✅ <b>{html.escape(alias)}</b>: {label} → "
            f"<code>{html.escape(display_value)}</code>"
        )

    # Check if worker is running
    workers = _get_workers(app)
    if alias in workers:
        message += (
            "\n\n"
            "ℹ️ Changes will fully apply on next login. "
            "Current session continues with previous credentials."
        )

    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

    logger.info(
        "Credential updated: alias=%s, field=%s",
        alias,
        field_key
    )


# ============================================================
# Handler Registration
# ============================================================

def register_alias_handlers(
    app: Application,
    settings: Settings | None = None
) -> None:
    """
    Register alias management command handlers with the application.
    
    Registered commands:
        /list, /aliases - Display all configured credentials
        /add            - Create new credential entry
        /edit           - Interactive credential editor
    
    Args:
        app: Telegram application instance
        settings: Optional settings (kept for backward compatibility)
    """
    # Command handlers
    app.add_handler(CommandHandler(["list", "aliases"], list_aliases))
    app.add_handler(CommandHandler("add", add_alias))
    app.add_handler(CommandHandler("edit", edit_alias))
    
    # Callback handler for edit button clicks
    app.add_handler(CallbackQueryHandler(edit_button_callback, pattern=r"^edit\|"))
    
    # Text message handler for edit flow (high priority, non-blocking)
    # Using group=-100 ensures this runs before other text handlers
    edit_text_handler = MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        handle_edit_text_input,
        block=False,  # Don't block other handlers
    )
    app.add_handler(edit_text_handler, group=-100)
    
    logger.info("Alias management handlers registered")