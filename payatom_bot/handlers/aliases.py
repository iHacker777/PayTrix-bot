from __future__ import annotations

import asyncio
import csv
import html
import logging
import os
import traceback
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
from ..creds import load_creds

logger = logging.getLogger(__name__)

# chat_id -> {"alias": ..., "field": ..., "label": ...}
pending_edit: Dict[int, Dict[str, str]] = {}

# Map short keys from the inline keyboard to CSV fields + human labels
FIELDS_MAP: Dict[str, tuple[str, str]] = {
    "login": ("login_id", "Login ID"),
    "user": ("user_id", "User ID"),
    "password": ("password", "Password"),
    "account": ("account_number", "Account number"),
}


# ─────────────────────────────
# helpers
# ─────────────────────────────
def _get_settings(app: Application) -> Settings:
    """
    Fetch Settings from app.bot_data with sanity checks so we
    fail with a clear error instead of a bare KeyError.
    """
    settings = app.bot_data.get("settings")
    if not isinstance(settings, Settings):
        raise RuntimeError(
            "Bot settings not initialised. "
            "Make sure build_application() stored a Settings instance "
            "in app.bot_data['settings']."
        )
    return settings


def _get_creds(app: Application) -> Dict[str, dict]:
    """
    Return the in-memory credentials mapping.

    Always returns a dict; if the key is missing or malformed we
    fall back to an empty dict instead of crashing.
    """
    creds = app.bot_data.get("creds_by_alias")
    if isinstance(creds, dict):
        return creds  # type: ignore[return-value]
    logger.warning("bot_data['creds_by_alias'] missing or not a dict – treating as empty.")
    return {}


def _set_creds(app: Application, creds: Dict[str, dict]) -> None:
    app.bot_data["creds_by_alias"] = creds


def _get_workers(app: Application) -> Dict[str, object]:
    """
    Registry for running workers keyed by alias.

    We never assume it exists – if not present or wrong type,
    we create a fresh dict instead of exploding.
    """
    reg = app.bot_data.get("workers")
    if not isinstance(reg, dict):
        logger.warning("bot_data['workers'] missing or not a dict – creating a new registry.")
        reg = {}
        app.bot_data["workers"] = reg
    return reg  # type: ignore[return-value]


def _format_unhandled_exception(where: str, error: BaseException) -> str:
    tb = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    header = (
        "<b>Oops! We have encountered an unhandled exception.</b>\n"
        "Please contact the administrator for more information.\n\n"
    )
    body = (
        f"<b>Location:</b> <code>{html.escape(where)}</code>\n"
        f"<b>Error:</b> <code>{html.escape(str(error))}</code>\n\n"
        "<b>Traceback:</b>\n"
        f"<pre>{html.escape(tb)}</pre>"
    )
    return header + body


async def _notify_unhandled_exception(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    where: str,
    error: BaseException,
) -> None:
    """
    Log an unhandled exception and send a detailed error + traceback
    to Telegram in a consistent, professional format.
    """
    logger.exception("Unhandled exception in %s", where, exc_info=error)

    text = _format_unhandled_exception(where, error)

    msg = update.effective_message
    if msg is not None:
        try:
            await msg.reply_text(
                text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return
        except Exception:
            logger.exception("Failed to send error reply via effective_message")

    # Fallback if we somehow don't have an effective_message
    chat = update.effective_chat
    if chat is not None:
        try:
            await context.bot.send_message(
                chat_id=chat.id,
                text=text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
        except Exception:
            logger.exception("Failed to send error message via bot.send_message")


def update_credentials_csv(
    app: Application,
    alias: str,
    field_key: str,
    new_value: str,
) -> None:
    """
    Update one field in the CSV for a given alias.
    Enforces uniqueness if field is account_number.
    Also hot-updates in-memory creds and any running worker.

    Any low-level IO error is wrapped in a RuntimeError with a
    human-readable message so the caller can show it to the user.
    """
    settings: Settings = _get_settings(app)
    csv_path = settings.credentials_csv
    new_value = (new_value or "").strip()

    rows: List[dict] = []
    found = False
    used_by: Optional[str] = None
    fieldnames: Optional[List[str]] = None

    # read all rows, prepare updates
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            rdr = csv.DictReader(f)
            fieldnames = rdr.fieldnames
            for row in rdr:
                alias_in_row = (row.get("alias") or "").strip()
                acc_in_row = (row.get("account_number") or "").strip()

                if (
                    field_key == "account_number"
                    and acc_in_row == new_value
                    and alias_in_row != alias
                ):
                    used_by = alias_in_row

                if alias_in_row == alias:
                    row[field_key] = new_value
                    found = True

                rows.append(row)
    except FileNotFoundError as e:
        logger.exception("Credentials CSV not found at %s", csv_path)
        raise RuntimeError(f"Credentials CSV not found at '{csv_path}'.") from e
    except PermissionError as e:
        logger.exception("No permission to read credentials CSV at %s", csv_path)
        raise RuntimeError(f"No permission to read credentials CSV at '{csv_path}'.") from e
    except OSError as e:
        logger.exception("OS error while reading credentials CSV at %s", csv_path)
        raise RuntimeError(f"Failed to read credentials CSV '{csv_path}': {e}") from e

    if not found:
        raise KeyError(f"Alias '{alias}' not found")

    if field_key == "account_number" and used_by:
        # Same error text as old main.py so previous tooling still matches.
        raise ValueError(f"Account number already used by alias '{used_by}'")

    if fieldnames is None:
        fieldnames = [
            "alias",
            "login_id",
            "user_id",
            "username",
            "password",
            "account_number",
        ]

    # write back
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)
    except PermissionError as e:
        logger.exception("No permission to write credentials CSV at %s", csv_path)
        raise RuntimeError(f"No permission to write credentials CSV at '{csv_path}'.") from e
    except OSError as e:
        logger.exception("OS error while writing credentials CSV at %s", csv_path)
        raise RuntimeError(f"Failed to write credentials CSV '{csv_path}': {e}") from e

    # refresh in-memory creds
    try:
        new_creds = load_creds(csv_path)
    except Exception as e:  # csv.Error etc.
        logger.exception("Failed to reload credentials from %s", csv_path)
        raise RuntimeError(f"Credentials file '{csv_path}' is corrupted or unreadable: {e}") from e

    _set_creds(app, new_creds)

    # live-update any running worker's cred snapshot (best-effort)
    workers = _get_workers(app)
    wkr = workers.get(alias)
    if wkr is not None:
        try:
            # worker.cred is a dict snapshot; keep this best-effort
            wkr.cred[field_key] = new_value  # type: ignore[attr-defined]
        except Exception:
            logger.debug(
                "Worker for alias %s does not expose a 'cred' dict; skipping live update.",
                alias,
            )


# ─────────────────────────────
# /list and /aliases
# ─────────────────────────────
async def list_aliases(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Show all configured aliases, grouped by bank, with masked account numbers.

    Fully wrapped in error handling so a broken CSV or missing
    state can’t crash the bot.
    """
    if not update.message:
        return

    try:
        app = context.application
        creds = _get_creds(app)

        if not creds:
            await update.message.reply_text("No credentials found in database.")
            return

        # Build a list of (bank_label, alias, masked_account) for sorting / grouping.
        items: List[tuple[str, str, str]] = []
        for alias, cred in creds.items():
            bank = (cred.get("bank_label") or "").strip() or "UNKNOWN"
            acc = str(cred.get("account_number", "") or "")
            digits = "".join(ch for ch in acc if ch.isdigit())
            last4 = digits[-4:] if digits else (acc[-4:] if acc else "")
            masked = f"***{last4}" if last4 else "***"
            items.append((bank, alias, masked))

        # Sort by bank name, then alias (case-insensitive).
        items.sort(key=lambda t: (t[0].lower(), t[1].lower()))

        # Group by bank and build text blocks.
        messages: List[str] = []
        current_bank: Optional[str] = None
        current_lines: List[str] = []
        idx = 1

        def flush_block() -> None:
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
                # start a new bank group
                flush_block()
                current_bank = bank
                current_lines = []

            line = (
                f"{idx:02d}. <b>{html.escape(alias)}</b>  |  "
                f"<code>{html.escape(masked)}</code>"
            )
            current_lines.append(line)
            idx += 1

        flush_block()

        if not messages:
            await update.message.reply_text("No credentials to display.")
            return

        # Telegram has message length limits; send in chunks if necessary.
        async def send_chunks(prefix: str, chunks: List[str]) -> None:
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

        await send_chunks("<b>Credentials List</b>", messages)

    except Exception as e:
        await _notify_unhandled_exception(update, context, "list_aliases", e)


# ─────────────────────────────
# /add (create new alias row)
# ─────────────────────────────
async def add_alias(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Usage:
      /add alias,username,password,account_number              (TMB/IOB/KGB/IDBI/IDFC)
      /add alias,login_id,user_id,password,account_number      (IOB corporate)
    """
    if not update.message or not update.message.text:
        return

    try:
        text = update.message.text.strip()
        if not text.lower().startswith("/add "):
            await update.message.reply_text(
                "Usage:\n"
                "  /add alias,username,password,account_number   (TMB/IOB/KGB/IDBI/IDFC)\n"
                "or\n"
                "  /add alias,login_id,user_id,password,account_number   (IOB corporate)"
            )
            return

        # Split into comma-separated fields
        parts = [p.strip() for p in text[5:].split(",") if p.strip()]

        # Banks that require the 5-field format (alias, login_id, user_id, password, account_number).
        FIVE_FIELD_BANKS = {"iobcorp"}

        alias_candidate = parts[0].lower() if parts else ""
        bank_token = alias_candidate.split("_")[-1] if alias_candidate else ""
        is_five_field_bank = bank_token in FIVE_FIELD_BANKS or any(
            b in alias_candidate for b in FIVE_FIELD_BANKS
        )

        # Enforce required field counts:
        if is_five_field_bank and len(parts) != 5:
            msg = (
                "❌ Alias appears to be for a bank that requires the 5-field format\n"
                "(alias, login_id, user_id, password, account_number).\n"
                "Please call /add with 5 comma-separated fields for this alias.\n\n"
                "Example:\n"
                "  /add test_iobcorp,loginid,userid,pass,1234567890"
            )
            await update.message.reply_text(msg)
            return

        if not is_five_field_bank and len(parts) not in (4, 5):
            await update.message.reply_text(
                "❌ Invalid format.\n"
                "Use 4 fields for TMB, IOB, KGB, IDBI, IDFC or 5 fields for IOB corporate."
            )
            return

        if len(parts) == 4:
            alias, username, password, account_number = parts
            login_id = ""
            user_id = ""
        else:  # len(parts) == 5
            alias, login_id, user_id, password, account_number = parts
            username = ""

        alias = (alias or "").strip()
        if not alias:
            await update.message.reply_text("❌ Alias cannot be empty.")
            return

        app = context.application
        creds = _get_creds(app)

        # Duplicate account number check (same message style as old main.py).
        for a, c in creds.items():
            if (c.get("account_number") or "").strip() == account_number.strip():
                msg = (
                    "❌ Account number <code>{}</code> is already linked to alias <code>{}</code>.\n"
                    "Use <code>/edit {}</code> to update that alias instead."
                ).format(html.escape(account_number), html.escape(a), html.escape(a))
                await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
                return

        if alias in creds:
            await update.message.reply_text(
                f"❌ Alias <code>{html.escape(alias)}</code> already exists.",
                parse_mode=ParseMode.HTML,
            )
            return

        settings: Settings = _get_settings(app)
        csv_path = settings.credentials_csv

        parent = os.path.dirname(csv_path)
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as e:
                raise RuntimeError(
                    f"Failed to prepare credentials file directory '{parent}': {e}"
                ) from e

        is_new = not os.path.exists(csv_path) or (os.path.getsize(csv_path) == 0)

        try:
            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "alias",
                        "login_id",
                        "user_id",
                        "username",
                        "password",
                        "account_number",
                    ],
                )
                if is_new:
                    writer.writeheader()
                writer.writerow(
                    {
                        "alias": alias,
                        "login_id": login_id,
                        "user_id": user_id,
                        "username": username,
                        "password": password,
                        "account_number": account_number,
                    }
                )
        except PermissionError as e:
            raise RuntimeError(f"No permission to write credentials CSV: {e}") from e
        except OSError as e:
            raise RuntimeError(f"Failed to write credentials CSV: {e}") from e

        # Reload creds into memory
        try:
            new_creds = load_creds(csv_path)
        except Exception as e:
            raise RuntimeError(
                f"Alias added to file, but failed to reload credentials: {e}"
            ) from e

        _set_creds(app, new_creds)

        await update.message.reply_text(
            f"✅ Added alias <code>{html.escape(alias)}</code>.",
            parse_mode=ParseMode.HTML,
        )

    except Exception as e:
        await _notify_unhandled_exception(update, context, "add_alias", e)


# ─────────────────────────────
# /edit <alias> (interactive)
# ─────────────────────────────
async def edit_alias(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Start the interactive edit flow for an alias.
    """
    if not update.message:
        return

    try:
        if not context.args:
            await update.message.reply_text("Usage: /edit <alias>")
            return

        alias = context.args[0].strip()
        app = context.application

        creds = _get_creds(app)

        if alias not in creds:
            await update.message.reply_text(f"❌ Unknown alias “{alias}”.")
            return

        kb = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("Login ID", callback_data=f"edit|{alias}|login")],
                [InlineKeyboardButton("User ID", callback_data=f"edit|{alias}|user")],
                [InlineKeyboardButton("Password", callback_data=f"edit|{alias}|password")],
                [InlineKeyboardButton("Account no.", callback_data=f"edit|{alias}|account")],
            ]
        )
        await update.message.reply_text(
            f"✏️ What do you want to change for *{alias}*?",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=kb,
        )

    except Exception as e:
        await _notify_unhandled_exception(update, context, "edit_alias", e)


async def edit_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle the inline-keyboard button click from /edit.

    Callback data: "edit|<alias>|<key>", key ∈ {login,user,password,account}
    """
    q = update.callback_query
    if q is None:
        return

    try:
        await q.answer()

        try:
            data = q.data or ""
            _, alias, key = data.split("|")
            field_key, label = FIELDS_MAP[key]
        except Exception:
            logger.exception("Invalid callback data for edit button: %r", getattr(q, "data", None))
            if q.message:
                await q.message.reply_text("❌ Invalid selection.")
            return

        chat = update.effective_chat
        if chat is None:
            return
        chat_id = chat.id

        # Store edit state keyed by chat, so any user in that chat can reply
        pending_edit[chat_id] = {"alias": alias, "field": field_key, "label": label}

        prompt = "Enter new password:" if field_key == "password" else f"Enter new {label}:"
        icon = "🔐 " if field_key == "password" else "✏️ "
        if q.message:
            await q.message.reply_text(icon + prompt)

    except Exception as e:
        await _notify_unhandled_exception(update, context, "edit_button", e)


async def handle_alias_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Intercept plain-text messages while a user is in an /edit flow,
    apply the update to CSV + in-memory creds, and confirm.
    """
    if not update.message or not update.message.text:
        return

    try:
        chat = update.effective_chat
        if chat is None:
            return
        chat_id = chat.id

        text = update.message.text.strip()

        st = pending_edit.get(chat_id)
        if not st:
            # Not in an /edit flow; let other text handlers run normally.
            return

        alias = st["alias"]
        field_key = st["field"]
        label = st["label"]

        app = context.application

        try:
            update_credentials_csv(app, alias, field_key, text)
        except ValueError as ve:  # duplicate account number case
            pending_edit.pop(chat_id, None)
            used_alias = "?"
            try:
                if ve.args and isinstance(ve.args[0], str):
                    used_alias = ve.args[0].split("'")[1]
            except Exception:
                pass
            await update.message.reply_text(
                f"❌ {ve}\nUse `/edit {used_alias}` to change that alias, or choose another number.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return
        except KeyError as e:
            pending_edit.pop(chat_id, None)
            await update.message.reply_text(f"❌ {e}")
            return
        except RuntimeError as e:
            pending_edit.pop(chat_id, None)
            # Treat CSV / IO failures as "serious" and include full traceback
            await _notify_unhandled_exception(
                update,
                context,
                "handle_alias_text/update_credentials_csv",
                e,
            )
            return

        # If we reach here, update was successful
        pending_edit.pop(chat_id, None)

        # Don’t echo passwords back
        if field_key == "password":
            msg = f"✅ *{alias}*: Password updated."
        else:
            shown = (
                text
                if field_key != "account_number"
                else (len(text[:-4]) * "•" + text[-4:])
            )
            msg = f"✅ *{alias}*: {label} → `{shown}`"

        workers = _get_workers(app)
        tail = ""
        if alias in workers:
            tail = "\nℹ️ Change will fully apply on next login. Current session keeps running."

        await update.message.reply_text(msg + tail, parse_mode=ParseMode.MARKDOWN)

    except Exception as e:
        await _notify_unhandled_exception(update, context, "handle_alias_text", e)


def register_alias_handlers(app: Application, settings: Settings | None = None) -> None:
    """
    Wire up alias-related commands and flows.

    Exposed commands:
      /list, /aliases  – show all configured aliases
      /add             – add a new alias row to the credentials CSV
      /edit <alias>    – interactively edit login_id / user_id / password / account_number

    `settings` is accepted but not used, so this works whether
    app.py calls register_alias_handlers(app) or
    register_alias_handlers(app, settings).
    """
    app.add_handler(CommandHandler(["list", "aliases"], list_aliases))
    app.add_handler(CommandHandler("add", add_alias))
    app.add_handler(CommandHandler("edit", edit_alias))
    app.add_handler(CallbackQueryHandler(edit_button, pattern=r"^edit\|"))

    # Plain text handler: run in a high-priority group and DO NOT block other handlers.
    # This ensures the /edit reply flow always works even if you have other text handlers.
    alias_text_handler = MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        handle_alias_text,
        block=False,
    )
    # Use a very early group so we see messages before OTP/CAPTCHA handlers, etc.
    app.add_handler(alias_text_handler, group=-100)
