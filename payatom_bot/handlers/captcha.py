# payatom_bot/handlers/captcha.py
from __future__ import annotations
import re
from typing import Dict
from telegram import Update
from telegram.ext import ContextTypes, MessageHandler, filters

def _registry(context: ContextTypes.DEFAULT_TYPE) -> Dict[str, object]:
    return context.application.bot_data.setdefault("workers", {})

async def otp_or_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.effective_message.text or "").strip()
    if not text:
        return

    # Prefer a 6-digit numeric (OTP); else accept compact A–Z/0–9 4–8 chars (CAPTCHA)
    m = re.search(r"\b(\d{6})\b", text)
    if m:
        code, as_otp = m.group(1), True
    else:
        t = text.replace(" ", "")
        if not re.fullmatch(r"[A-Za-z0-9]{4,8}", t):
            return
        code, as_otp = t.upper(), False

    applied = []
    for alias, w in list(_registry(context).items()):
        try:
            if as_otp and hasattr(w, "otp_code"):
                setattr(w, "otp_code", code)
                applied.append(f"{alias}: OTP")
            if hasattr(w, "captcha_code"):
                setattr(w, "captcha_code", code)
                applied.append(f"{alias}: CAPTCHA")
        except Exception:
            pass

    if applied:
        await update.effective_message.reply_text("✔️ Applied to " + ", ".join(applied))

def register_captcha_handlers(app) -> None:
    # Capture in any chat; if you want to restrict, filter by chat_id here.
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, otp_or_captcha))
