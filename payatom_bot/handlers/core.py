from __future__ import annotations
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from ..config import Settings

logger = logging.getLogger(__name__)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("This is the official RPA Bot to scrape statements from bank accounts\nBot is alive.\nUse /help for commands.")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Available: /start")

def register_core_handlers(app: Application, settings: Settings) -> None:
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
