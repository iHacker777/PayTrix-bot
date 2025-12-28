# app.py (UPDATED WITH BALANCE MONITORING)
from __future__ import annotations
import asyncio
import logging

from telegram.ext import ApplicationBuilder, Application

from .cipherbank_client import initialize_cipherbank_client, shutdown_cipherbank_client
from .config import load_settings
from .handlers.core import register_core_handlers
from .handlers.aliases import register_alias_handlers
from .handlers.sessions import register_session_handlers
from .handlers.reports import register_report_handlers
from .messaging import Messenger
from .creds import load_creds
from .handlers.captcha import register_captcha_handlers
from .balance_monitor import BalanceMonitor

logger = logging.getLogger(__name__)

def build_application() -> Application:
    settings = load_settings()
    app = ApplicationBuilder().token(settings.telegram_token).build()

    # Register handlers
    register_core_handlers(app, settings)
    register_alias_handlers(app)
    register_session_handlers(app, settings)
    register_report_handlers(app, settings)
    register_captcha_handlers(app)

    # Attach shared objects
    loop = asyncio.get_event_loop()
    app.bot_data["messenger"] = Messenger(bot=app.bot, chat_id=settings.telegram_chat_id, loop=loop, debug=True)
    app.bot_data["settings"] = settings
    app.bot_data["creds_by_alias"] = load_creds(settings.credentials_csv)
    app.bot_data["workers"] = {}
    
    # Initialize balance monitor
    balance_monitor = BalanceMonitor(
        bot=app.bot,
        alert_group_ids=settings.alert_group_ids,
        check_interval=settings.balance_check_interval,
    )
    app.bot_data["balance_monitor"] = balance_monitor
    
    logger.info("Application built successfully")
    return app

async def post_init(application: Application) -> None:
    """Called after the application starts."""
    logger.info("Starting post-initialization tasks...")
    
    # Start balance monitor
    balance_monitor = application.bot_data.get("balance_monitor")
    if balance_monitor:
        workers_registry = application.bot_data.get("workers", {})
        await balance_monitor.start(workers_registry)
        logger.info("✅ Balance monitor started")
    else:
        logger.warning("⚠️ Balance monitor not initialized")

    # Initialize CipherBank client
    settings = application.bot_data.get("settings")
    messenger = application.bot_data.get("messenger")
    
    if settings and settings.cipherbank_url and settings.cipherbank_username:
        try:
            logger.info("Initializing CipherBank client...")
            cipherbank_client = initialize_cipherbank_client(
                base_url=settings.cipherbank_url,
                username=settings.cipherbank_username,
                password=settings.cipherbank_password,
                messenger=messenger,
            )
            application.bot_data["cipherbank_client"] = cipherbank_client
            logger.info("✅ CipherBank client initialized and started")
        except Exception as e:
            logger.error("❌ Failed to initialize CipherBank client: %s", e)
            if messenger:
                messenger.send_event(
                    f"❌ <b>CipherBank Initialization Failed</b>\n\n"
                    f"Error: {type(e).__name__}: {str(e)}\n\n"
                    f"CipherBank uploads will be skipped.\n"
                    f"Check CIPHERBANK_* settings in .env file.",
                    kind="ERROR"
                )
    else:
        logger.info("ℹ️ CipherBank integration disabled (missing configuration)")
    #  END OF ADDED SECTION

async def post_shutdown(application: Application) -> None:
    """Called before the application shuts down."""
    logger.info("Starting shutdown tasks...")
    
    # Stop balance monitor
    balance_monitor = application.bot_data.get("balance_monitor")
    if balance_monitor:
        await balance_monitor.stop()
        logger.info("✅ Balance monitor stopped")

    # Shutdown CipherBank client
    try:
        shutdown_cipherbank_client()
        logger.info("✅ CipherBank client stopped")
    except Exception as e:
        logger.error("Error stopping CipherBank client: %s", e)
    #  END OF ADDED SECTION

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("🚀 Starting Autobot V2...")
    
    app = build_application()
    
    # Register lifecycle callbacks
    app.post_init = post_init
    app.post_shutdown = post_shutdown
    
    logger.info("✅ Autobot V2 ready - starting polling...")
    app.run_polling(allowed_updates=["message", "callback_query"])

if __name__ == "__main__":
    main()
