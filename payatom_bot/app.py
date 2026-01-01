# payatom_bot/app.py
"""
PayTrix Bot - Enterprise Banking Automation System

Main application entry point with:
- Comprehensive logging configuration
- CipherBank integration
- Balance monitoring
- Telegram bot handlers
- Graceful startup/shutdown
- Audit trail
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys

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
from .logging_config import (
    configure_logging,
    log_audit_event,
    cleanup_old_logs,
    get_audit_logger,
)

# Logger will be configured in main(), so we get it here
logger = logging.getLogger(__name__)


def build_application() -> Application:
    """
    Build and configure the Telegram bot application.
    
    Sets up:
    - Bot with token
    - All command handlers
    - Messenger for notifications
    - Credentials from CSV
    - Worker registry
    - Balance monitor
    
    Returns:
        Configured Application instance
    """
    logger.info("Building application...")
    
    try:
        settings = load_settings()
        logger.debug("Settings loaded successfully")
        
        # Build bot application
        app = ApplicationBuilder().token(settings.telegram_token).build()
        logger.debug("Telegram bot application created")

        # Register handlers
        logger.debug("Registering command handlers...")
        register_core_handlers(app, settings)
        register_alias_handlers(app)
        register_session_handlers(app, settings)
        register_report_handlers(app, settings)
        register_captcha_handlers(app)
        logger.info("All command handlers registered")

        # Attach shared objects
        loop = asyncio.get_event_loop()
        
        logger.debug("Initializing Messenger...")
        app.bot_data["messenger"] = Messenger(
            bot=app.bot,
            chat_id=settings.telegram_chat_id,
            loop=loop,
            debug=True
        )
        
        app.bot_data["settings"] = settings
        
        # Load credentials
        logger.debug("Loading credentials from CSV...")
        try:
            creds = load_creds(settings.credentials_csv)
            app.bot_data["creds_by_alias"] = creds
            logger.info("Loaded %d credential(s) from %s", len(creds), settings.credentials_csv)
            
            # Audit log for credentials loaded
            log_audit_event('CREDENTIALS_LOADED', {
                'count': len(creds),
                'file': settings.credentials_csv,
            })
            
        except Exception as e:
            logger.error("Failed to load credentials: %s", e, exc_info=True)
            raise
        
        # Initialize worker registry
        app.bot_data["workers"] = {}
        
        # Initialize balance monitor
        logger.debug("Initializing balance monitor...")
        balance_monitor = BalanceMonitor(
            bot=app.bot,
            alert_group_ids=settings.alert_group_ids,
            check_interval=settings.balance_check_interval,
        )
        app.bot_data["balance_monitor"] = balance_monitor
        logger.info(
            "Balance monitor configured: %d alert group(s), check interval: %ds",
            len(settings.alert_group_ids),
            settings.balance_check_interval
        )
        
        logger.info("✅ Application built successfully")
        return app
        
    except Exception as e:
        logger.critical("Failed to build application: %s", e, exc_info=True)
        raise


async def post_init(application: Application) -> None:
    """
    Post-initialization tasks after bot starts.
    
    Called by python-telegram-bot after the application is ready.
    Sets up:
    - Balance monitor
    - CipherBank client
    - Audit logging
    """
    logger.info("=" * 60)
    logger.info("Starting post-initialization tasks...")
    logger.info("=" * 60)
    
    # Audit log for system start
    log_audit_event('SYSTEM_START', {
        'component': 'PayTrix Bot',
        'version': '2.0',
        'pid': os.getpid(),
    })
    
    # Start balance monitor
    balance_monitor = application.bot_data.get("balance_monitor")
    if balance_monitor:
        try:
            workers_registry = application.bot_data.get("workers", {})
            await balance_monitor.start(workers_registry)
            
            stats = balance_monitor.get_status()
            logger.info(
                "✅ Balance monitor started: %d alert groups, %ds interval",
                stats['alert_groups'],
                stats['check_interval']
            )
            
            # Audit log
            log_audit_event('BALANCE_MONITOR_START', {
                'alert_groups': stats['alert_groups'],
                'interval': stats['check_interval'],
            })
            
        except Exception as e:
            logger.error("Failed to start balance monitor: %s", e, exc_info=True)
    else:
        logger.warning("⚠️ Balance monitor not initialized")

    # Initialize CipherBank client
    settings = application.bot_data.get("settings")
    messenger = application.bot_data.get("messenger")
    
    if (settings and 
        settings.cipherbank_auth_url and 
        settings.cipherbank_upload_url and 
        settings.cipherbank_username and 
        settings.cipherbank_password):
        try:
            logger.info("Initializing CipherBank client...")
            logger.debug(
                "CipherBank config: auth=%s, upload=%s, user=%s",
                settings.cipherbank_auth_url,
                settings.cipherbank_upload_url,
                settings.cipherbank_username
            )
            
            cipherbank_client = initialize_cipherbank_client(
                auth_base_url=settings.cipherbank_auth_url,
                upload_base_url=settings.cipherbank_upload_url,
                username=settings.cipherbank_username,
                password=settings.cipherbank_password,
                messenger=messenger,
            )
            application.bot_data["cipherbank_client"] = cipherbank_client
            
            logger.info("✅ CipherBank client initialized and started")
            
            # Audit log
            log_audit_event('CIPHERBANK_INIT', {
                'auth_url': settings.cipherbank_auth_url,
                'upload_url': settings.cipherbank_upload_url,
                'username': settings.cipherbank_username,
            })
            
        except Exception as e:
            logger.error("❌ Failed to initialize CipherBank client: %s", e, exc_info=True)
            
            if messenger:
                messenger.send_event(
                    f"❌ <b>CipherBank Initialization Failed</b>\n\n"
                    f"Error: {type(e).__name__}: {str(e)}\n\n"
                    f"CipherBank uploads will be skipped.\n"
                    f"Check CIPHERBANK_AUTH_URL, CIPHERBANK_UPLOAD_URL, and credentials in .env file.",
                    kind="ERROR"
                )
    else:
        logger.info("ℹ️ CipherBank integration disabled (missing configuration)")
        logger.debug(
            "CipherBank config check: auth_url=%s, upload_url=%s, username=%s, password=%s",
            bool(settings.cipherbank_auth_url) if settings else False,
            bool(settings.cipherbank_upload_url) if settings else False,
            bool(settings.cipherbank_username) if settings else False,
            bool(settings.cipherbank_password) if settings else False,
        )
    
    logger.info("=" * 60)
    logger.info("✅ Post-initialization complete - bot is ready")
    logger.info("=" * 60)


async def post_shutdown(application: Application) -> None:
    """
    Pre-shutdown cleanup tasks.
    
    Called by python-telegram-bot before application shutdown.
    Cleans up:
    - Balance monitor
    - CipherBank client
    - Old log files
    - Audit trail
    """
    logger.info("=" * 60)
    logger.info("Starting shutdown tasks...")
    logger.info("=" * 60)
    
    # Audit log for system stop
    log_audit_event('SYSTEM_STOP', {
        'component': 'PayTrix Bot',
        'pid': os.getpid(),
    })
    
    # Stop balance monitor
    balance_monitor = application.bot_data.get("balance_monitor")
    if balance_monitor:
        try:
            await balance_monitor.stop()
            logger.info("✅ Balance monitor stopped")
            
            # Log final stats
            stats = balance_monitor.get_status()
            logger.info(
                "Balance monitor stats: sent=%d, failed=%d",
                stats.get('total_alerts', 0),
                0  # Could add failure tracking to balance_monitor
            )
            
        except Exception as e:
            logger.error("Error stopping balance monitor: %s", e, exc_info=True)

    # Shutdown CipherBank client
    try:
        shutdown_cipherbank_client()
        logger.info("✅ CipherBank client stopped")
    except Exception as e:
        logger.error("Error stopping CipherBank client: %s", e, exc_info=True)
    
    # Cleanup old logs
    try:
        logger.info("Cleaning up old log files...")
        cleanup_old_logs()
        logger.info("✅ Old log files cleaned up")
    except Exception as e:
        logger.warning("Error cleaning up old logs: %s", e)
    
    logger.info("=" * 60)
    logger.info("✅ Shutdown complete")
    logger.info("=" * 60)


def main() -> None:
    """
    Main entry point for PayTrix Bot.
    
    Configures comprehensive logging, builds the application,
    and starts the Telegram bot.
    """
    # ========================================
    # STEP 1: CONFIGURE LOGGING (FIRST!)
    # ========================================
    
    # Determine environment from env var
    environment = os.getenv('ENVIRONMENT', 'production').lower()
    
    # Validate environment
    if environment not in ['development', 'staging', 'production']:
        print(f"Warning: Invalid ENVIRONMENT '{environment}', defaulting to 'production'")
        environment = 'production'
    
    # Determine if console output should be colored
    colored_console = (
        environment == 'development' and 
        hasattr(sys.stdout, 'isatty') and 
        sys.stdout.isatty()
    )
    
    # Get log directory from env or use default
    log_dir = os.getenv('LOG_DIR', 'logs')
    
    # Check if structured logging is enabled
    structured_logs = os.getenv('STRUCTURED_LOGS', '').lower() == 'true'
    
    # Check if PII masking is enabled (default: true)
    enable_pii_masking = os.getenv('ENABLE_PII_MASKING', 'true').lower() != 'false'
    
    try:
        # Configure comprehensive logging
        configure_logging(
            environment=environment,
            log_dir=log_dir,
            console_output=True,
            colored_console=colored_console,
            structured_logs=structured_logs,
            enable_pii_masking=enable_pii_masking,
        )
        
        # Now we can use logger
        logger.info("=" * 60)
        logger.info("🚀 PayTrix Bot - Starting")
        logger.info("=" * 60)
        logger.info("Environment: %s", environment)
        logger.info("Log Directory: %s", log_dir)
        logger.info("Structured Logs: %s", structured_logs)
        logger.info("PII Masking: %s", enable_pii_masking)
        logger.info("Console Colors: %s", colored_console)
        logger.info("=" * 60)
        
    except Exception as e:
        # If logging setup fails, fall back to basic config and continue
        print(f"WARNING: Failed to configure advanced logging: {e}", file=sys.stderr)
        print("Falling back to basic logging configuration", file=sys.stderr)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger.error("Advanced logging configuration failed: %s", e, exc_info=True)
    
    # ========================================
    # STEP 2: BUILD APPLICATION
    # ========================================
    
    try:
        logger.info("Building application...")
        app = build_application()
        
        # Register lifecycle callbacks
        app.post_init = post_init
        app.post_shutdown = post_shutdown
        
        logger.info("✅ Application built successfully")
        
    except Exception as e:
        logger.critical(
            "Failed to build application: %s",
            e,
            exc_info=True
        )
        logger.critical("PayTrix Bot cannot start - exiting")
        
        # Audit log for startup failure
        try:
            log_audit_event('SYSTEM_START_FAILED', {
                'error': str(e),
                'error_type': type(e).__name__,
            })
        except Exception:
            pass
        
        sys.exit(1)
    
    # ========================================
    # STEP 3: START BOT
    # ========================================
    
    try:
        logger.info("=" * 60)
        logger.info("✅ PayTrix Bot ready - starting polling...")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 60)
        
        # Start polling
        app.run_polling(allowed_updates=["message", "callback_query"])
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received - shutting down gracefully...")
        
    except Exception as e:
        logger.critical(
            "Unhandled exception in main loop: %s",
            e,
            exc_info=True
        )
        
        # Audit log for runtime failure
        try:
            log_audit_event('SYSTEM_RUNTIME_ERROR', {
                'error': str(e),
                'error_type': type(e).__name__,
            })
        except Exception:
            pass
        
        sys.exit(1)
        
    finally:
        logger.info("PayTrix Bot shutdown complete")
        logger.info("=" * 60)


if __name__ == "__main__":
    main()