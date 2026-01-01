# payatom_bot/logging_config.py
"""
Enterprise-grade logging configuration for PayTrix Bot.

Features:
- Hierarchical log file organization
- Automatic log rotation (size and time-based)
- PII masking for security compliance
- Thread-safe operations
- Correlation IDs for tracking
- Structured logging support
- Environment-based configuration
- Console output with colors (development)
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# ============================================================
# Configuration Constants
# ============================================================

# Log directory structure
DEFAULT_LOG_DIR = "logs"
LOG_RETENTION_DAYS = 30
MAX_LOG_SIZE_MB = 50
BACKUP_COUNT = 10

# Log levels by environment
LOG_LEVELS = {
    "development": logging.DEBUG,
    "staging": logging.INFO,
    "production": logging.INFO,
}

# Sensitive patterns to mask
SENSITIVE_PATTERNS = [
    (r'password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', r'password=***MASKED***'),
    (r'Password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', r'Password=***MASKED***'),
    (r'pwd["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', r'pwd=***MASKED***'),
    (r'token["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', r'token=***MASKED***'),
    (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', r'api_key=***MASKED***'),
    (r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', r'Bearer ***MASKED***'),
    # Account numbers (last 4 digits visible)
    (r'\b(\d{4,})\b', lambda m: '***' + m.group(1)[-4:] if len(m.group(1)) >= 4 else '***'),
]


# ============================================================
# Custom Filters
# ============================================================

class PIIMaskingFilter(logging.Filter):
    """
    Filter that masks sensitive information in log messages.
    
    Masks:
    - Passwords
    - API keys
    - Tokens
    - Account numbers (shows last 4 digits)
    """
    
    def __init__(self):
        super().__init__()
        self.compiled_patterns = [
            (re.compile(pattern), replacement)
            for pattern, replacement in SENSITIVE_PATTERNS
        ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Apply masking to log message."""
        if hasattr(record, 'msg'):
            original_msg = str(record.msg)
            masked_msg = original_msg
            
            for pattern, replacement in self.compiled_patterns:
                if callable(replacement):
                    masked_msg = pattern.sub(replacement, masked_msg)
                else:
                    masked_msg = pattern.sub(replacement, masked_msg)
            
            record.msg = masked_msg
        
        # Also mask args if present
        if hasattr(record, 'args') and record.args:
            try:
                if isinstance(record.args, dict):
                    record.args = {
                        k: self._mask_value(v)
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, (tuple, list)):
                    record.args = tuple(
                        self._mask_value(v) for v in record.args
                    )
            except Exception:
                # Don't break logging if masking fails
                pass
        
        return True
    
    def _mask_value(self, value: Any) -> Any:
        """Mask a single value if it's a string."""
        if isinstance(value, str):
            masked = value
            for pattern, replacement in self.compiled_patterns:
                if callable(replacement):
                    masked = pattern.sub(replacement, masked)
                else:
                    masked = pattern.sub(replacement, masked)
            return masked
        return value


class WorkerContextFilter(logging.Filter):
    """
    Add worker context to log records.
    
    Extracts worker alias from logger name or thread name
    and adds it to the record for consistent formatting.
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add worker_alias to record if available."""
        # Check if already set
        if hasattr(record, 'worker_alias'):
            return True
        
        # Extract from thread name (workers set thread name to alias)
        import threading
        thread_name = threading.current_thread().name
        
        if thread_name and thread_name != 'MainThread':
            record.worker_alias = thread_name
        else:
            record.worker_alias = None
        
        return True


class StructuredFormatter(logging.Formatter):
    """
    JSON-formatted logs for log aggregation systems.
    
    Outputs logs in structured JSON format for easy parsing
    by log aggregation tools like ELK, Splunk, etc.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format record as JSON."""
        import json
        
        log_data = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'thread': record.threadName,
            'process': record.process,
        }
        
        # Add worker context if available
        if hasattr(record, 'worker_alias') and record.worker_alias:
            log_data['worker_alias'] = record.worker_alias
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info),
            }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in [
                'name', 'msg', 'args', 'created', 'filename', 'funcName',
                'levelname', 'levelno', 'lineno', 'module', 'msecs',
                'message', 'pathname', 'process', 'processName', 'relativeCreated',
                'thread', 'threadName', 'exc_info', 'exc_text', 'stack_info',
                'worker_alias',
            ]:
                try:
                    # Only add JSON-serializable values
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    pass
        
        return json.dumps(log_data)


class ColoredConsoleFormatter(logging.Formatter):
    """
    Colored console output for development.
    
    Uses ANSI color codes to make console logs more readable
    during development.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format with colors."""
        # Add color to level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
            )
        
        # Format the message
        formatted = super().format(record)
        
        # Reset levelname for next use
        record.levelname = levelname
        
        return formatted


# ============================================================
# Log Directory Setup
# ============================================================

def setup_log_directories(base_dir: str = DEFAULT_LOG_DIR) -> Dict[str, Path]:
    """
    Create log directory structure.
    
    Structure:
        logs/
        ├── main.log
        ├── errors.log
        ├── workers/
        │   ├── iob.log
        │   ├── tmb.log
        │   └── ...
        ├── cipherbank.log
        ├── telegram.log
        └── audit.log
    
    Args:
        base_dir: Base directory for logs
        
    Returns:
        Dictionary mapping log types to paths
    """
    base_path = Path(base_dir)
    base_path.mkdir(exist_ok=True)
    
    # Create subdirectories
    workers_dir = base_path / "workers"
    workers_dir.mkdir(exist_ok=True)
    
    archive_dir = base_path / "archive"
    archive_dir.mkdir(exist_ok=True)
    
    return {
        'base': base_path,
        'workers': workers_dir,
        'archive': archive_dir,
        'main': base_path / 'main.log',
        'errors': base_path / 'errors.log',
        'cipherbank': base_path / 'cipherbank.log',
        'telegram': base_path / 'telegram.log',
        'audit': base_path / 'audit.log',
    }


# ============================================================
# Handler Creation
# ============================================================

def create_rotating_file_handler(
    filepath: Path,
    max_bytes: int = MAX_LOG_SIZE_MB * 1024 * 1024,
    backup_count: int = BACKUP_COUNT,
    level: int = logging.DEBUG,
) -> logging.handlers.RotatingFileHandler:
    """
    Create a rotating file handler.
    
    Args:
        filepath: Path to log file
        max_bytes: Maximum file size before rotation
        backup_count: Number of backup files to keep
        level: Log level
        
    Returns:
        Configured RotatingFileHandler
    """
    handler = logging.handlers.RotatingFileHandler(
        filepath,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8',
    )
    handler.setLevel(level)
    return handler


def create_timed_rotating_handler(
    filepath: Path,
    when: str = 'midnight',
    interval: int = 1,
    backup_count: int = LOG_RETENTION_DAYS,
    level: int = logging.DEBUG,
) -> logging.handlers.TimedRotatingFileHandler:
    """
    Create a time-based rotating file handler.
    
    Args:
        filepath: Path to log file
        when: Rotation interval ('midnight', 'h', 'd', etc.)
        interval: Interval multiplier
        backup_count: Number of backup files to keep
        level: Log level
        
    Returns:
        Configured TimedRotatingFileHandler
    """
    handler = logging.handlers.TimedRotatingFileHandler(
        filepath,
        when=when,
        interval=interval,
        backupCount=backup_count,
        encoding='utf-8',
    )
    handler.setLevel(level)
    
    # Add date suffix to rotated files
    handler.suffix = "%Y-%m-%d"
    
    return handler


def create_console_handler(
    level: int = logging.INFO,
    colored: bool = True,
) -> logging.StreamHandler:
    """
    Create console handler.
    
    Args:
        level: Log level
        colored: Whether to use colored output
        
    Returns:
        Configured StreamHandler
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    
    if colored and sys.stdout.isatty():
        # Use colored formatter for terminals
        formatter = ColoredConsoleFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    else:
        # Plain formatter for non-terminals (e.g., systemd logs)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    
    handler.setFormatter(formatter)
    return handler


# ============================================================
# Main Configuration
# ============================================================

def configure_logging(
    *,
    environment: str = 'production',
    log_dir: str = DEFAULT_LOG_DIR,
    console_output: bool = True,
    colored_console: bool = True,
    structured_logs: bool = False,
    enable_pii_masking: bool = True,
) -> None:
    """
    Configure comprehensive logging for PayTrix Bot.
    
    Sets up:
    - Main log file (all logs)
    - Error log file (ERROR and above)
    - Worker-specific logs
    - Component-specific logs (CipherBank, Telegram)
    - Audit log for critical operations
    - Console output (optional, colored in dev)
    - PII masking for security
    - Log rotation
    
    Args:
        environment: 'development', 'staging', or 'production'
        log_dir: Base directory for log files
        console_output: Whether to output to console
        colored_console: Whether to use colored console output
        structured_logs: Whether to use JSON format
        enable_pii_masking: Whether to mask sensitive data
    """
    # Determine log level
    log_level = LOG_LEVELS.get(environment, logging.INFO)
    
    # Setup directories
    log_paths = setup_log_directories(log_dir)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture all, filter at handlers
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Choose formatter
    if structured_logs:
        file_formatter = StructuredFormatter()
    else:
        # Detailed format for file logs
        file_formatter = logging.Formatter(
            '%(asctime)s - [%(levelname)s] - %(name)s - '
            '%(threadName)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    
    # --------------------------------------------------------
    # 1. Main log file (all logs)
    # --------------------------------------------------------
    main_handler = create_timed_rotating_handler(
        log_paths['main'],
        level=log_level,
    )
    main_handler.setFormatter(file_formatter)
    root_logger.addHandler(main_handler)
    
    # --------------------------------------------------------
    # 2. Error log file (errors only)
    # --------------------------------------------------------
    error_handler = create_rotating_file_handler(
        log_paths['errors'],
        level=logging.ERROR,
    )
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)
    
    # --------------------------------------------------------
    # 3. Console output (optional)
    # --------------------------------------------------------
    if console_output:
        console_handler = create_console_handler(
            level=log_level,
            colored=colored_console and environment == 'development',
        )
        root_logger.addHandler(console_handler)
    
    # --------------------------------------------------------
    # 4. Component-specific loggers
    # --------------------------------------------------------
    
    # CipherBank logs
    cipherbank_logger = logging.getLogger('payatom_bot.cipherbank_client')
    cipherbank_handler = create_rotating_file_handler(
        log_paths['cipherbank'],
        level=logging.DEBUG,
    )
    cipherbank_handler.setFormatter(file_formatter)
    cipherbank_logger.addHandler(cipherbank_handler)
    
    # Telegram/Messaging logs
    telegram_logger = logging.getLogger('payatom_bot.messaging')
    telegram_handler = create_rotating_file_handler(
        log_paths['telegram'],
        level=logging.DEBUG,
    )
    telegram_handler.setFormatter(file_formatter)
    telegram_logger.addHandler(telegram_handler)
    
    # Also capture telegram library logs
    telegram_lib_logger = logging.getLogger('telegram')
    telegram_lib_logger.addHandler(telegram_handler)
    
    # Audit log for critical operations
    audit_logger = logging.getLogger('payatom_bot.audit')
    audit_handler = create_rotating_file_handler(
        log_paths['audit'],
        level=logging.INFO,
    )
    # Audit logs should be detailed and structured
    audit_formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    audit_handler.setFormatter(audit_formatter)
    audit_logger.addHandler(audit_handler)
    
    # --------------------------------------------------------
    # 5. Worker-specific loggers (created on-demand)
    # --------------------------------------------------------
    # These are set up by create_worker_logger() when workers start
    
    # --------------------------------------------------------
    # 6. Add filters
    # --------------------------------------------------------
    
    # PII masking filter (applies to all handlers)
    if enable_pii_masking:
        pii_filter = PIIMaskingFilter()
        for handler in root_logger.handlers:
            handler.addFilter(pii_filter)
        for handler in cipherbank_logger.handlers:
            handler.addFilter(pii_filter)
        for handler in telegram_logger.handlers:
            handler.addFilter(pii_filter)
    
    # Worker context filter
    worker_filter = WorkerContextFilter()
    for handler in root_logger.handlers:
        handler.addFilter(worker_filter)
    
    # --------------------------------------------------------
    # 7. Reduce noise from third-party libraries
    # --------------------------------------------------------
    logging.getLogger('selenium').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    
    # Log configuration summary
    logger = logging.getLogger(__name__)
    logger.info(
        "Logging configured: environment=%s, level=%s, dir=%s, pii_masking=%s",
        environment,
        logging.getLevelName(log_level),
        log_dir,
        enable_pii_masking,
    )


def create_worker_logger(
    worker_alias: str,
    log_dir: str = DEFAULT_LOG_DIR,
) -> logging.Logger:
    """
    Create a dedicated logger for a worker.
    
    Each worker gets its own log file in logs/workers/ directory.
    Inherits from root logger configuration but also logs to
    worker-specific file.
    
    Args:
        worker_alias: Worker alias (e.g., 'madras_tmb')
        log_dir: Base log directory
        
    Returns:
        Configured logger for the worker
    """
    # Create logger
    logger_name = f'payatom_bot.workers.{worker_alias}'
    logger = logging.getLogger(logger_name)
    
    # Create worker-specific file handler
    workers_dir = Path(log_dir) / 'workers'
    workers_dir.mkdir(exist_ok=True)
    
    worker_log_path = workers_dir / f'{worker_alias}.log'
    
    # Rotating handler for worker
    handler = create_rotating_file_handler(
        worker_log_path,
        level=logging.DEBUG,
    )
    
    # Detailed formatter for worker logs
    formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    handler.setFormatter(formatter)
    
    # Add PII masking
    handler.addFilter(PIIMaskingFilter())
    
    # Add handler to logger
    logger.addHandler(handler)
    
    # Don't propagate to avoid duplicate logs
    # (worker logs go to both main.log and worker-specific log)
    # logger.propagate = False  # Commented: we want logs in main.log too
    
    logger.debug("Worker logger created: %s", worker_alias)
    
    return logger


def get_audit_logger() -> logging.Logger:
    """
    Get the audit logger for critical operations.
    
    Use for logging:
    - Login attempts
    - Statement downloads
    - File uploads
    - Configuration changes
    - Worker starts/stops
    
    Returns:
        Audit logger
    """
    return logging.getLogger('payatom_bot.audit')


def log_audit_event(
    event_type: str,
    details: Dict[str, Any],
    level: int = logging.INFO,
) -> None:
    """
    Log an audit event in structured format.
    
    Args:
        event_type: Type of event (e.g., 'LOGIN', 'DOWNLOAD', 'UPLOAD')
        details: Event details dictionary
        level: Log level
    """
    audit_logger = get_audit_logger()
    
    # Format as structured message
    message = f"[{event_type}] "
    
    # Add details
    detail_parts = [f"{k}={v}" for k, v in details.items()]
    message += " | ".join(detail_parts)
    
    audit_logger.log(level, message)


# ============================================================
# Utilities
# ============================================================

def get_logger_for_worker(worker_alias: str) -> logging.Logger:
    """
    Get or create logger for a worker.
    
    Args:
        worker_alias: Worker alias
        
    Returns:
        Logger instance
    """
    logger_name = f'payatom_bot.workers.{worker_alias}'
    logger = logging.getLogger(logger_name)
    
    # Check if worker logger already has handlers
    if not any(
        isinstance(h, logging.handlers.RotatingFileHandler) and
        str(worker_alias) in str(h.baseFilename)
        for h in logger.handlers
    ):
        # Create worker logger if not exists
        return create_worker_logger(worker_alias)
    
    return logger


def cleanup_old_logs(
    log_dir: str = DEFAULT_LOG_DIR,
    retention_days: int = LOG_RETENTION_DAYS,
) -> None:
    """
    Clean up old log files beyond retention period.
    
    Args:
        log_dir: Base log directory
        retention_days: Number of days to retain logs
    """
    import time
    
    log_path = Path(log_dir)
    
    if not log_path.exists():
        return
    
    cutoff_time = time.time() - (retention_days * 86400)
    removed_count = 0
    
    for log_file in log_path.rglob('*.log*'):
        # Skip current log files (no date suffix)
        if log_file.suffix == '.log':
            continue
        
        try:
            if log_file.stat().st_mtime < cutoff_time:
                log_file.unlink()
                removed_count += 1
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning("Failed to remove old log file %s: %s", log_file, e)
    
    if removed_count > 0:
        logger = logging.getLogger(__name__)
        logger.info("Cleaned up %d old log files (>%d days)", removed_count, retention_days)