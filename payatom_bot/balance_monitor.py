# payatom_bot/balance_monitor.py
"""
Enterprise-grade balance monitoring system with escalating urgency alerts.

Monitors account balances across all running workers and sends alerts to
designated Telegram groups when thresholds are crossed.

Features:
- Threshold-based alert system with escalating urgency
- Repeated alerts every 5 minutes until resolved
- Automatic alert clearing when balance drops
- Integration with existing error handling and logging
- Thread-safe concurrent operations
- Comprehensive audit trail
- PII-compliant logging with account masking

Threshold Levels:
- ₹50,000: Low urgency (informational)
- ₹60,000: Low-Medium urgency (watch closely)
- ₹70,000: Medium urgency (action required)
- ₹90,000: High urgency (immediate action needed)
- ₹100,000+: CRITICAL (stop account immediately)

Security:
- Account numbers masked in all outputs
- Audit logging for all alert operations
- PII protection via existing logging infrastructure
"""
from __future__ import annotations

import asyncio
import html
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Set, Optional

from telegram import Bot
from telegram.constants import ParseMode

from .error_handler import (
    ErrorContext,
    ErrorCategory,
    ErrorMetadata,
    ErrorSeverity,
    safe_operation,
)
from .logging_config import log_audit_event

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BalanceThreshold:
    """Configuration for a balance alert threshold."""
    amount: int
    urgency: str
    emoji: str
    action_required: str


# Threshold configurations with escalating urgency
THRESHOLDS = [
    BalanceThreshold(
        amount=50_000,
        urgency="🟡 LOW PRIORITY",
        emoji="ℹ️",
        action_required="Monitor account activity"
    ),
    BalanceThreshold(
        amount=60_000,
        urgency="🟠 LOW-MEDIUM PRIORITY",
        emoji="⚠️",
        action_required="Watch closely and prepare for fund transfer"
    ),
    BalanceThreshold(
        amount=70_000,
        urgency="🟠 MEDIUM PRIORITY",
        emoji="⚠️⚠️",
        action_required="<b>TRANSFER FUNDS URGENTLY</b> to prevent exceeding limits"
    ),
    BalanceThreshold(
        amount=90_000,
        urgency="🔴 HIGH PRIORITY",
        emoji="🚨",
        action_required=(
            "<b>⚡ IMMEDIATE ACTION REQUIRED ⚡</b>\n"
            "<b>TRANSFER FUNDS NOW!</b> Account approaching critical limit"
        )
    ),
    BalanceThreshold(
        amount=100_000,
        urgency="🔴🔴 CRITICAL ALERT 🔴🔴",
        emoji="🚨🚨🚨",
        action_required=(
            "<b>🛑 STOP ALL OPERATIONS IMMEDIATELY 🛑</b>\n\n"
            "<b>⚡⚡⚡ TRANSFER FUNDS RIGHT NOW ⚡⚡⚡</b>\n\n"
            "Account has exceeded ₹1,00,000 limit!\n"
            "Risk of account suspension or regulatory issues.\n"
            "<b>DO NOT DELAY - ACT NOW!</b>"
        )
    ),
]


def parse_balance_amount(balance_str: str) -> Optional[float]:
    """
    Parse balance string to numeric value.
    
    Handles various formats:
    - "₹12,345.67"
    - "INR 12345.67"
    - "12,345.67 INR"
    - "12345.67"
    
    Args:
        balance_str: Balance string from worker
        
    Returns:
        Numeric balance value or None if unparseable
    """
    if not balance_str:
        return None
    
    result = safe_operation(
        lambda: _parse_balance_internal(balance_str),
        context=f"parse balance string: {balance_str}",
        default=None,
        log_errors=False,  # Don't spam logs for parsing failures
    )
    
    return result


def _parse_balance_internal(balance_str: str) -> Optional[float]:
    """Internal balance parsing logic."""
    # Remove currency symbols and common text
    cleaned = balance_str.upper()
    cleaned = re.sub(r'[₹$€£INR\s,]', '', cleaned)
    
    # Handle formats like "12345.67 CR" or "12345.67 DR"
    cleaned = re.sub(r'\s*(CR|DR|CREDIT|DEBIT)\s*$', '', cleaned, flags=re.IGNORECASE)
    
    # Extract first number (handles "Available: 12345.67" etc)
    match = re.search(r'[\d.]+', cleaned)
    if match:
        return float(match.group())
        
    return None


def _mask_account_number(account_number: str) -> str:
    """
    Mask account number showing only last 4 digits.
    
    Follows existing PII protection patterns.
    """
    if not account_number:
        return "N/A"
    
    if len(account_number) > 4:
        return "****" + account_number[-4:]
    return account_number


def format_alert_message(
    alias: str,
    balance: float,
    threshold: BalanceThreshold,
    account_number: str = "",
    bank_label: str = "",
    is_repeat: bool = False,
) -> str:
    """
    Format professional alert message with appropriate urgency level.
    
    Follows existing messaging patterns with HTML formatting.
    
    Args:
        alias: Account alias
        balance: Current balance
        threshold: Triggered threshold configuration
        account_number: Account number (optional, will be masked)
        bank_label: Bank name (optional)
        is_repeat: Whether this is a repeated alert
        
    Returns:
        Formatted HTML message for Telegram
    """
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    # Format balance with Indian number system
    balance_formatted = f"₹{balance:,.2f}"
    threshold_formatted = f"₹{threshold.amount:,.0f}"
    
    # Mask account number (PII protection)
    masked_account = _mask_account_number(account_number)
    
    # Build header based on urgency (follows error_handler.py patterns)
    if threshold.amount >= 100_000:
        header = (
            "🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨\n"
            "🔴 <b>CRITICAL BALANCE ALERT</b> 🔴\n"
            "🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨\n"
        )
        if is_repeat:
            header += "<b>⚠️ REPEATED ALERT - STILL CRITICAL ⚠️</b>\n"
        header += "\n"
    elif threshold.amount >= 90_000:
        header = (
            "🚨🚨🚨🚨🚨🚨🚨🚨🚨\n"
            "🔴 <b>HIGH PRIORITY ALERT</b> 🔴\n"
            "🚨🚨🚨🚨🚨🚨🚨🚨🚨\n"
        )
        if is_repeat:
            header += "<b>⚠️ REPEATED - STILL HIGH PRIORITY ⚠️</b>\n"
        header += "\n"
    elif threshold.amount >= 70_000:
        header = (
            "⚠️⚠️⚠️⚠️⚠️⚠️⚠️\n"
            "🟠 <b>URGENT ALERT</b> 🟠\n"
            "⚠️⚠️⚠️⚠️⚠️⚠️⚠️\n"
        )
        if is_repeat:
            header += "<b>🔁 REPEATED ALERT 🔁</b>\n"
        header += "\n"
    else:
        header = f"{threshold.emoji} <b>Balance Alert</b> {threshold.emoji}\n"
        if is_repeat:
            header += "<i>🔁 Repeated Alert</i>\n"
        header += "\n"
    
    # Account details section (follows error_handler.py context section pattern)
    details = (
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<b>📌 Account Details:</b>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"<b>🏷️ Alias:</b> <code>{html.escape(alias)}</code>\n"
    )
    
    if bank_label:
        details += f"<b>🏦 Bank:</b> {html.escape(bank_label)}\n"
    
    details += (
        f"<b>🔢 Account:</b> <code>{masked_account}</code>\n"
        f"<b>🕐 Time:</b> {timestamp}\n\n"
    )
    
    # Balance information with emphasis
    excess_amount = balance - threshold.amount
    if threshold.amount >= 100_000:
        balance_section = (
            f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
            f"<b>💰 BALANCE STATUS:</b>\n"
            f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
            f"<b>🔴 Current Balance:</b> <code>{balance_formatted}</code>\n"
            f"<b>⚠️ Threshold Crossed:</b> <code>{threshold_formatted}</code>\n"
            f"<b>📊 Excess Amount:</b> <code>₹{excess_amount:,.2f}</code>\n\n"
        )
    else:
        balance_section = (
            f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
            f"<b>💰 Balance Information:</b>\n"
            f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
            f"<b>Current Balance:</b> <code>{balance_formatted}</code>\n"
            f"<b>Threshold Crossed:</b> <code>{threshold_formatted}</code>\n"
            f"<b>Excess Amount:</b> <code>₹{excess_amount:,.2f}</code>\n\n"
        )
    
    # Urgency level
    urgency_section = (
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<b>🚦 Alert Level:</b>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"{threshold.urgency}\n\n"
    )
    
    # Required actions
    action_section = (
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<b>📋 Required Action:</b>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"{threshold.action_required}\n\n"
    )
    
    # Footer
    if threshold.amount >= 100_000:
        footer = (
            "<b>━━━━━━━━━━━━━━━━━━━</b>\n"
            "🚨 <b>THIS IS AN AUTOMATED CRITICAL ALERT</b> 🚨\n"
            "🔴 <b>IMMEDIATE MANUAL INTERVENTION REQUIRED</b> 🔴\n"
        )
        if is_repeat:
            footer += "⚠️ <b>ALERT REPEATING EVERY 5 MINUTES</b> ⚠️\n"
        footer += "<b>━━━━━━━━━━━━━━━━━━━</b>"
    elif threshold.amount >= 90_000:
        footer = (
            "<b>━━━━━━━━━━━━━━━━━━━</b>\n"
            "⚠️ <b>Automated High Priority Alert</b> ⚠️\n"
            "Please take immediate action\n"
        )
        if is_repeat:
            footer += "🔁 <i>Repeating every 5 minutes until resolved</i>\n"
        footer += "<b>━━━━━━━━━━━━━━━━━━━</b>"
    else:
        footer = (
            "<b>━━━━━━━━━━━━━━━━━━━</b>\n"
            "ℹ️ <i>Automated Balance Monitoring System</i>\n"
        )
        if is_repeat:
            footer += "🔁 <i>Alert repeats every 5 min until balance drops</i>\n"
        footer += "<b>━━━━━━━━━━━━━━━━━━━</b>"
    
    return header + details + balance_section + urgency_section + action_section + footer


class BalanceMonitor:
    """
    Enterprise-grade balance monitoring with escalating alerts.
    
    Features:
    - Threshold-based monitoring with 5 urgency levels
    - Repeated alerts every 5 minutes until resolved
    - Automatic alert clearing when balance drops
    - Thread-safe concurrent operations
    - Integration with existing error handling
    - Comprehensive audit trail
    
    Thread Safety:
    - Can run concurrently with multiple workers
    - Uses safe_operation() for all worker access
    - No shared state between worker checks
    """
    
    def __init__(
        self,
        bot: Bot,
        alert_group_ids: list[int],
        check_interval: int = 180,
    ):
        """
        Initialize balance monitor.
        
        Args:
            bot: Telegram bot instance
            alert_group_ids: List of Telegram group IDs to send alerts to
            check_interval: Seconds between balance checks (default: 180 = 3 minutes)
        """
        self.bot = bot
        self.alert_group_ids = alert_group_ids or []
        self.check_interval = check_interval
        
        # Track which thresholds have been triggered for each alias
        self.triggered_thresholds: Dict[str, Set[int]] = {}
        
        # Track last alert time per alias (for repeated alerts every 5 min)
        self.last_alert_time: Dict[str, datetime] = {}
        
        # Alert repeat interval (5 minutes)
        self.alert_repeat_interval = 300  # 5 minutes in seconds
        
        # Task handle for monitoring
        self._task: Optional[asyncio.Task] = None
        self._running = False
        
        # Audit log for monitor initialization
        log_audit_event('BALANCE_MONITOR_INIT', {
            'alert_groups': len(self.alert_group_ids),
            'check_interval': check_interval,
            'repeat_interval': self.alert_repeat_interval,
            'thresholds': [t.amount for t in THRESHOLDS],
        })
        
        logger.info(
            "Balance monitor initialized: %d alert group(s), check interval: %ds, repeat alerts every: %ds",
            len(self.alert_group_ids),
            check_interval,
            self.alert_repeat_interval,
        )
    
    async def start(self, workers_registry: Dict[str, object]) -> None:
        """
        Start the balance monitoring task.
        
        Uses ErrorContext for proper error handling integration.
        
        Args:
            workers_registry: Reference to bot_data["workers"] dictionary
        """
        if self._running:
            logger.warning("Balance monitor already running")
            return
        
        if not self.alert_group_ids:
            logger.warning(
                "No alert group IDs configured - balance monitoring disabled. "
                "Set ALERT_GROUP_IDS in environment to enable."
            )
            return
        
        with ErrorContext(
            "starting balance monitor",
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.MEDIUM,
            reraise=True,
        ):
            self._running = True
            self._task = asyncio.create_task(self._monitor_loop(workers_registry))
            
            # Audit log
            log_audit_event('BALANCE_MONITOR_START', {
                'alert_groups': len(self.alert_group_ids),
                'check_interval': self.check_interval,
            })
            
            logger.info("Balance monitor started successfully")
    
    async def stop(self) -> None:
        """
        Stop the balance monitoring task gracefully.
        
        Cancels the monitoring task and waits for cleanup.
        """
        if not self._running:
            return
        
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        # Audit log
        log_audit_event('BALANCE_MONITOR_STOP', {
            'total_alerts_sent': sum(len(t) for t in self.triggered_thresholds.values()),
            'monitored_aliases': len(self.triggered_thresholds),
        })
        
        logger.info("Balance monitor stopped")
    
    async def _monitor_loop(self, workers_registry: Dict[str, object]) -> None:
        """
        Main monitoring loop with comprehensive error handling.
        
        Uses safe_operation() for worker access and ErrorContext for exceptions.
        """
        logger.info("Balance monitor loop started")
        
        while self._running:
            try:
                await self._check_all_balances(workers_registry)
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Use existing error handling - this logs and reports automatically
                logger.exception("Error in balance monitor loop: %s", e)
                # Don't crash the monitor - continue running
            
            # Wait for next check interval
            try:
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
        
        logger.info("Balance monitor loop stopped")
    
    async def _check_all_balances(self, workers_registry: Dict[str, object]) -> None:
        """
        Check balances for all running workers.
        
        Thread-safe implementation using safe_operation() for all worker access.
        """
        if not workers_registry:
            return
        
        checked_count = 0
        alert_count = 0
        
        for alias, worker in list(workers_registry.items()):
            try:
                # Check if worker is alive (thread-safe)
                is_alive = safe_operation(
                    lambda: hasattr(worker, 'is_alive') and worker.is_alive(),
                    context=f"check if {alias} worker is alive",
                    default=False,
                    log_errors=False,
                )
                
                if not is_alive:
                    continue
                
                # Get balance (thread-safe)
                balance_str = safe_operation(
                    lambda: getattr(worker, 'last_balance', None),
                    context=f"get balance for {alias}",
                    default=None,
                    log_errors=False,
                )
                
                if not balance_str:
                    continue
                
                checked_count += 1
                
                # Parse balance
                balance = parse_balance_amount(balance_str)
                if balance is None:
                    logger.debug(
                        "Could not parse balance for %s: %s",
                        alias,
                        balance_str,
                    )
                    continue
                
                # Process threshold logic
                await self._process_balance_threshold(alias, balance, worker)
                
            except Exception as e:
                # Log but don't crash the monitor
                logger.exception(
                    "Error checking balance for %s: %s",
                    alias,
                    e,
                )
        
        if checked_count > 0:
            logger.debug(
                "Balance check complete: %d workers checked, %d with active alerts",
                checked_count,
                len(self.last_alert_time),
            )
    
    async def _process_balance_threshold(
        self,
        alias: str,
        balance: float,
        worker: object,
    ) -> None:
        """
        Process balance threshold logic for a single worker.
        
        Determines if alert should be sent based on:
        - Current threshold crossed
        - Time since last alert
        - Whether this is a repeat alert
        """
        # Find the HIGHEST threshold that balance has crossed
        current_threshold = None
        for threshold in reversed(THRESHOLDS):  # Check from highest to lowest
            if balance >= threshold.amount:
                current_threshold = threshold
                break
        
        # If balance is below ALL thresholds, auto-clear tracking
        if current_threshold is None:
            if alias in self.triggered_thresholds or alias in self.last_alert_time:
                logger.info(
                    "Balance for %s dropped below all thresholds (₹%.2f) - auto-cleared alerts",
                    alias,
                    balance,
                )
                
                # Audit log for alert clearing
                log_audit_event('BALANCE_ALERT_CLEARED', {
                    'alias': alias,
                    'balance': balance,
                    'reason': 'below_all_thresholds',
                })
                
                self.triggered_thresholds.pop(alias, None)
                self.last_alert_time.pop(alias, None)
            return
        
        # Balance is above a threshold - check if we should send alert
        now = datetime.now()
        last_alert = self.last_alert_time.get(alias)
        
        should_send_alert = False
        
        if last_alert is None:
            # First time crossing - send immediately
            should_send_alert = True
            logger.info(
                "🔔 %s crossed ₹%s threshold for first time (current: ₹%.2f)",
                alias,
                f"{current_threshold.amount:,}",
                balance,
            )
        else:
            # Check if 5 minutes have passed since last alert
            time_since_last = (now - last_alert).total_seconds()
            if time_since_last >= self.alert_repeat_interval:
                should_send_alert = True
                logger.info(
                    "🔁 Repeating alert for %s - still at ₹%s threshold (current: ₹%.2f, last alert: %.0fs ago)",
                    alias,
                    f"{current_threshold.amount:,}",
                    balance,
                    time_since_last,
                )
        
        if should_send_alert:
            # Send alert with error handling
            await self._send_alert(alias, balance, current_threshold, worker, last_alert is not None)
            
            # Update tracking
            self.last_alert_time[alias] = now
            if alias not in self.triggered_thresholds:
                self.triggered_thresholds[alias] = set()
            self.triggered_thresholds[alias].add(current_threshold.amount)
    
    async def _send_alert(
        self,
        alias: str,
        balance: float,
        threshold: BalanceThreshold,
        worker: object,
        is_repeat: bool,
    ) -> None:
        """
        Send alert to all configured groups with comprehensive error handling.
        
        Uses ErrorContext for automatic error reporting and audit logging.
        """
        # Get additional worker details (thread-safe)
        account_number = safe_operation(
            lambda: getattr(worker, 'cred', {}).get('account_number', ''),
            context=f"get account number for {alias}",
            default='',
            log_errors=False,
        )
        
        bank_label = safe_operation(
            lambda: getattr(worker, 'cred', {}).get('bank_label', ''),
            context=f"get bank label for {alias}",
            default='',
            log_errors=False,
        )
        
        # Format message
        message = format_alert_message(
            alias=alias,
            balance=balance,
            threshold=threshold,
            account_number=account_number,
            bank_label=bank_label,
            is_repeat=is_repeat,
        )
        
        # Audit log for alert
        alert_type = "REPEAT" if is_repeat else "NEW"
        log_audit_event('BALANCE_ALERT_SENT', {
            'alias': alias,
            'balance': balance,
            'threshold': threshold.amount,
            'urgency': threshold.urgency,
            'is_repeat': is_repeat,
            'alert_type': alert_type,
            'bank': bank_label,
            'account': _mask_account_number(account_number),
        })
        
        # Send to all alert groups
        success_count = 0
        for group_id in self.alert_group_ids:
            with ErrorContext(
                f"sending balance alert to group {group_id}",
                alias=alias,
                bank=bank_label,
                category=ErrorCategory.SYSTEM,
                severity=ErrorSeverity.HIGH if threshold.amount >= 90_000 else ErrorSeverity.MEDIUM,
                reraise=False,  # Don't crash monitor if one send fails
            ):
                await self.bot.send_message(
                    chat_id=group_id,
                    text=message,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )
                success_count += 1
                
                logger.info(
                    "Sent %s %s alert for %s (₹%.2f) to group %d",
                    alert_type,
                    threshold.urgency,
                    alias,
                    balance,
                    group_id,
                )
        
        if success_count == 0:
            logger.error(
                "Failed to send alert to any groups for %s at threshold ₹%s",
                alias,
                f"{threshold.amount:,}",
            )
    
    def reset_alerts_for_alias(
        self,
        alias: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        chat_id: Optional[int] = None,
    ) -> None:
        """
        Reset triggered alerts for an alias.
        
        Useful when worker restarts or after manual fund transfer.
        Thread-safe operation.
        
        Args:
            alias: Worker alias to reset
            user_id: Telegram user ID (if triggered by command)
            username: Telegram username (if triggered by command)
            chat_id: Telegram chat ID (if triggered by command)
        """
        if alias in self.triggered_thresholds:
            del self.triggered_thresholds[alias]
        if alias in self.last_alert_time:
            del self.last_alert_time[alias]
        
        # Build audit log data with user context if available
        audit_data = {
            'alias': alias,
            'reason': 'command' if user_id else 'system',
        }
        
        if user_id is not None:
            audit_data['user_id'] = user_id
        if username:
            audit_data['username'] = username
        if chat_id is not None:
            audit_data['chat_id'] = chat_id
        
        # Audit log
        log_audit_event('BALANCE_ALERT_RESET', audit_data)
        
        # Enhanced logging with user context
        if user_id:
            logger.info(
                "Reset balance alerts for %s (triggered by user_id=%s, username=%s)",
                alias,
                user_id,
                username or 'unknown',
            )
        else:
            logger.info("Reset balance alerts for %s (system trigger)", alias)
    
    def get_status(self) -> dict:
        """
        Get monitor status information for debugging and monitoring.
        
        Returns:
            Dictionary with current status metrics
        """
        return {
            "running": self._running,
            "alert_groups": len(self.alert_group_ids),
            "check_interval": self.check_interval,
            "monitored_aliases": len(self.triggered_thresholds),
            "total_alerts": sum(len(t) for t in self.triggered_thresholds.values()),
            "repeat_interval": self.alert_repeat_interval,
            "aliases_with_active_alerts": len(self.last_alert_time),
            "thresholds": [
                {
                    "amount": t.amount,
                    "urgency": t.urgency,
                    "emoji": t.emoji,
                }
                for t in THRESHOLDS
            ],
        }