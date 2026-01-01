# payatom_bot/messaging.py
"""
Enterprise-grade Telegram messaging client with professional features.

Features:
- Thread-safe message queuing with priority handling
- Automatic message truncation (Telegram 4096 char limit)
- Rate limiting protection (30 msg/sec limit)
- Circuit breaker pattern for failure recovery
- Message deduplication for repeated alerts
- Comprehensive error handling and logging
- Graceful shutdown with proper cleanup
- Metrics tracking for monitoring
"""
from __future__ import annotations

import asyncio
import hashlib
import html as html_module
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Deque, Set

from telegram import Bot
from telegram.constants import ParseMode
from telegram.error import RetryAfter, TimedOut, NetworkError

logger = logging.getLogger(__name__)


class MessagePriority(Enum):
    """Message priority levels for queue ordering."""
    CRITICAL = 1  # Errors, system failures
    HIGH = 2      # Balance alerts, authentication issues
    NORMAL = 3    # Status updates, routine operations
    LOW = 4       # Debug info, batch summaries


@dataclass
class QueuedMessage:
    """Represents a queued message with metadata."""
    text: str
    priority: MessagePriority
    timestamp: float
    kind: str
    attempt: int = 0
    
    def __lt__(self, other: QueuedMessage) -> bool:
        """Compare by priority, then timestamp."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.timestamp < other.timestamp


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"    # Normal operation
    OPEN = "open"        # Failing, reject new requests
    HALF_OPEN = "half_open"  # Testing recovery


class Messenger:
    """
    Professional Telegram messaging client for enterprise operations.
    
    Thread-safe implementation with:
    - Priority-based message queuing
    - Automatic rate limiting
    - Circuit breaker for failure recovery
    - Message deduplication
    - Comprehensive error handling
    """
    
    # Telegram API limits
    MAX_MESSAGE_LENGTH = 4096
    MAX_CAPTION_LENGTH = 1024
    RATE_LIMIT_MESSAGES_PER_SECOND = 20  # Conservative limit
    
    # Circuit breaker settings
    CIRCUIT_FAILURE_THRESHOLD = 5
    CIRCUIT_TIMEOUT_SECONDS = 60
    CIRCUIT_HALF_OPEN_ATTEMPTS = 3
    
    # Buffer settings
    MAX_BUFFER_SIZE = 100
    BATCH_INTERVAL_SECONDS = 60
    
    # Deduplication window
    DEDUP_WINDOW_SECONDS = 300  # 5 minutes
    
    def __init__(
        self,
        *,
        bot: Bot,
        chat_id: int,
        loop: asyncio.AbstractEventLoop,
        debug: bool = True
    ):
        """
        Initialize messenger.
        
        Args:
            bot: Telegram bot instance
            chat_id: Target chat ID for messages
            loop: Event loop for async operations
            debug: If True, send all messages immediately
        """
        self.bot = bot
        self.chat_id = chat_id
        self.loop = loop
        self.debug = debug
        
        # Message buffering
        self._buffer: Deque[QueuedMessage] = deque(maxlen=self.MAX_BUFFER_SIZE)
        self._buffer_lock = threading.Lock()
        self._flush_timer: Optional[asyncio.Handle] = None
        
        # Rate limiting
        self._rate_limiter_lock = threading.Lock()
        self._message_timestamps: Deque[float] = deque(maxlen=self.RATE_LIMIT_MESSAGES_PER_SECOND)
        
        # Circuit breaker
        self._circuit_lock = threading.Lock()
        self._circuit_state = CircuitState.CLOSED
        self._circuit_failures = 0
        self._circuit_opened_at: Optional[float] = None
        self._circuit_half_open_successes = 0
        
        # Message deduplication
        self._dedup_lock = threading.Lock()
        self._recent_message_hashes: Set[str] = set()
        self._dedup_timestamps: Deque[float] = deque()
        
        # Metrics
        self._metrics_lock = threading.Lock()
        self._total_sent = 0
        self._total_failed = 0
        self._total_deduplicated = 0
        self._total_rate_limited = 0
        
        # State
        self._closed = False
        
        logger.info(
            "Messenger initialized: chat_id=%d, debug=%s, rate_limit=%d msg/s",
            chat_id,
            debug,
            self.RATE_LIMIT_MESSAGES_PER_SECOND
        )
    
    # ============================================================
    # Public API
    # ============================================================
    
    def set_debug(self, enabled: bool) -> None:
        """
        Enable or disable debug mode.
        
        Args:
            enabled: If True, send all messages immediately
        """
        self.debug = enabled
        logger.info("Messenger debug mode: %s", "ENABLED" if enabled else "DISABLED")
    
    def send_event(self, text: str, kind: str = "INFO") -> None:
        """
        Send an event message to Telegram.
        
        Args:
            text: Message text (HTML formatted)
            kind: Event type (ERROR, START, STOP, CAPTCHA, OTP, UPLOAD_OK, INFO)
        """
        if self._closed:
            logger.warning("Messenger closed - cannot send event: %s", text[:50])
            return
        
        # Determine priority
        priority = self._get_priority(kind)
        
        # Check deduplication for errors
        if kind == "ERROR" and not self.debug:
            if self._is_duplicate(text):
                with self._metrics_lock:
                    self._total_deduplicated += 1
                logger.debug("Deduplicated error message (seen recently)")
                return
        
        # Escape HTML to prevent injection
        text = self._ensure_valid_html(text)
        
        # Create queued message
        message = QueuedMessage(
            text=text,
            priority=priority,
            timestamp=time.time(),
            kind=kind
        )
        
        # Send immediately if critical or debug mode
        if self.debug or priority in (MessagePriority.CRITICAL, MessagePriority.HIGH):
            self._send_immediate(message)
        else:
            self._buffer_message(message)
    
    def send_photo(
        self,
        photo,
        caption: Optional[str] = None,
        kind: str = "INFO"
    ) -> None:
        """
        Send a photo to Telegram.
        
        Args:
            photo: Photo file object or bytes (BytesIO)
            caption: Optional caption (HTML formatted)
            kind: Event type (affects priority)
        """
        if self._closed:
            logger.warning("Messenger closed - cannot send photo")
            return
        
        # Rewind BytesIO if needed
        if hasattr(photo, 'seek'):
            try:
                photo.seek(0)
            except Exception as e:
                logger.warning("Failed to rewind photo buffer: %s", e)
        
        # Escape caption HTML
        if caption:
            caption = self._ensure_valid_html(caption)
            caption = self._truncate_text(caption, self.MAX_CAPTION_LENGTH)
        
        # Determine if critical
        is_critical = kind == "ERROR" or (caption and "captcha" in caption.lower())
        
        if self.debug or is_critical:
            self._send_photo_immediate(photo, caption, kind)
        else:
            logger.debug("Skipped non-critical photo in production mode")
    
    async def aclose(self) -> None:
        """
        Flush pending messages and close messenger gracefully.
        
        Ensures all buffered messages are sent before shutdown.
        """
        logger.info("Closing messenger...")
        self._closed = True
        
        # Cancel scheduled flush
        if self._flush_timer and not self._flush_timer.cancelled():
            self._flush_timer.cancel()
        
        # Final flush with timeout
        try:
            await asyncio.wait_for(
                self._flush_buffer_async(),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.warning("Messenger close timeout - some messages may be lost")
        except Exception as e:
            logger.error("Error during messenger close: %s", e)
        
        logger.info(
            "Messenger closed - Stats: sent=%d, failed=%d, dedup=%d, rate_limited=%d",
            self._total_sent,
            self._total_failed,
            self._total_deduplicated,
            self._total_rate_limited
        )
    
    def get_stats(self) -> dict:
        """
        Get messaging statistics for monitoring.
        
        Returns:
            Dictionary with metrics
        """
        with self._metrics_lock:
            with self._circuit_lock:
                return {
                    "total_sent": self._total_sent,
                    "total_failed": self._total_failed,
                    "total_deduplicated": self._total_deduplicated,
                    "total_rate_limited": self._total_rate_limited,
                    "buffer_size": len(self._buffer),
                    "circuit_state": self._circuit_state.value,
                    "circuit_failures": self._circuit_failures,
                }
    
    # ============================================================
    # Internal Implementation
    # ============================================================
    
    def _get_priority(self, kind: str) -> MessagePriority:
        """Map event kind to priority level."""
        priority_map = {
            "ERROR": MessagePriority.CRITICAL,
            "START": MessagePriority.HIGH,
            "STOP": MessagePriority.HIGH,
            "CAPTCHA": MessagePriority.HIGH,
            "OTP": MessagePriority.HIGH,
            "UPLOAD_OK": MessagePriority.NORMAL,
            "INFO": MessagePriority.NORMAL,
        }
        return priority_map.get(kind, MessagePriority.NORMAL)
    
    def _is_duplicate(self, text: str) -> bool:
        """
        Check if message is duplicate within deduplication window.
        
        Args:
            text: Message text to check
            
        Returns:
            True if duplicate detected
        """
        # Hash the message
        msg_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]
        
        with self._dedup_lock:
            # Clean old entries
            cutoff = time.time() - self.DEDUP_WINDOW_SECONDS
            while self._dedup_timestamps and self._dedup_timestamps[0] < cutoff:
                self._dedup_timestamps.popleft()
            
            # Rebuild hash set from valid timestamps
            # (Simple approach - in production, use a proper time-based cache)
            if msg_hash in self._recent_message_hashes:
                return True
            
            # Add new
            self._recent_message_hashes.add(msg_hash)
            self._dedup_timestamps.append(time.time())
            
            # Limit size
            if len(self._recent_message_hashes) > 100:
                self._recent_message_hashes.clear()
                self._dedup_timestamps.clear()
            
            return False
    
    def _ensure_valid_html(self, text: str) -> str:
        """
        Ensure text is valid HTML by escaping if needed.
        
        Already-formatted HTML with proper tags is preserved.
        Plain text is escaped.
        
        Args:
            text: Input text
            
        Returns:
            Safe HTML text
        """
        # If text already has HTML tags, assume it's intentionally formatted
        if any(tag in text for tag in ['<b>', '<i>', '<code>', '<pre>', '<a>']):
            return text
        
        # Otherwise escape to be safe
        return html_module.escape(text)
    
    def _truncate_text(self, text: str, max_length: int) -> str:
        """
        Truncate text to maximum length intelligently.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            
        Returns:
            Truncated text with ellipsis if needed
        """
        if len(text) <= max_length:
            return text
        
        # Leave room for ellipsis
        truncate_at = max_length - 100
        truncated = text[:truncate_at]
        
        # Try to break at newline
        last_newline = truncated.rfind('\n')
        if last_newline > truncate_at - 200:
            truncated = truncated[:last_newline]
        
        return truncated + "\n\n<i>[Message truncated - see logs for full details]</i>"
    
    def _buffer_message(self, message: QueuedMessage) -> None:
        """Add message to buffer and schedule flush."""
        with self._buffer_lock:
            self._buffer.append(message)
            
            # Log if buffer is getting full
            if len(self._buffer) >= self.MAX_BUFFER_SIZE * 0.8:
                logger.warning(
                    "Message buffer at %d%% capacity (%d/%d)",
                    int(len(self._buffer) / self.MAX_BUFFER_SIZE * 100),
                    len(self._buffer),
                    self.MAX_BUFFER_SIZE
                )
        
        self._schedule_flush()
    
    def _schedule_flush(self) -> None:
        """Schedule a flush of buffered messages."""
        if self._closed:
            return
        
        if self._flush_timer and not self._flush_timer.cancelled():
            return  # Already scheduled
        
        try:
            self._flush_timer = self.loop.call_later(
                self.BATCH_INTERVAL_SECONDS,
                lambda: asyncio.create_task(self._flush_buffer_async())
            )
        except Exception as e:
            logger.error("Failed to schedule flush: %s", e)
    
    def _send_immediate(self, message: QueuedMessage) -> None:
        """Send message immediately (async)."""
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._send_message_with_circuit_breaker(message),
                self.loop
            )
            
            def handle_result(f):
                try:
                    f.result()
                except Exception as e:
                    logger.error("Failed to send immediate message: %s", e)
            
            fut.add_done_callback(handle_result)
            
        except Exception as e:
            logger.error("Failed to schedule immediate send: %s", e)
    
    def _send_photo_immediate(self, photo, caption: Optional[str], kind: str) -> None:
        """Send photo immediately (async)."""
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._send_photo_with_retry(photo, caption),
                self.loop
            )
            
            def handle_result(f):
                try:
                    f.result()
                    with self._metrics_lock:
                        self._total_sent += 1
                except Exception as e:
                    logger.error("Failed to send photo: %s", e)
                    with self._metrics_lock:
                        self._total_failed += 1
            
            fut.add_done_callback(handle_result)
            
        except Exception as e:
            logger.error("Failed to schedule photo send: %s", e)
    
    async def _flush_buffer_async(self) -> None:
        """Flush buffered messages (called in event loop)."""
        messages_to_send = []
        
        with self._buffer_lock:
            if not self._buffer:
                return
            
            # Sort by priority
            sorted_buffer = sorted(self._buffer, key=lambda m: m.priority.value)
            messages_to_send = list(sorted_buffer)
            self._buffer.clear()
        
        if not messages_to_send:
            return
        
        # Combine low-priority messages into batches
        batched = self._create_batches(messages_to_send)
        
        # Send each batch/message
        for item in batched:
            if isinstance(item, str):
                # Batch summary
                await self._send_text_with_rate_limit(item, ParseMode.HTML)
            else:
                # Individual high-priority message
                await self._send_message_with_circuit_breaker(item)
    
    def _create_batches(self, messages: list[QueuedMessage]) -> list:
        """
        Create batches from messages.
        
        High priority messages sent individually.
        Low priority messages combined into summary.
        
        Args:
            messages: Sorted list of messages
            
        Returns:
            List of QueuedMessage or batch strings
        """
        result = []
        low_priority = []
        
        for msg in messages:
            if msg.priority in (MessagePriority.CRITICAL, MessagePriority.HIGH):
                result.append(msg)
            else:
                low_priority.append(msg)
        
        # Create batch summary for low-priority
        if low_priority:
            batch_text = self._format_batch_summary(low_priority)
            result.append(batch_text)
        
        return result
    
    def _format_batch_summary(self, messages: list[QueuedMessage]) -> str:
        """Format low-priority messages into batch summary."""
        header = f"<b>Activity Summary</b> ({len(messages)} events)\n\n"
        
        # Group by kind
        by_kind = {}
        for msg in messages:
            by_kind.setdefault(msg.kind, []).append(msg)
        
        lines = []
        for kind, msgs in by_kind.items():
            if len(msgs) == 1:
                # Show single message
                lines.append(msgs[0].text)
            else:
                # Summarize multiple
                lines.append(f"<b>{kind}</b>: {len(msgs)} events")
        
        return header + "\n".join(lines)
    
    async def _send_message_with_circuit_breaker(self, message: QueuedMessage) -> None:
        """Send message with circuit breaker pattern."""
        # Check circuit state
        if not self._check_circuit():
            logger.warning("Circuit OPEN - message dropped: %s", message.text[:50])
            with self._metrics_lock:
                self._total_failed += 1
            return
        
        # Truncate if needed
        text = self._truncate_text(message.text, self.MAX_MESSAGE_LENGTH)
        
        try:
            await self._send_text_with_rate_limit(text, ParseMode.HTML)
            
            # Success - update circuit
            with self._circuit_lock:
                if self._circuit_state == CircuitState.HALF_OPEN:
                    self._circuit_half_open_successes += 1
                    if self._circuit_half_open_successes >= self.CIRCUIT_HALF_OPEN_ATTEMPTS:
                        self._circuit_state = CircuitState.CLOSED
                        self._circuit_failures = 0
                        logger.info("Circuit breaker: CLOSED (recovered)")
            
            with self._metrics_lock:
                self._total_sent += 1
                
        except Exception as e:
            logger.error("Message send failed: %s", e)
            
            # Update circuit on failure
            with self._circuit_lock:
                self._circuit_failures += 1
                
                if self._circuit_state == CircuitState.HALF_OPEN:
                    # Failed during testing - reopen
                    self._circuit_state = CircuitState.OPEN
                    self._circuit_opened_at = time.time()
                    self._circuit_half_open_successes = 0
                    logger.warning("Circuit breaker: OPEN (test failed)")
                    
                elif self._circuit_failures >= self.CIRCUIT_FAILURE_THRESHOLD:
                    self._circuit_state = CircuitState.OPEN
                    self._circuit_opened_at = time.time()
                    logger.error(
                        "Circuit breaker: OPEN (threshold reached: %d failures)",
                        self._circuit_failures
                    )
            
            with self._metrics_lock:
                self._total_failed += 1
    
    def _check_circuit(self) -> bool:
        """
        Check circuit breaker state and transition if needed.
        
        Returns:
            True if circuit allows requests
        """
        with self._circuit_lock:
            if self._circuit_state == CircuitState.CLOSED:
                return True
            
            if self._circuit_state == CircuitState.OPEN:
                # Check if timeout expired
                if (self._circuit_opened_at and
                    time.time() - self._circuit_opened_at >= self.CIRCUIT_TIMEOUT_SECONDS):
                    # Transition to half-open (test mode)
                    self._circuit_state = CircuitState.HALF_OPEN
                    self._circuit_half_open_successes = 0
                    logger.info("Circuit breaker: HALF_OPEN (testing recovery)")
                    return True
                return False
            
            # HALF_OPEN - allow request for testing
            return True
    
    async def _send_text_with_rate_limit(self, text: str, parse_mode: str) -> None:
        """Send text message with rate limiting."""
        # Wait if rate limit reached
        await self._wait_for_rate_limit()
        
        # Send with retry
        max_retries = 3
        for attempt in range(max_retries):
            try:
                await self.bot.send_message(
                    self.chat_id,
                    text,
                    parse_mode=parse_mode,
                    disable_web_page_preview=True,
                )
                
                # Record send time for rate limiting
                with self._rate_limiter_lock:
                    self._message_timestamps.append(time.time())
                
                return
                
            except RetryAfter as e:
                # Telegram asked us to wait
                wait_time = e.retry_after + 1
                logger.warning("Rate limited by Telegram - waiting %ds", wait_time)
                
                with self._metrics_lock:
                    self._total_rate_limited += 1
                
                if attempt < max_retries - 1:
                    await asyncio.sleep(wait_time)
                else:
                    raise
                    
            except (TimedOut, NetworkError) as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise
                    
            except Exception as e:
                logger.error(
                    "Send attempt %d/%d failed: %s: %s",
                    attempt + 1,
                    max_retries,
                    type(e).__name__,
                    e
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    raise
    
    async def _wait_for_rate_limit(self) -> None:
        """Wait if rate limit would be exceeded."""
        with self._rate_limiter_lock:
            # Clean old timestamps
            cutoff = time.time() - 1.0
            while self._message_timestamps and self._message_timestamps[0] < cutoff:
                self._message_timestamps.popleft()
            
            # Check if at limit
            if len(self._message_timestamps) >= self.RATE_LIMIT_MESSAGES_PER_SECOND:
                # Calculate wait time
                oldest = self._message_timestamps[0]
                wait_time = 1.0 - (time.time() - oldest)
                
                if wait_time > 0:
                    logger.debug("Rate limit - waiting %.2fs", wait_time)
                    await asyncio.sleep(wait_time)
    
    async def _send_photo_with_retry(
        self,
        photo,
        caption: Optional[str] = None,
        max_retries: int = 3
    ) -> None:
        """Send photo with retry logic."""
        for attempt in range(max_retries):
            try:
                # Rewind before each attempt
                if hasattr(photo, 'seek'):
                    photo.seek(0)
                
                await self.bot.send_photo(
                    self.chat_id,
                    photo=photo,
                    caption=caption,
                    parse_mode=ParseMode.HTML if caption else None
                )
                return
                
            except Exception as e:
                logger.warning(
                    "Photo send attempt %d/%d failed: %s",
                    attempt + 1,
                    max_retries,
                    e
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    logger.error("Failed to send photo after %d attempts", max_retries)
                    raise