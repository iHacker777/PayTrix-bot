from __future__ import annotations
import asyncio
import threading
import logging
from typing import Optional
from telegram.constants import ParseMode
from telegram import Bot

logger = logging.getLogger(__name__)

class Messenger:
    """
    Thread-safe Telegram sender with batching and robust error handling.
    
    Features:
    - Thread-safe message queuing
    - Optional 60s batching for non-critical messages
    - Immediate delivery for critical events
    - Graceful error recovery
    """
    def __init__(
        self,
        *,
        bot: Bot,
        chat_id: int,
        loop: asyncio.AbstractEventLoop,
        debug: bool = True
    ):
        self.bot = bot
        self.chat_id = chat_id
        self.loop = loop
        self.debug = debug

        self._buf: list[str] = []
        self._buf_lock = threading.Lock()
        self._flush_timer: Optional[asyncio.Handle] = None
        self._closed = False
        self._consecutive_errors = 0
        self._max_consecutive_errors = 5

    def set_debug(self, on: bool) -> None:
        """Enable or disable debug mode (immediate message delivery)."""
        self.debug = on
        logger.info("Messenger debug mode: %s", "ON" if on else "OFF")

    # —— internal ——
    def _schedule_flush(self) -> None:
        """Schedule a flush of buffered messages."""
        if self._closed:
            return
        if self._flush_timer and not self._flush_timer.cancelled():
            # already scheduled
            return
        # schedule a one-shot callback that will run in loop thread
        try:
            self._flush_timer = self.loop.call_later(60.0, self._flush_now_threadsafe)
        except Exception as e:
            logger.error("Failed to schedule flush: %s", e)

    def _flush_now_threadsafe(self) -> None:
        """Flush buffered messages to Telegram (called from event loop)."""
        with self._buf_lock:
            if not self._buf:
                return
            text = "🧾 <b>Summary (last 1 min):</b>\n" + "\n".join(self._buf)
            self._buf.clear()
        
        fut = asyncio.run_coroutine_threadsafe(
            self._send_message_with_retry(text, ParseMode.HTML),
            self.loop
        )
        
        def handle_result(f):
            try:
                f.result()
                self._consecutive_errors = 0
            except Exception as e:
                logger.warning("Messenger flush error: %s", e)
                self._consecutive_errors += 1
                if self._consecutive_errors >= self._max_consecutive_errors:
                    logger.error(
                        "Too many consecutive Telegram errors (%d). "
                        "Messages may not be delivered.",
                        self._consecutive_errors
                    )
        
        fut.add_done_callback(handle_result)

    async def _send_message_with_retry(
        self,
        text: str,
        parse_mode: str,
        max_retries: int = 3
    ) -> None:
        """Send a message with automatic retries on failure."""
        for attempt in range(max_retries):
            try:
                await self.bot.send_message(
                    self.chat_id,
                    text,
                    parse_mode=parse_mode,
                    disable_web_page_preview=True,
                )
                return
            except Exception as e:
                logger.warning(
                    "Telegram send_message attempt %d/%d failed: %s",
                    attempt + 1,
                    max_retries,
                    e
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    logger.error(
                        "Failed to send message after %d attempts: %s",
                        max_retries,
                        text[:100]
                    )
                    raise

    async def _send_photo_with_retry(
        self,
        photo,
        caption: Optional[str] = None,
        max_retries: int = 3
    ) -> None:
        """Send a photo with automatic retries on failure."""
        for attempt in range(max_retries):
            try:
                await self.bot.send_photo(
                    self.chat_id,
                    photo=photo,
                    caption=caption
                )
                return
            except Exception as e:
                logger.warning(
                    "Telegram send_photo attempt %d/%d failed: %s",
                    attempt + 1,
                    max_retries,
                    e
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                else:
                    logger.error(
                        "Failed to send photo after %d attempts",
                        max_retries
                    )
                    raise

    async def aclose(self) -> None:
        """Flush pending messages and close the messenger."""
        logger.info("Closing messenger...")
        self._closed = True
        if self._flush_timer and not self._flush_timer.cancelled():
            self._flush_timer.cancel()
        # final flush
        self._flush_now_threadsafe()
        logger.info("Messenger closed")

    # —— public (thread-safe) ——
    def send_event(self, text: str, kind: str = "INFO"):
        """
        Send an event message to Telegram .
        
        Args:
            text: Message text
            kind: Event type (INFO, ERROR, START, STOP, CAPTCHA, OTP, UPLOAD_OK)
        """
        if self._closed:
            logger.warning("Messenger is closed; cannot send event: %s", text[:50])
            return
            
        is_critical = kind in {"ERROR", "START", "STOP", "CAPTCHA", "OTP", "UPLOAD_OK"}
        
        if self.debug or is_critical:
            # Send immediately
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self._send_message_with_retry(text, ParseMode.HTML),
                    self.loop
                )
                
                def handle_result(f):
                    try:
                        f.result()
                        self._consecutive_errors = 0
                    except Exception as e:
                        logger.error("Failed to send %s event: %s", kind, e)
                        self._consecutive_errors += 1
                
                fut.add_done_callback(handle_result)
                
            except Exception as e:
                logger.error("Failed to schedule event send: %s", e)
            return
        
        # Buffer non-critical messages
        with self._buf_lock:
            self._buf.append(text)
        self._schedule_flush()

    def send_photo(self, photo, caption: str | None = None, kind: str = "INFO"):
        """
        Send a photo to Telegram.
        
        Args:
            photo: Photo file object or bytes
            caption: Optional caption for the photo
            kind: Event type (affects delivery priority)
        """
        if self._closed:
            logger.warning("Messenger is closed; cannot send photo")
            return
            
        is_critical = kind == "ERROR" or (caption and "captcha" in caption.lower())
        
        if self.debug or is_critical:
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self._send_photo_with_retry(photo, caption),
                    self.loop
                )
                
                def handle_result(f):
                    try:
                        f.result()
                        self._consecutive_errors = 0
                    except Exception as e:
                        logger.error("Failed to send photo: %s", e)
                        self._consecutive_errors += 1
                
                fut.add_done_callback(handle_result)
                
            except Exception as e:
                logger.error("Failed to schedule photo send: %s", e)
        else:
            # Non-critical photos are dropped in production mode
            logger.debug("Skipping non-critical photo in production mode")
