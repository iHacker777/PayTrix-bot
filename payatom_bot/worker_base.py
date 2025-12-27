# payatom_bot/worker_base.py
from __future__ import annotations
import traceback
import os
import time
import threading
from io import BytesIO
from typing import Optional, Callable
from datetime import datetime  # 🔹 NEW

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from .messaging import Messenger


class BaseWorker(threading.Thread):
    """
    Shared Selenium/Telegram scaffolding for all bank workers.
    Handles: Chrome profile, stop flag, basic retry wrapper, screenshots, and logging.
    Concrete subclasses should implement their own run() which calls:
      - self._run_with_retries(step, label)
      - self.screenshot_all_tabs(reason)
    """

    def __init__(
        self,
        *,
        bot,
        chat_id: int,
        alias: str,
        cred: dict,
        messenger: Messenger,
        profile_dir: str,
    ):
        super().__init__(daemon=True)
        self.bot = bot
        self.chat_id = chat_id
        self.alias = alias
        self.cred = cred
        self.msgr = messenger
        self.profile_dir = profile_dir

        self.stop_evt = threading.Event()
        self.last_balance: Optional[str] = None
        self.last_upload_at: Optional[datetime] = None  # 🔹 NEW: last AutoBank upload time

        download_root = os.path.join(os.getcwd(), "downloads", alias)
        os.makedirs(download_root, exist_ok=True)
        self.download_dir = download_root

        opts = webdriver.ChromeOptions()
        # opts.add_argument("--headless=new")
        # opts.add_argument("--disable-gpu")
        opts.add_argument(f"--user-data-dir={profile_dir}")
        opts.add_argument("--start-maximized")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--allow-insecure-localhost")
        opts.add_argument("--ignore-ssl-errors")

        prefs = {
            "download.default_directory": download_root,
            "download.prompt_for_download": False,
            "profile.default_content_setting_values.automatic_downloads": 1,
        }
        opts.add_experimental_option("prefs", prefs)

        self.driver = webdriver.Chrome(options=opts)
        self.driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
        self.driver.execute_cdp_cmd("Network.clearBrowserCache", {})
        self.driver.execute_script(
            "window.localStorage.clear(); window.sessionStorage.clear();"
        )

    # ———————————————————
    # Logging helpers
    # ———————————————————
    def info(self, msg: str) -> None:
        # 🔹 Detect successful AutoBank upload and mark timestamp
        kind = "INFO"
        if "AutoBank upload succeeded" in msg:
            try:
                self.last_upload_at = datetime.now()
            except Exception:
                self.last_upload_at = None
            kind = "UPLOAD_OK"  # also treated as critical in Messenger
        self.msgr.send_event(f"[{self.alias}] {msg}", kind)

    def error(self, msg: str) -> None:
        self.msgr.send_event(f"[{self.alias}] {msg}", "ERROR")

    # ———————————————————
    # Control
    # ———————————————————
    def stop(self):
        """Set stop flag and close browser."""
        self.stop_evt.set()
        try:
            self.driver.quit()
        except Exception:
            pass

    # ———————————————————
    # Retry wrapper
    # ———————————————————
    def _run_with_retries(
        self,
        func: Callable[[], None],
        label: str,
        *,
        max_retries: int = 3,
        retry_sleep: float = 5.0,
    ) -> None:
        """
        Run `func` with basic retries, screenshots, and a detailed error message.
        Raises the last exception if all attempts fail.
        """
        attempt = 0

        while not self.stop_evt.is_set() and attempt < max_retries:
            try:
                return func()
            except Exception as e:
                attempt += 1
                tb = traceback.format_exc()
                msg = (
                    "⚠️ Opps! There seems to be an issue.\n"
                    "Please contact the dev team with the details below.\n\n"
                    f"Context: {label}\n"
                    f"Error: {type(e).__name__}: {e}\n"
                    f"Traceback:\n{tb}"
                )
                self.error(msg)

                try:
                    self.screenshot_all_tabs(f"{label} failure (attempt {attempt})")
                except Exception:
                    pass

                if attempt >= max_retries or self.stop_evt.is_set():
                    # Bubble up to the worker's outer loop (like IOBWorker.run / CanaraWorker.run)
                    raise

                time.sleep(retry_sleep)

    # ———————————————————
    # Screenshot helper
    # ———————————————————
    def screenshot_all_tabs(self, reason: str = "") -> None:
        """
        Capture all open tabs and send as photos.
        """
        for h in self.driver.window_handles:
            try:
                self.driver.switch_to.window(h)
                png = self.driver.get_screenshot_as_png()
                bio = BytesIO(png)
                which = self.driver.title or "unknown tab"
                caption = f"[{self.alias}] 📸 {which}"
                if reason:
                    caption += f" — {reason}"
                self.msgr.send_photo(bio, caption, kind="ERROR")
            except Exception:
                continue

    # ———————————————————
    # Download helper
    # ———————————————————
    def wait_newest_file(
        self,
        suffix: str,
        timeout: float = 60.0,
    ) -> Optional[str]:
        """
        Poll this worker's download_dir until a file with the given suffix appears,
        then return its full path. Returns None on timeout.
        """
        deadline = time.time() + timeout
        suffix = suffix.lower()
        latest_path: Optional[str] = None

        while time.time() < deadline and not self.stop_evt.is_set():
            try:
                files = [
                    f
                    for f in os.listdir(self.download_dir)
                    if f.lower().endswith(suffix)
                ]
            except FileNotFoundError:
                files = []

            if files:
                latest = max(
                    files,
                    key=lambda f: os.path.getctime(
                        os.path.join(self.download_dir, f)
                    ),
                )
                latest_path = os.path.join(self.download_dir, latest)
                break

            time.sleep(1.0)

        return latest_path
