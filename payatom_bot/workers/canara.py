# payatom_bot/workers/canara.py
from __future__ import annotations

import time
import traceback
from datetime import datetime, timedelta
from io import BytesIO
from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    ElementClickInterceptedException,
)

from ..worker_base import BaseWorker
from ..captcha_solver import TwoCaptcha
from ..autobank_client import AutoBankClient


class CanaraWorker(BaseWorker):
    """
    Canara Bank automation.

    - Logs in with username + password
    - Solves CAPTCHA via 2Captcha with Telegram fallback
    - Handles OTP via Telegram (6-digit code)
    - Loops: download CSV → upload to AutoBank ("Canara Bank") → update balance
    """

    LOGIN_URL = "https://online.canarabank.bank.in/?module=login"

    def __init__(
        self,
        *,
        bot,
        chat_id: int,
        alias: str,
        cred: dict,
        messenger,
        profile_dir: str,
        two_captcha: Optional[TwoCaptcha] = None,
    ):
        super().__init__(
            bot=bot,
            chat_id=chat_id,
            alias=alias,
            cred=cred,
            messenger=messenger,
            profile_dir=profile_dir,
        )
        self.wait = WebDriverWait(self.driver, 30)
        self.solver = two_captcha
        self.canara_win: Optional[str] = None

        # These are used by handlers/handlers/captcha.py
        self.captcha_code: Optional[str] = None
        self.otp_code: Optional[str] = None
        self._captcha_id: Optional[str] = None

    # ------------------------------------------------------------------
    # High-level loop
    # ------------------------------------------------------------------
    def run(self) -> None:
        self.info("🚀 Starting Canara Bank automation")
        try:
            while not self.stop_evt.is_set():
                try:
                    # Full login with retries
                    self._run_with_retries(self._login, "Canara login")

                    # Logged in; steady-state loop
                    while not self.stop_evt.is_set():
                        self._run_with_retries(
                            self._download_and_upload_statement,
                            "Canara statement",
                        )

                        # Balance is best-effort; do not kill the worker if it fails
                        try:
                            self._run_with_retries(
                                self._update_balance_from_summary,
                                "Canara balance",
                                max_retries=2,
                            )
                        except Exception as e:
                            self.error(
                                f"Canara balance step failed (non-fatal): {e!r}"
                            )

                        time.sleep(60)
                except Exception as e:
                    self._report_fatal(e, context="Canara outer loop")
                    time.sleep(5)
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # Error helper – "Opps!" + traceback
    # ------------------------------------------------------------------
    def _report_fatal(self, exc: Exception, *, context: str) -> None:
        tb = traceback.format_exc()
        msg = (
            "⚠️ Opps! There seems to be an issue.\n"
            "Please contact the dev team with the details below.\n\n"
            f"Context: {context}\n"
            f"Error: {type(exc).__name__}: {exc}\n"
            f"Traceback:\n{tb}"
        )
        self.error(msg)
        try:
            self.screenshot_all_tabs(f"{context} failure")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Login + CAPTCHA + OTP
    # ------------------------------------------------------------------
    def _login(self) -> None:
        d = self.driver
        w = self.wait

        # Always fresh navigation
        d.get(self.LOGIN_URL)
        self.canara_win = d.current_window_handle

        # Close any initial popup (top-right click + generic OK/Close)
        time.sleep(5)
        self._dismiss_initial_popups()
        # Username + password
        user = (self.cred.get("auth_id") or self.cred.get("username") or "").strip()
        if not user:
            raise RuntimeError("Missing username/auth_id for Canara login")

        user_input = w.until(
            EC.presence_of_element_located((By.ID, "login_username|input"))
        )
        user_input.clear()
        user_input.send_keys(user)

        pwd_input = w.until(
            EC.presence_of_element_located((By.ID, "login_password|input"))
        )
        pwd_input.clear()
        pwd_input.send_keys(self.cred["password"])

        # CAPTCHA image (#imageCaptcha img.customCaptcha)
        img = w.until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "#imageCaptcha img.customCaptcha")
            )
        )
        d.execute_script("arguments[0].scrollIntoView(true);", img)
        time.sleep(3)
        img = w.until(
            EC.visibility_of_element_located(
                (By.CSS_SELECTOR, "#imageCaptcha img.customCaptcha")
            )
        )
        img_bytes = img.screenshot_as_png

        # 1) Try 2Captcha
        self.info("🤖 Solving Canara CAPTCHA via 2Captcha…")
        solved = None
        self._captcha_id = None
        if self.solver and getattr(self.solver, "key", None):
            try:
                sol, cid = self.solver.solve(img_bytes)
                if sol:
                    solved = str(sol).strip()
                    self._captcha_id = cid
            except Exception as e:
                self.error(f"2Captcha.solve raised {type(e).__name__}: {e!r}")

        # 2) Fallback to Telegram/manual via captcha.py
        if solved:
            self.captcha_code = solved
            self.info(f"✅ CAPTCHA auto-solved: `{solved}`")
        else:
            self.captcha_code = None
            self.msgr.send_photo(
                BytesIO(img_bytes),
                f"[{self.alias}] 🔐 Please solve this CAPTCHA (Canara Bank login)",
                kind="CAPTCHA",
            )
            self.info("Waiting up to 180s for manual CAPTCHA via Telegram…")

            deadline = time.time() + 180
            while not self.stop_evt.is_set() and time.time() < deadline:
                # captcha.py will set self.captcha_code for ANY 4–8 A–Z/0–9 text
                if self.captcha_code:
                    solved = self.captcha_code.strip()
                    break
                time.sleep(0.5)

            if not solved:
                raise TimeoutException("CAPTCHA not solved (manual entry timeout)")

        # Fill captcha input (e4) and click LOGIN (e5)
        captcha_input = w.until(
            EC.presence_of_element_located((By.ID, "captchaid|input"))
        )
        captcha_input.clear()
        captcha_input.send_keys(solved)

        login_btn = self._find_clickable_by_span_text("LOGIN")
        if not login_btn:
            raise TimeoutException("LOGIN button not found on Canara login page")
        self._safe_click(login_btn)

        # OTP (if present)
        self._handle_otp_if_present()

        # Wait for Accounts & Services nav (e12)
        w.until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//span[contains(@class,'group-item-label') and contains(., 'Accounts & Services')]",
                )
            )
        )

        # Close welcome Ok popup (e11) if it appears
        self._dismiss_post_login_ok()

        self.logged_in = True
        self.info("✅ Logged in to Canara Bank")

    def _dismiss_initial_popups(self) -> None:
        d = self.driver
        # Generic "click top-right"
        try:
            d.execute_script(
                "var el = document.elementFromPoint(window.innerWidth-50, 50);"
                "if (el) el.click();"
            )
            time.sleep(0.3)
        except Exception:
            pass

        # Try common Ok / Close buttons very quickly
        for text in ("Ok", "OK", "Okay", "Close"):
            try:
                btn = WebDriverWait(d, 3).until(
                    EC.element_to_be_clickable(
                        (
                            By.XPATH,
                            f"//span[normalize-space(text())='{text}']"
                            "/ancestor::*[self::button or @role='button']",
                        )
                    )
                )
                self._safe_click(btn)
                break
            except TimeoutException:
                continue

    # Replace the _dismiss_post_login_ok method in canara.py with this version:

    def _dismiss_post_login_ok(self) -> None:
        d = self.driver
        try:
            # Multiple strategies to click the OK button
            # Strategy 1: Click the actual button element inside oj-button
            ok_button = WebDriverWait(d, 10).until(
                EC.presence_of_element_located(
                    (By.XPATH, "//oj-button[@id='pwdExpiryButton']//button[@class='oj-button-button oj-component-initnode']")
                )
            )
            self._safe_click(ok_button)
            self.info("✅ 'Ok' button clicked to dismiss post-login popup (strategy 1).")
        except TimeoutException:
            try:
                # Strategy 2: Click by the span text inside the button
                ok_button = WebDriverWait(d, 5).until(
                    EC.presence_of_element_located(
                        (By.XPATH, "//span[text()='Ok' and @class='oj-button-text']/ancestor::button")
                    )
                )
                self._safe_click(ok_button)
                self.info("✅ 'Ok' button clicked to dismiss post-login popup (strategy 2).")
            except TimeoutException:
                try:
                    # Strategy 3: Click the close button (X) on the modal header
                    close_btn = WebDriverWait(d, 5).until(
                        EC.element_to_be_clickable(
                            (By.CSS_SELECTOR, "a.modal-header__close")
                        )
                    )
                    self._safe_click(close_btn)
                    self.info("✅ Modal closed using X button (strategy 3).")
                except TimeoutException:
                    self.info("⚠️ 'Ok' button not found after login (all strategies failed).")

    def _handle_otp_if_present(self) -> None:
        d = self.driver

        # Detect OTP page (e6)
        try:
            WebDriverWait(d, 10).until(
                EC.presence_of_element_located(
                    (
                        By.XPATH,
                        "//span[contains(text(),'One Time Password (OTP)')]",
                    )
                )
            )
            otp_required = True
        except TimeoutException:
            otp_required = False

        if not otp_required:
            self.info("ℹ️ No OTP challenge detected for Canara login.")
            return

        self.info(
            "🔐 OTP challenge detected for Canara. "
            f"Send the OTP in Telegram (any 6-digit code) for alias `{self.alias}`."
        )

        otp_input = WebDriverWait(d, 30).until(
            EC.presence_of_element_located((By.ID, "otp|input"))
        )

        while not self.stop_evt.is_set():
            # captcha.py sets otp_code for ANY 6-digit number in any message
            if not self.otp_code:
                time.sleep(0.5)
                continue

            code = self.otp_code.strip()
            self.otp_code = None  # consume

            otp_input.clear()
            otp_input.send_keys(code)

            submit_btn = self._find_clickable_by_span_text("Submit")
            if not submit_btn:
                raise TimeoutException("Submit button not found on OTP page")
            self._safe_click(submit_btn)

            # Check for invalid OTP popup (e9 + e10)
            try:
                msg_span = WebDriverWait(d, 5).until(
                    EC.presence_of_element_located(
                        (
                            By.XPATH,
                            "//span[contains(@data-bind,'modalMessage')]",
                        )
                    )
                )
                text = (msg_span.text or "").strip().lower()
                if "invalid" in text:
                    self.info("❌ OTP invalid. Waiting for a new OTP…")
                    try:
                        ok_btn = WebDriverWait(d, 5).until(
                            EC.element_to_be_clickable(
                                (
                                    By.XPATH,
                                    "//span[normalize-space(text())='Okay']"
                                    "/ancestor::*[self::button or @role='button']",
                                )
                            )
                        )
                        self._safe_click(ok_btn)
                    except TimeoutException:
                        pass
                    continue  # wait for new OTP
            except TimeoutException:
                # No modal: assume OTP accepted → continue
                break

        if self.stop_evt.is_set():
            raise TimeoutException("Worker stopped while waiting for OTP")

    # ------------------------------------------------------------------
    # Statement download + AutoBank upload
    # ------------------------------------------------------------------
    def _download_and_upload_statement(self) -> None:
        d = self.driver
        w = self.wait

        if self.canara_win:
            d.switch_to.window(self.canara_win)

        # Navigate Account Statement → View/Download (e12–e14)
        self._open_statement_page()

        acct_no = (self.cred.get("account_number") or "").strip()
        if acct_no:
            self._select_account_number(acct_no)

        # View options: "Date Range" (e16)
        self._select_date_range_period()

        # Date logic:
        #   00:00–04:59 → from = yesterday, to = today
        #   05:00–23:59 → from = today, to = today
        now = datetime.now()
        if now.hour < 5:
            from_date = now.date() - timedelta(days=1)
            to_date = now.date()
        else:
            from_date = now.date()
            to_date = now.date()

        self._set_date_input("fromDate|input", from_date)  # e17
        self._set_date_input("todate|input", to_date)      # e18

        # Apply Filter (e19)
        apply_btn = self._find_clickable_by_span_text("Apply Filter")
        if not apply_btn:
            raise TimeoutException("Apply Filter button not found")
        self._safe_click(apply_btn)

        time.sleep(3)  # let table render

        # Output Format = CSV (e20)
        self._select_output_format_csv()

        # Download (e21)
        dl_btn = self._find_clickable_by_span_text("Download")
        if not dl_btn:
            raise TimeoutException("Download button not found")
        self._safe_click(dl_btn)

        # Wait for CSV in worker's download dir
        csv_path = self.wait_newest_file(".csv", timeout=90.0)
        if not csv_path:
            raise TimeoutException("Timed out waiting for Canara CSV download")

        # Upload CSV to AutoBank in a separate tab
        original = d.current_window_handle
        d.execute_script("window.open('about:blank');")
        upload_tab = [h for h in d.window_handles if h != original][-1]

        acct_no_val = acct_no
        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                d.switch_to.window(upload_tab)
                AutoBankClient(d).upload("Canara Bank", acct_no_val, csv_path)
                self.info(
                    f"✅ AutoBank upload (Canara) succeeded "
                    f"(attempt {attempt}/{max_attempts})"
                )
                break
            except Exception as e:
                self.error(
                    f"⚠️ AutoBank upload (Canara) failed "
                    f"(attempt {attempt}/{max_attempts}): {type(e).__name__}: {e}"
                )
                try:
                    self.screenshot_all_tabs("AutoBank upload failed (Canara)")
                except Exception:
                    pass
                if attempt == max_attempts:
                    try:
                        d.close()
                    except Exception:
                        pass
                    d.switch_to.window(original)
                    raise
                time.sleep(2)

        # Close upload tab, return to Canara
        try:
            d.switch_to.window(original)
            for h in list(d.window_handles):
                if h != original:
                    d.switch_to.window(h)
                    d.close()
            d.switch_to.window(original)
        except Exception:
            pass

    def _open_statement_page(self) -> None:
        d = self.driver
        w = self.wait

        # Accounts & Services (e12)
        try:
            acc_group = w.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//div[contains(@class,'oj-navigationlist-group-item')]"
                        "[.//span[contains(@class,'group-item-label') "
                        "and contains(.,'Accounts & Services')]]",
                    )
                )
            )
            self._safe_click(acc_group.find_element(By.XPATH, ".//a"))
        except Exception:
            pass  # non-fatal; menu may already be expanded

        # Account Statement (e13)
        stmt_link = w.until(
            EC.element_to_be_clickable(
                (
                    By.XPATH,
                    "//span[@class='oj-navigationlist-item-label' "
                    "and normalize-space(text())='Account Statement']",
                )
            )
        )
        self._safe_click(stmt_link.find_element(By.XPATH, "./ancestor::a[1]"))

        # View/Download Account Statement (e14)
        view_link = w.until(
            EC.element_to_be_clickable(
                (
                    By.XPATH,
                    "//span[@class='oj-navigationlist-item-label' "
                    "and normalize-space(text())='View/Download Account Statement']",
                )
            )
        )
        self._safe_click(view_link.find_element(By.XPATH, "./ancestor::a[1]"))

        # Wait for account dropdown (e15)
        w.until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//div[contains(@class,'oj-select-choice') "
                    "and @aria-label='Select Account Number']",
                )
            )
        )

    def _select_account_number(self, acct_no: str) -> None:
        d = self.driver

        try:
            choice = self.wait.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//div[contains(@class,'oj-select-choice') "
                        "and @aria-label='Select Account Number']",
                    )
                )
            )
        except TimeoutException:
            self.info("Account dropdown not found; using default account.")
            return

        self._safe_click(choice)
        time.sleep(0.5)

        try:
            option = self.wait.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//ul[contains(@id,'oj-listbox-results') and @role='listbox']"
                        f"//li//div[contains(normalize-space(.),'{acct_no}')]",
                    )
                )
            )
            self._safe_click(option)
        except TimeoutException:
            self.info(
                f"Could not find account {acct_no!r} in dropdown; "
                "using existing selection."
            )

    def _select_date_range_period(self) -> None:
        d = self.driver
        try:
            choice = self.wait.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//div[contains(@class,'account-statement-left__selectPeriod')]"
                        "//div[contains(@class,'oj-select-choice')]",
                    )
                )
            )
        except TimeoutException:
            raise TimeoutException("Period (selectPeriod) dropdown not found")

        self._safe_click(choice)
        time.sleep(0.5)

        try:
            option = self.wait.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//ul[contains(@id,'selectPeriod') and contains(@id,'-list')]"
                        "//li//div[normalize-space(text())='Date Range']",
                    )
                )
            )
            self._safe_click(option)
        except TimeoutException:
            raise TimeoutException("'Date Range' option not found in Period dropdown")

    def _set_date_input(self, input_id: str, dt) -> None:
        d = self.driver
        val = dt.strftime("%d/%m/%Y")
        inp = self.wait.until(EC.presence_of_element_located((By.ID, input_id)))
        d.execute_script("arguments[0].focus();", inp)
        try:
            inp.clear()
        except Exception:
            d.execute_script("arguments[0].value = '';", inp)
        inp.send_keys(val)

    def _select_output_format_csv(self) -> None:
        d = self.driver
        try:
            choice = self.wait.until(
                EC.element_to_be_clickable((By.ID, "ojChoiceId_myMenu"))
            )
        except TimeoutException:
            raise TimeoutException("Output format dropdown (myMenu) not found")

        self._safe_click(choice)
        time.sleep(0.5)

        try:
            opt = self.wait.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//ul[@id='myMenu-list']//li//div[normalize-space(text())='CSV']",
                    )
                )
            )
            self._safe_click(opt)
        except TimeoutException:
            raise TimeoutException("'CSV' option not found in Output Format dropdown")

    # ------------------------------------------------------------------
    # Balance from Account Summary (e22–e24)
    # ------------------------------------------------------------------
    def _update_balance_from_summary(self) -> None:
        d = self.driver
        w = self.wait

        if self.canara_win:
            d.switch_to.window(self.canara_win)

        # Account Summary nav (e22)
        try:
            acc_summary_link = w.until(
                EC.element_to_be_clickable(
                    (
                        By.XPATH,
                        "//a[@aria-label='Account Summary']",
                    )
                )
            )
            self._safe_click(acc_summary_link)
        except TimeoutException:
            raise TimeoutException("Account Summary link not found")

        acct_no = (self.cred.get("account_number") or "").strip()
        if not acct_no:
            raise RuntimeError("Missing account_number in credentials for Canara Bank")

        # Row containing account number (e23)
        row_xpath = (
            "//table[contains(@id,'DDSummaryTable')]//tr"
            f"[.//span[normalize-space(text())='{acct_no}']]"
        )
        row = w.until(EC.presence_of_element_located((By.XPATH, row_xpath)))

        # Balance cell on that row (e24)
        try:
            bal_cell = row.find_element(By.XPATH, ".//td[contains(@class,'amount')]")
            bal_text = bal_cell.text.strip()
        except NoSuchElementException:
            bal_text = ""

        if bal_text:
            self.last_balance = bal_text
            self.info(f"💰 Canara available balance: {bal_text}")
        else:
            self.info("⚠️ Could not extract available balance for Canara.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _safe_click(self, elem) -> None:
        d = self.driver
        try:
            elem.click()
        except ElementClickInterceptedException:
            d.execute_script("arguments[0].click();", elem)
        except Exception:
            d.execute_script("arguments[0].click();", elem)

    def _find_clickable_by_span_text(self, text: str):
        try:
            span = self.wait.until(
                EC.presence_of_element_located(
                    (By.XPATH, f"//span[normalize-space(text())='{text}']")
                )
            )
            try:
                btn = span.find_element(
                    By.XPATH, "./ancestor::*[self::button or @role='button'][1]"
                )
            except NoSuchElementException:
                btn = span
            return btn
        except TimeoutException:
            return None

    # Optional: direct hook if you ever want alias-specific OTP setter
    def set_otp(self, otp: str) -> None:
        otp = (otp or "").strip()
        if len(otp) < 4:
            self.info("Ignoring too-short OTP payload.")
            return
        self.otp_code = otp
        self.info("🔑 OTP received for Canara.")
