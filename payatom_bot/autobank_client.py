from __future__ import annotations
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support import expected_conditions as EC
#All Bank Workers will use this code to upload files to autobank, so be carefull when changing this. 
# Have to change the code here when endpoint is generated. Comment all current code when that happens.
class AutoBankClient:
    def __init__(self, driver, wait_secs: int = 20):
        self.driver = driver
        self.wait = WebDriverWait(driver, wait_secs)

    def ensure_logged_in(self) -> None:
        d = self.driver
        d.get("https://autostatement.ipay365.net/operator_index.php")
        try:
            self.wait.until(EC.presence_of_element_located((By.ID, "sidebar")))
            return
        except TimeoutException:
            pass
        try:
            btn = self.wait.until(EC.element_to_be_clickable((
                By.XPATH,
                "//a[contains(@class,'auth-form-btn')] | //button[contains(@onclick,'getToken') or normalize-space()='Sign In' or normalize-space()='SIGN IN']"
            )))
            ActionChains(d).move_to_element(btn).pause(0.05).click(btn).perform()
            self.wait.until(EC.presence_of_element_located((By.ID, "sidebar")))
        except TimeoutException:
            # Already logged or different layout; continue
            pass

    def upload(self, bank_label: str, account_number: str, file_path: str) -> None:
        d = self.driver
        self.ensure_logged_in()
        d.get("https://autostatement.ipay365.net/bankupload.php")

        self.wait.until(EC.presence_of_element_located((By.ID, "drop-zone")))
        Select(self.wait.until(EC.presence_of_element_located((By.ID, "bank")))).select_by_visible_text(bank_label)

        acct = self.wait.until(EC.presence_of_element_located((By.ID, "account_number")))
        acct.clear(); acct.send_keys(account_number)

        self.wait.until(EC.presence_of_element_located((By.ID, "file_input"))).send_keys(file_path)

        # Wait for a common success condition; adjust selectors per the page.
        # Sometimes autobank has issues with showing the favicon so cannot rely on this alone. 
        self.wait.until(
            EC.any_of(
                EC.visibility_of_element_located((By.CSS_SELECTOR, ".swal2-icon-success")),
                EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "Upload successful")
            )
        )
