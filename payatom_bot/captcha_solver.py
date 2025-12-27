from __future__ import annotations
import base64
import time
import requests
from typing import Tuple, Optional
# 2CCaptcha API code that pings the 2Captcha service to solve captchas.
# 2Caotcha wrong captcha reporting is not working sometimes, have to check later.
# Have to fix IOB captcha only recieving lower case letters even after setting regsense to true. Currently forcing uppercase in IOBWorker but have to check why not working here.
class TwoCaptcha:
    def __init__(self, api_key: str) -> None:
        self.key = api_key

    def solve(
        self,
        image_bytes: bytes,
        *,
        min_len: Optional[int] = None,
        max_len: Optional[int] = None,
        regsense: bool = True
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns (solution_text, captcha_id) or (None, None)
        """
        data = {
            "method": "base64",
            "key": self.key,
            "body": base64.b64encode(image_bytes).decode(),
            "json": 1
        }
        if regsense:
            data["regsense"] = 1
        if min_len:
            data["min_len"] = min_len
        if max_len:
            data["max_len"] = max_len

        r = requests.post("http://2captcha.com/in.php", data=data, timeout=30)
        r.raise_for_status()
        jin = r.json()
        if jin.get("status") != 1:
            return None, None

        cid = str(jin["request"])
        # poll
        for _ in range(30):
            time.sleep(5)
            res = requests.get(
                "http://2captcha.com/res.php",
                params={"key": self.key, "action": "get", "id": cid, "json": 1},
                timeout=15
            )
            res.raise_for_status()
            jout = res.json()
            if jout.get("status") == 1:
                return str(jout["request"]), cid
            if jout.get("request") != "CAPCHA_NOT_READY":
                return None, None
        return None, None

    def report_bad(self, captcha_id: str) -> None:
        try:
            requests.get(
                "http://2captcha.com/res.php",
                params={"key": self.key, "action": "reportbad", "id": captcha_id},
                timeout=10
            )
        except Exception:
            pass
