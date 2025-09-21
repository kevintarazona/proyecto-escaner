import requests
from typing import Dict, Optional, Tuple

DEFAULT_HEADERS = {"User-Agent": "VulnScanner/0.1 (+https://example.com)"}

class HttpClient:
    def __init__(self, timeout: int = 10, headers: Optional[Dict[str, str]] = None):
        self.timeout = timeout
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        self.session.headers.update(DEFAULT_HEADERS)

    def get(self, url: str, params: Optional[Dict] = None) -> Tuple[int, str]:
        resp = self.session.get(url, params=params, timeout=self.timeout, verify=False)
        return resp.status_code, resp.text

    def post(self, url: str, data: Dict, headers: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        resp = self.session.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
        return resp.status_code, resp.text
