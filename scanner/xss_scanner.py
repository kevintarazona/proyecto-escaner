from .payloads import XSS_PAYLOADS
from .report import ScanReport
from .utils import list_query_params, inject_param
from .http_client import HttpClient

MARKERS = ["<script>alert('xss')</script>", "alert(1)"]


def scan_xss(base_url: str, html: str, report: ScanReport, client: HttpClient):
    params = list_query_params(base_url)
    for p in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_param(base_url, payload, p)
            _, body = client.get(test_url)
            if payload in body or any(m in body for m in MARKERS):
                report.add('XSS', test_url, payload, 'Reflejo directo encontrado')
                break
