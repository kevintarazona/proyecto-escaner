from typing import List
from .payloads import SQLI_PAYLOADS, ERROR_SIGNATURES
from .utils import list_query_params, inject_param
from .report import ScanReport
from .http_client import HttpClient


def scan_sqli(base_url: str, html: str, report: ScanReport, client: HttpClient):
    # 1. Probar parámetros en la URL directa
    params = list_query_params(base_url)
    for p in params:
        original_url = base_url
        for payload in SQLI_PAYLOADS:
            test_url = inject_param(original_url, payload, p)
            status, body = client.get(test_url)
            lowered = body.lower()
            if any(sig in lowered for sig in ERROR_SIGNATURES):
                report.add('SQLi', test_url, payload, 'Error SQL detectado')
                break  # Evitar inundar con muchos payloads sobre mismo param

    # 2. Formularios (solo GET/POST simples)
    # html ya fue pasado, se pueden reusar forms fuera si se desea modularizar.
