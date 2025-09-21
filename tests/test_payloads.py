from scanner.payloads import SQLI_PAYLOADS, XSS_PAYLOADS

def test_payloads_min_sizes():
    assert len(SQLI_PAYLOADS) >= 20, "Se esperaban >=20 payloads SQLi"
    assert len(XSS_PAYLOADS) >= 15, "Se esperaban >=15 payloads XSS"

def test_no_duplicate_sqli():
    assert len(SQLI_PAYLOADS) == len(set(SQLI_PAYLOADS)), "Duplicados en SQLI_PAYLOADS"

def test_no_duplicate_xss():
    assert len(XSS_PAYLOADS) == len(set(XSS_PAYLOADS)), "Duplicados en XSS_PAYLOADS"
