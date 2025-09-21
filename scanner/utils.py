from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import List

def inject_param(url: str, payload: str, param: str) -> str:
    parts = list(urlparse(url))
    query = dict(parse_qsl(parts[4], keep_blank_values=True))
    if param in query:
        query[param] = query[param] + payload
    parts[4] = urlencode(query, doseq=True)
    return urlunparse(parts)


def list_query_params(url: str) -> List[str]:
    parts = urlparse(url)
    return list(dict(parse_qsl(parts.query, keep_blank_values=True)).keys())
