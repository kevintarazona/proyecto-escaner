from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import List, Dict


def extract_forms(html: str, base_url: str) -> List[Dict]:
    soup = BeautifulSoup(html, 'lxml')
    forms_data = []
    for form in soup.find_all('form'):
        method = (form.get('method') or 'get').lower()
        action = form.get('action') or ''
        full_action = urljoin(base_url, action)
        inputs = []
        for inp in form.find_all(['input','textarea']):
            name = inp.get('name')
            if not name:
                continue
            itype = (inp.get('type') or 'text').lower()
            value = inp.get('value') or ''
            inputs.append({'name': name, 'type': itype, 'value': value})
        forms_data.append({
            'method': method,
            'action': full_action,
            'inputs': inputs
        })
    return forms_data
