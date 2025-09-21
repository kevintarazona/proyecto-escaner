from flask import Flask, render_template, request
from scanner.http_client import HttpClient
from scanner.forms_extractor import extract_forms
from scanner.report import ScanReport
from scanner.sqli_scanner import scan_sqli
from scanner.xss_scanner import scan_xss

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target_url')
    if not target:
        return render_template('index.html', error='Debe ingresar una URL')

    client = HttpClient()
    status, body = client.get(target)
    forms = extract_forms(body, target)

    report = ScanReport(target_url=target)
    # Lanzar escaneos
    scan_sqli(target, body, report, client)
    scan_xss(target, body, report, client)

    return render_template('results.html', report=report.summary(), forms=forms)

if __name__ == '__main__':
    app.run(debug=True)
