# Vuln Scanner Demo (SQLi & XSS)

Proyecto educativo minimalista para la universidad que  realiza pruebas básicas de detección de posibles vulnerabilidades de **Inyección SQL (reflejada en parámetros)** y **XSS reflejado** sobre una URL objetivo.

> ADVERTENCIA: Solo usar sobre sistemas para los que tengas autorización explícita. El uso indebido puede ser ilegal. Este software se entrega "tal cual" sin garantías.

## Características
- Interfaz web simple con Flask
- Detección muy básica de errores SQL visibles en la respuesta
- Búsqueda de reflejo de payloads XSS simples
- Extracción de formularios (método y campos) para enumeración
- Reporte resumido en tabla

## Limitaciones
- No detecta SQLi ciega ni tiempo basada
- No ejecuta un navegador real (no DOM XSS complejo)
- No gestiona autenticación, cookies avanzadas ni CSRF tokens
- Lista de payloads muy corta (solo ejemplo)

## Requisitos
Python 3.10+

Instalar dependencias:
```
pip install -r requirements.txt
```

## Uso
Ejecutar la aplicación:
```
python app.py
```
Abrir en el navegador: http://127.0.0.1:5000

Ingresar una URL con parámetros, por ejemplo:
```
https://ejemplo.com/product.php?id=1
```

## Estructura
```
scanner/
  http_client.py
  forms_extractor.py
  payloads.py
  report.py
  sqli_scanner.py
  utils.py
  xss_scanner.py
app.py
templates/
static/
```

## Tests
Ejecutar tests (si tienes pytest instalado):
```
pytest -q
```

## Ampliaciones Sugeridas
- Agregar soporte para POST y envío automático de formularios
- Payloads cargados desde archivo externo
- Selenium/Playwright para XSS DOM / almacenado
- Reporte en JSON exportable
- Logging estructurado y niveles de verbosidad

## Ética
El objetivo es educativo: comprender cómo funcionan las inyecciones básicas y la importancia de validar/escapar entradas y usar consultas parametrizadas.
