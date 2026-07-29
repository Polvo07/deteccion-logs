"""
Generador de logs de acceso.

Crea un archivo de log con el formato estándar de Apache/Nginx, mezclando
tráfico normal con cuatro tipos de ataque. Al mismo tiempo escribe un segundo
archivo con la "verdad": qué IP hizo qué, para poder medir después si el
detector acierta.

Por qué se genera en vez de descargar: un log ajeno no dice cuáles líneas son
ataques, así que "detectar" sería adivinar. Al generarlo, se conoce la
respuesta exacta y se puede medir la precisión del detector con números, no con
impresiones. Es la misma idea que usan los datasets académicos de seguridad
(CSIC 2010, por ejemplo), que también son generados.

Uso:
    python datos/generar_logs.py
    python datos/generar_logs.py --lineas 50000 --semilla 7
"""

import argparse
import ipaddress
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ARCHIVO_LOG = RAIZ / "datos" / "acceso.log"
ARCHIVO_VERDAD = RAIZ / "datos" / "verdad.csv"

# --- Piezas para armar peticiones realistas ---------------------------------

# Páginas normales que pediría un visitante cualquiera.
RUTAS_NORMALES = [
    "/", "/index.html", "/productos", "/productos/123", "/productos/456",
    "/nosotros", "/contacto", "/blog", "/blog/como-empezar", "/carrito",
    "/css/estilo.css", "/js/app.js", "/img/logo.png", "/favicon.ico",
    "/api/productos", "/api/usuario/perfil", "/buscar?q=zapatos",
]

# Navegadores reales. Un visitante normal se identifica con uno de estos.
NAVEGADORES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/604.1",
]

# Rutas que solo busca un atacante: paneles de administración, archivos de
# configuración, respaldos olvidados. Un visitante normal nunca pide esto.
RUTAS_ESCANEO = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/.git/config", "/config.php", "/backup.sql", "/backup.zip",
    "/shell.php", "/cmd.php", "/.htaccess", "/server-status", "/api/v1/admin",
    "/console", "/manager/html", "/solr/admin", "/actuator/env", "/debug",
]

# Cargas de inyección SQL: intentan engañar a la base de datos.
INYECCIONES_SQL = [
    "/producto?id=1' OR '1'='1",
    "/producto?id=1 UNION SELECT username,password FROM users",
    "/login?user=admin'--",
    "/buscar?q='; DROP TABLE usuarios;--",
    "/producto?id=1 AND SLEEP(5)",
    "/api/user?id=-1' UNION SELECT NULL,version()--",
]

# Herramientas automáticas de ataque se identifican con estos nombres.
AGENTES_MALICIOSOS = [
    "sqlmap/1.7", "Nikto/2.5.0", "Nmap Scripting Engine",
    "acunetix-wvs", "Mozilla/5.0 (compatible; Nmap)", "curl/7.88.1",
]


def ip_aleatoria(rng):
    """Genera una IP pública cualquiera, evitando rangos privados."""
    while True:
        n = rng.randint(1, 0xFFFFFFFF)
        ip = ipaddress.IPv4Address(n)
        if ip.is_global:
            return str(ip)


def linea_log(ip, momento, metodo, ruta, codigo, tam, agente):
    """
    Arma una línea en el formato combinado de Apache/Nginx.

    Formato:
    IP - - [fecha] "METODO ruta HTTP/1.1" codigo tamaño "referer" "navegador"

    Es el formato estándar real. El detector tendrá que parsear exactamente
    esto, igual que haría con un log de producción.
    """
    # Se fija +0000 a mano: sin zona horaria el formato no coincide con el de un
    # log real de Apache y el parser del siguiente paso lo rechazaría.
    fecha = momento.strftime("%d/%b/%Y:%H:%M:%S") + " +0000"
    return (f'{ip} - - [{fecha}] "{metodo} {ruta} HTTP/1.1" '
            f'{codigo} {tam} "-" "{agente}"')


def generar(n_lineas, semilla, dificil=False):
    rng = random.Random(semilla)
    inicio = datetime(2026, 3, 1, 8, 0, 0)

    lineas = []          # (momento, texto_del_log)
    verdad = []          # (ip, tipo_de_actor) para medir después

    # --- 1. Tráfico normal: la gran mayoría -------------------------------
    # Un puñado de visitantes legítimos, cada uno pidiendo varias páginas.
    n_normales = int(n_lineas * 0.85)
    visitantes = [ip_aleatoria(rng) for _ in range(max(1, n_normales // 12))]
    for ip in visitantes:
        verdad.append((ip, "normal"))
    for _ in range(n_normales):
        ip = rng.choice(visitantes)
        momento = inicio + timedelta(seconds=rng.randint(0, 6 * 3600))
        ruta = rng.choice(RUTAS_NORMALES)
        codigo = rng.choices([200, 200, 200, 304, 404], weights=[70, 10, 10, 5, 5])[0]
        tam = rng.randint(200, 8000)
        agente = rng.choice(NAVEGADORES)
        lineas.append((momento, linea_log(ip, momento, "GET", ruta, codigo, tam, agente)))

    # --- 2. Fuerza bruta: una IP intenta entrar muchas veces --------------
    # Muchos POST al login en poco tiempo, casi todos fallando (401).
    for _ in range(3):
        ip = ip_aleatoria(rng)
        verdad.append((ip, "fuerza_bruta"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 5 * 3600))
        for i in range(rng.randint(40, 90)):
            momento = arranque + timedelta(seconds=i * rng.randint(1, 3))
            codigo = rng.choices([401, 401, 401, 200], weights=[85, 5, 5, 5])[0]
            agente = rng.choice(NAVEGADORES)
            lineas.append((momento, linea_log(ip, momento, "POST", "/login", codigo, 180, agente)))

    # --- 3. Escaneo: una IP busca puertas olvidadas -----------------------
    # Pide muchas rutas sensibles distintas, la mayoría inexistentes (404).
    for _ in range(3):
        ip = ip_aleatoria(rng)
        verdad.append((ip, "escaneo"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 5 * 3600))
        rutas = rng.sample(RUTAS_ESCANEO, rng.randint(12, len(RUTAS_ESCANEO)))
        for i, ruta in enumerate(rutas):
            momento = arranque + timedelta(seconds=i * rng.randint(1, 2))
            codigo = rng.choices([404, 404, 403, 200], weights=[80, 5, 10, 5])[0]
            agente = rng.choice(AGENTES_MALICIOSOS)
            lineas.append((momento, linea_log(ip, momento, "GET", ruta, codigo, 150, agente)))

    # --- 4. Inyección SQL: cargas maliciosas en los parámetros ------------
    for _ in range(2):
        ip = ip_aleatoria(rng)
        verdad.append((ip, "inyeccion_sql"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 5 * 3600))
        for i in range(rng.randint(8, 20)):
            momento = arranque + timedelta(seconds=i * rng.randint(1, 4))
            ruta = rng.choice(INYECCIONES_SQL)
            codigo = rng.choices([200, 500, 403], weights=[50, 30, 20])[0]
            agente = rng.choice(AGENTES_MALICIOSOS)
            lineas.append((momento, linea_log(ip, momento, "GET", ruta, codigo, 300, agente)))

    # --- 5. Volumen anómalo: una IP genera un pico de tráfico -------------
    # Como un scraper agresivo: cientos de peticiones muy seguidas.
    for _ in range(2):
        ip = ip_aleatoria(rng)
        verdad.append((ip, "volumen"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 5 * 3600))
        for i in range(rng.randint(300, 600)):
            momento = arranque + timedelta(seconds=i * rng.choice([0, 0, 1]))
            ruta = rng.choice(RUTAS_NORMALES)
            agente = rng.choice(NAVEGADORES)
            lineas.append((momento, linea_log(ip, momento, "GET", ruta, 200, rng.randint(200, 5000), agente)))

    # --- 6. MODO DIFÍCIL: casos que engañan a un detector ingenuo ---------
    # Se activa con --dificil. Añade dos clases de casos límite que existen en
    # el tráfico real y que separan un buen detector de uno de juguete.
    if dificil:
        # (a) Atacante SIGILOSO de fuerza bruta: en vez de 80 intentos rápidos,
        #     hace 15 muy espaciados. Queda POR DEBAJO del umbral de 20, así
        #     que el detector actual lo va a dejar pasar. Es un falso negativo
        #     esperado, y sirve para mostrar el límite del umbral fijo.
        ip = ip_aleatoria(rng)
        verdad.append((ip, "fuerza_bruta_lenta"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 3 * 3600))
        for i in range(15):
            momento = arranque + timedelta(minutes=i * 12)  # uno cada 12 min
            agente = rng.choice(NAVEGADORES)
            lineas.append((momento, linea_log(ip, momento, "POST", "/login", 401, 180, agente)))

        # (b) Escáner SIGILOSO: pide solo 6 rutas sensibles, bajo el umbral de
        #     10. También debería escaparse. Otro falso negativo con propósito.
        ip = ip_aleatoria(rng)
        verdad.append((ip, "escaneo_lento"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 3 * 3600))
        for i, ruta in enumerate(rng.sample(RUTAS_ESCANEO, 6)):
            momento = arranque + timedelta(minutes=i * 8)
            lineas.append((momento, linea_log(ip, momento, "GET", ruta, 404, 150,
                                              rng.choice(NAVEGADORES))))

        # (c) Usuario NORMAL pero intenso: un desarrollador o un cliente muy
        #     activo que hace muchas peticiones legítimas. Se parece a "volumen"
        #     pero es inocente. Si el detector lo acusa, es un FALSO POSITIVO.
        ip = ip_aleatoria(rng)
        verdad.append((ip, "normal"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 4 * 3600))
        for i in range(180):
            momento = arranque + timedelta(seconds=i * rng.randint(2, 8))
            ruta = rng.choice(RUTAS_NORMALES)
            codigo = rng.choices([200, 200, 304, 404], weights=[80, 10, 5, 5])[0]
            lineas.append((momento, linea_log(ip, momento, "GET", ruta, codigo,
                                              rng.randint(200, 6000), rng.choice(NAVEGADORES))))

        # (d) Usuario NORMAL con algún 404 honesto: siguió enlaces rotos del
        #     propio sitio. Tiene 404s pero de rutas NORMALES, no sensibles.
        #     Un buen detector no debe confundirlo con un escáner.
        ip = ip_aleatoria(rng)
        verdad.append((ip, "normal"))
        arranque = inicio + timedelta(seconds=rng.randint(0, 4 * 3600))
        for i in range(12):
            momento = arranque + timedelta(minutes=i * 3)
            ruta = rng.choice(RUTAS_NORMALES)  # rutas normales, no sensibles
            codigo = 404 if i % 2 else 200
            lineas.append((momento, linea_log(ip, momento, "GET", ruta, codigo, 400,
                                              rng.choice(NAVEGADORES))))

    # --- Ordenar por tiempo, como sería un log real -----------------------
    lineas.sort(key=lambda par: par[0])

    ARCHIVO_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(ARCHIVO_LOG, "w", encoding="utf-8") as f:
        for _, texto in lineas:
            f.write(texto + "\n")

    with open(ARCHIVO_VERDAD, "w", encoding="utf-8") as f:
        f.write("ip,tipo\n")
        for ip, tipo in verdad:
            f.write(f"{ip},{tipo}\n")

    return len(lineas), verdad


def main():
    parser = argparse.ArgumentParser(description="Genera un log de acceso con ataques etiquetados.")
    parser.add_argument("--lineas", type=int, default=20000,
                        help="Aproximado de líneas de tráfico normal (por defecto 20000).")
    parser.add_argument("--semilla", type=int, default=42,
                        help="Semilla aleatoria para que el resultado sea reproducible.")
    parser.add_argument("--dificil", action="store_true",
                        help="Añade casos límite: atacantes sigilosos y usuarios intensos.")
    args = parser.parse_args()

    total, verdad = generar(args.lineas, args.semilla, args.dificil)

    print(f"[log]    {total:,} líneas  ->  {ARCHIVO_LOG}")
    print(f"[verdad] {len(verdad)} actores etiquetados  ->  {ARCHIVO_VERDAD}")
    print()
    conteo = {}
    for _, tipo in verdad:
        conteo[tipo] = conteo.get(tipo, 0) + 1
    print("Actores por tipo:")
    for tipo, n in sorted(conteo.items()):
        print(f"  {tipo:<16s} {n}")
    print("\nSiguiente paso: bash triage/triage.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
