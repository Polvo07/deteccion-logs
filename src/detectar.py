"""
Motor de detección.

Analiza la tabla de peticiones y marca las IPs que se comportan como atacantes.
Cada tipo de ataque tiene su propia función de detección, con un umbral que se
puede ajustar. La idea es detectar por COMPORTAMIENTO, no por atacar nada:
mirar qué hace cada IP y decidir si ese patrón es normal o no.

Uso:
    python src/detectar.py
"""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leer_log

# --- Umbrales de detección ---------------------------------------------------
# Están todos juntos y con nombre para que se puedan ajustar sin tocar la
# lógica. Cambiar estos números cambia qué tan sensible es el detector.

MIN_FALLOS_LOGIN = 20      # 401s de una IP para considerarla fuerza bruta
MIN_RUTAS_404 = 10         # rutas inexistentes distintas para considerarla escaneo
FACTOR_VOLUMEN = 10        # cuántas veces sobre la mediana para ser "volumen anómalo"

# Palabras que, en la ruta de una petición, delatan un intento de inyección SQL.
PATRONES_SQL = [
    "union select", "or '1'='1", "drop table", "sleep(", "--",
    "' or ", "information_schema", "version()", "' and ",
]

# Herramientas de ataque reconocibles por su user-agent.
HERRAMIENTAS_ATAQUE = [
    "sqlmap", "nikto", "nmap", "acunetix", "netsparker", "masscan", "wpscan",
]


def detectar_fuerza_bruta(tabla):
    """
    Fuerza bruta: una IP que falla al entrar muchas veces.

    Un usuario normal se equivoca de contraseña dos o tres veces. Cuarenta
    fallos seguidos es un programa probando combinaciones.
    """
    fallos = tabla[tabla["codigo"] == 401]
    conteo = fallos.groupby("ip").size()
    sospechosas = conteo[conteo >= MIN_FALLOS_LOGIN]
    return {ip: {"tipo": "fuerza_bruta", "evidencia": f"{n} intentos de login fallidos"}
            for ip, n in sospechosas.items()}


def detectar_escaneo(tabla):
    """
    Escaneo: una IP que pide muchas rutas distintas que no existen.

    Buscar puertas olvidadas deja un rastro claro: montones de 404 hacia rutas
    diferentes. Un usuario normal repite las pocas páginas que le interesan.
    """
    no_encontradas = tabla[tabla["codigo"] == 404]
    rutas_distintas = no_encontradas.groupby("ip")["ruta"].nunique()
    sospechosas = rutas_distintas[rutas_distintas >= MIN_RUTAS_404]
    return {ip: {"tipo": "escaneo", "evidencia": f"{n} rutas inexistentes distintas"}
            for ip, n in sospechosas.items()}


def detectar_inyeccion_sql(tabla):
    """
    Inyección SQL: peticiones cuyo texto contiene patrones de base de datos.

    Se busca en la ruta completa. Basta una petición con un patrón claro para
    marcar la IP: nadie escribe "UNION SELECT" en una búsqueda por accidente.
    """
    ruta_min = tabla["ruta"].str.lower()
    marca = pd.Series(False, index=tabla.index)
    for patron in PATRONES_SQL:
        marca = marca | ruta_min.str.contains(patron, regex=False, na=False)

    sospechosas = tabla[marca].groupby("ip").size()
    return {ip: {"tipo": "inyeccion_sql", "evidencia": f"{n} peticiones con patrones SQL"}
            for ip, n in sospechosas.items()}


def detectar_volumen(tabla):
    """
    Volumen anómalo: una IP que genera muchísimo más tráfico que las demás.

    Se compara cada IP contra la mediana de todas. Se usa la mediana y no el
    promedio porque el promedio ya estaría inflado por los propios atacantes;
    la mediana refleja el visitante típico. Es la misma lección del proyecto de
    contratos: en distribuciones sesgadas, la mediana describe lo normal.
    """
    peticiones = tabla.groupby("ip").size()
    mediana = peticiones.median()
    limite = mediana * FACTOR_VOLUMEN
    sospechosas = peticiones[peticiones > limite]
    return {ip: {"tipo": "volumen",
                 "evidencia": f"{n} peticiones ({n/mediana:.0f}x la mediana de {mediana:.0f})"}
            for ip, n in sospechosas.items()}


def herramienta_conocida(tabla):
    """Devuelve, por IP, si usó alguna herramienta de ataque reconocible."""
    agente_min = tabla["agente"].str.lower()
    marca = pd.Series(False, index=tabla.index)
    for h in HERRAMIENTAS_ATAQUE:
        marca = marca | agente_min.str.contains(h, regex=False, na=False)
    return set(tabla[marca]["ip"].unique())


def detectar(tabla):
    """
    Corre todas las reglas y arma un reporte por IP.

    Una misma IP puede disparar varias reglas (por ejemplo, escanear Y usar
    sqlmap). Se acumulan todas sus señales para dar un cuadro completo.
    """
    hallazgos = {}
    for deteccion in (detectar_fuerza_bruta, detectar_escaneo,
                      detectar_inyeccion_sql, detectar_volumen):
        for ip, info in deteccion(tabla).items():
            hallazgos.setdefault(ip, []).append(info)

    # Señal extra: si además usó una herramienta de ataque conocida.
    con_herramienta = herramienta_conocida(tabla)

    filas = []
    for ip, señales in hallazgos.items():
        tipos = sorted({s["tipo"] for s in señales})
        evidencias = "; ".join(s["evidencia"] for s in señales)
        filas.append({
            "ip": ip,
            "tipos_detectados": ", ".join(tipos),
            "num_reglas": len(tipos),
            "usa_herramienta_ataque": ip in con_herramienta,
            "evidencia": evidencias,
            "peticiones_totales": int((tabla["ip"] == ip).sum()),
        })

    reporte = pd.DataFrame(filas)
    if len(reporte):
        # Ordena por cantidad de reglas disparadas: más señales, más sospecha.
        reporte = reporte.sort_values(
            ["num_reglas", "peticiones_totales"], ascending=[False, False])
    return reporte


def main():
    tabla = leer_log.leer()
    print(f"[detectar] analizando {len(tabla):,} peticiones de {tabla['ip'].nunique():,} IPs\n")

    reporte = detectar(tabla)

    if not len(reporte):
        print("No se detectaron IPs sospechosas.")
        return 0

    print(f"Se detectaron {len(reporte)} IPs sospechosas:\n")
    for _, f in reporte.iterrows():
        marca = "  [herramienta de ataque]" if f["usa_herramienta_ataque"] else ""
        print(f"  {f['ip']:<18s} {f['tipos_detectados']}{marca}")
        print(f"  {'':18s} {f['evidencia']}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
