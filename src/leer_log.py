"""
Lector de logs.

Convierte el archivo de log —donde cada línea es un texto apretado— en una
tabla ordenada que se puede analizar. Es el mismo trabajo de limpieza de los
proyectos anteriores: pasar de texto crudo a datos estructurados.

Uso (normalmente lo llaman otros archivos, pero se puede probar solo):
    python src/leer_log.py
"""

import re
import sys
from pathlib import Path

import pandas as pd

RAIZ = Path(__file__).resolve().parent.parent
ARCHIVO_LOG = RAIZ / "datos" / "acceso.log"

# Expresión regular que describe una línea del formato combinado de Apache.
# Cada (?P<nombre>...) captura un trozo y le pone nombre. Se explica pieza a
# pieza en docs/como-funciona.md; aquí la idea es reconocer:
#   IP - - [fecha] "METODO ruta PROTOCOLO" codigo tamaño "referer" "agente"
PATRON = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>.*?) (?P<protocolo>[^"]*)" '
    r'(?P<codigo>\d{3}) (?P<tam>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agente>[^"]*)"'
)


def parsear_linea(linea):
    """
    Convierte una línea de texto en un diccionario con sus campos.

    Devuelve None si la línea no encaja en el formato esperado. En un log real
    siempre hay basura ocasional, y descartar esas líneas es más seguro que
    dejar que rompan todo el análisis.
    """
    m = PATRON.match(linea)
    if not m:
        return None
    d = m.groupdict()
    d["codigo"] = int(d["codigo"])
    d["tam"] = int(d["tam"]) if d["tam"].isdigit() else 0
    return d


def leer(ruta=ARCHIVO_LOG):
    """Lee el log entero y devuelve una tabla de pandas, una fila por petición."""
    ruta = Path(ruta)
    if not ruta.exists():
        raise FileNotFoundError(
            f"No se encontró {ruta}. Genera uno con: python3 datos/generar_logs.py")

    filas = []
    descartadas = 0
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            d = parsear_linea(linea)
            if d is None:
                descartadas += 1
            else:
                filas.append(d)

    tabla = pd.DataFrame(filas)

    # La fecha viene como texto tipo "01/Mar/2026:08:00:02 +0000". Se convierte
    # a fecha real para poder medir intervalos de tiempo después.
    tabla["momento"] = pd.to_datetime(
        tabla["fecha"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce")

    if descartadas:
        print(f"[leer] {descartadas} líneas no encajaron en el formato y se descartaron")

    return tabla


def main():
    tabla = leer()
    print(f"[leer] {len(tabla):,} peticiones leídas")
    print(f"[leer] {tabla['ip'].nunique():,} IPs distintas")
    print(f"[leer] rango de tiempo: {tabla['momento'].min()} a {tabla['momento'].max()}")
    print("\nPrimeras filas:")
    print(tabla[["ip", "metodo", "ruta", "codigo"]].head(8).to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
