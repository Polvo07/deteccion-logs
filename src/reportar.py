"""
Reporte de IPs sospechosas.

Toma la detección, la ordena por gravedad y la guarda como evidencia. Igual que
en el proyecto de vulnerabilidades: no basta con detectar, hay que priorizar
para que un analista sepa a quién mirar primero.

La gravedad combina dos señales: cuántas reglas distintas disparó la IP (no es
lo mismo solo hacer volumen que escanear Y usar sqlmap) y si empleó una
herramienta de ataque conocida.

Uso:
    python src/reportar.py
"""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leer_log
import detectar

RAIZ = Path(__file__).resolve().parent.parent
DIR_DOCS = RAIZ / "docs"

# Peso de gravedad por tipo de ataque. La inyección SQL y la fuerza bruta son
# intentos directos de comprometer el sistema; el escaneo es reconocimiento
# previo; el volumen puede ser molesto sin ser un ataque dirigido.
GRAVEDAD_TIPO = {
    "inyeccion_sql": 4,
    "fuerza_bruta": 3,
    "escaneo": 2,
    "volumen": 1,
}


def puntaje_gravedad(fila):
    """
    Combina las señales en un puntaje único para ordenar.

    Suma la gravedad de cada tipo detectado y añade un bono si usó una
    herramienta de ataque reconocida. Más señales y más peligrosas, más arriba.
    """
    tipos = fila["tipos_detectados"].split(", ")
    base = sum(GRAVEDAD_TIPO.get(t, 0) for t in tipos)
    bono = 2 if fila["usa_herramienta_ataque"] else 0
    return base + bono


def construir_reporte():
    tabla = leer_log.leer()
    reporte = detectar.detectar(tabla)
    if not len(reporte):
        return reporte

    reporte["gravedad"] = reporte.apply(puntaje_gravedad, axis=1)
    reporte = reporte.sort_values("gravedad", ascending=False).reset_index(drop=True)
    reporte.insert(0, "prioridad", range(1, len(reporte) + 1))
    return reporte


def imprimir(reporte):
    if not len(reporte):
        print("No se detectaron IPs sospechosas.")
        return

    print("=" * 70)
    print(f"REPORTE DE IPs SOSPECHOSAS  ({len(reporte)} detectadas)")
    print("=" * 70)
    print("Ordenadas por gravedad: revisar de arriba hacia abajo.\n")

    for _, f in reporte.iterrows():
        marca = "  ⚠ herramienta de ataque" if f["usa_herramienta_ataque"] else ""
        print(f"#{f['prioridad']}  {f['ip']:<18s} gravedad {f['gravedad']}{marca}")
        print(f"     tipo(s): {f['tipos_detectados']}")
        print(f"     {f['evidencia']}")
        print()


def main():
    reporte = construir_reporte()
    imprimir(reporte)

    if len(reporte):
        DIR_DOCS.mkdir(exist_ok=True)
        columnas = ["prioridad", "ip", "gravedad", "tipos_detectados",
                    "usa_herramienta_ataque", "peticiones_totales", "evidencia"]
        salida = DIR_DOCS / "reporte_ips.csv"
        reporte[columnas].to_csv(salida, index=False, encoding="utf-8")
        print(f"[guardado] {salida}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
