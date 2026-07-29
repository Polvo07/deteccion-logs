"""
Medición del detector.

Compara lo que detectó el motor contra la verdad conocida (el archivo que se
generó junto con el log). Sin esta comparación, el detector solo "dice cosas";
con ella, se puede afirmar con números qué tan bien funciona.

Esto es lo que distingue un análisis serio: no basta con detectar, hay que
demostrar la precisión. La verdad del log generado cumple el mismo papel que el
catálogo KEV en el proyecto de vulnerabilidades: la referencia contra la cual
se mide el acierto.

Uso:
    python src/medir.py
"""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leer_log
import detectar

RAIZ = Path(__file__).resolve().parent.parent
ARCHIVO_VERDAD = RAIZ / "datos" / "verdad.csv"


def cargar_verdad():
    if not ARCHIVO_VERDAD.exists():
        raise FileNotFoundError(
            f"Falta {ARCHIVO_VERDAD}. Genera el log con: python3 datos/generar_logs.py")
    verdad = pd.read_csv(ARCHIVO_VERDAD)
    # Solo interesan los atacantes reales; los normales son el resto.
    return verdad[verdad["tipo"] != "normal"]


def medir(reporte, verdad):
    """
    Cruza detección contra verdad y calcula las cuatro cantidades clásicas:

      - Verdadero positivo (VP): era atacante y lo detectamos. Bien.
      - Falso negativo   (FN): era atacante y se nos escapó. Mal.
      - Falso positivo   (FP): era inocente y lo acusamos. Mal.

    Con esas se calculan las dos métricas que importan en seguridad:
      - Precisión: de los que acusamos, cuántos eran de verdad. Mide el ruido.
      - Cobertura (recall): de los atacantes reales, cuántos atrapamos. Mide fugas.
    """
    ips_detectadas = set(reporte["ip"]) if len(reporte) else set()
    ips_atacantes = set(verdad["ip"])

    vp = ips_detectadas & ips_atacantes
    fn = ips_atacantes - ips_detectadas
    fp = ips_detectadas - ips_atacantes

    precision = len(vp) / len(ips_detectadas) if ips_detectadas else 0
    cobertura = len(vp) / len(ips_atacantes) if ips_atacantes else 0
    f1 = (2 * precision * cobertura / (precision + cobertura)
          if (precision + cobertura) else 0)

    return {"vp": vp, "fn": fn, "fp": fp,
            "precision": precision, "cobertura": cobertura, "f1": f1}


def medir_por_tipo(reporte, verdad):
    """Para cada tipo de ataque, cuántos de esa clase se detectaron."""
    detectadas = set(reporte["ip"]) if len(reporte) else set()
    filas = []
    for tipo in sorted(verdad["tipo"].unique()):
        ips_tipo = set(verdad[verdad["tipo"] == tipo]["ip"])
        atrapados = ips_tipo & detectadas
        filas.append({
            "tipo": tipo,
            "reales": len(ips_tipo),
            "detectados": len(atrapados),
            "cobertura": len(atrapados) / len(ips_tipo) if ips_tipo else 0,
        })
    return pd.DataFrame(filas)


def main():
    tabla = leer_log.leer()
    reporte = detectar.detectar(tabla)
    verdad = cargar_verdad()

    print("=" * 64)
    print("MEDICIÓN DEL DETECTOR")
    print("=" * 64)
    print(f"Peticiones analizadas : {len(tabla):,}")
    print(f"IPs totales           : {tabla['ip'].nunique():,}")
    print(f"Atacantes reales      : {len(set(verdad['ip']))}")
    print(f"IPs detectadas        : {len(reporte)}")

    r = medir(reporte, verdad)

    print("\n--- Resultado global ---")
    print(f"Detectados correctamente (VP) : {len(r['vp'])}")
    print(f"Se escaparon (FN)             : {len(r['fn'])}")
    print(f"Falsas alarmas (FP)           : {len(r['fp'])}")
    print()
    print(f"Precisión : {r['precision']:.1%}  (de lo que acusamos, cuánto era real)")
    print(f"Cobertura : {r['cobertura']:.1%}  (de los atacantes, cuántos atrapamos)")
    print(f"F1        : {r['f1']:.1%}  (equilibrio entre las dos)")

    print("\n--- Cobertura por tipo de ataque ---")
    por_tipo = medir_por_tipo(reporte, verdad)
    print(f"{'Tipo':<16s} {'Reales':>8s} {'Detectados':>12s} {'Cobertura':>11s}")
    print("-" * 50)
    for _, f in por_tipo.iterrows():
        print(f"{f['tipo']:<16s} {f['reales']:>8d} {f['detectados']:>12d} {f['cobertura']:>10.0%}")

    if r["fn"]:
        print(f"\n[atención] se escaparon estas IPs atacantes: {sorted(r['fn'])}")
    if r["fp"]:
        print(f"\n[atención] falsas alarmas (IPs inocentes acusadas): {sorted(r['fp'])}")
    if not r["fn"] and not r["fp"]:
        print("\nSin fugas ni falsas alarmas en este conjunto.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
