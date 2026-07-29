"""
Pruebas del motor de detección.

Arman logs pequeños y controlados, con casos donde se conoce la respuesta, y
verifican que cada regla detecte lo que debe y deje pasar lo que no. No
necesitan internet ni el log real.

Uso:
    python src/test_detectar.py
"""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detectar


def ok(condicion, descripcion, fallos):
    if condicion:
        print(f"  PASA  {descripcion}")
    else:
        print(f"  FALLA {descripcion}")
        fallos.append(descripcion)


def peticion(ip, codigo=200, ruta="/", agente="Mozilla/5.0", metodo="GET"):
    """Arma una fila de log con valores por defecto razonables."""
    return {"ip": ip, "codigo": codigo, "ruta": ruta, "agente": agente,
            "metodo": metodo, "fecha": "", "protocolo": "HTTP/1.1",
            "tam": 100, "referer": "-"}


def tabla_de(filas):
    return pd.DataFrame(filas)


def main():
    fallos = []

    print("== Fuerza bruta ==")
    # 25 fallos de login de una IP: por encima del umbral de 20.
    filas = [peticion("1.1.1.1", codigo=401, ruta="/login") for _ in range(25)]
    r = detectar.detectar_fuerza_bruta(tabla_de(filas))
    ok("1.1.1.1" in r, "detecta 25 intentos fallidos de login", fallos)

    # 5 fallos: por debajo del umbral, no debe marcarla.
    filas = [peticion("2.2.2.2", codigo=401, ruta="/login") for _ in range(5)]
    r = detectar.detectar_fuerza_bruta(tabla_de(filas))
    ok("2.2.2.2" not in r, "ignora 5 fallos (un usuario despistado)", fallos)

    print("\n== Escaneo ==")
    # 15 rutas distintas con 404: por encima del umbral de 10.
    filas = [peticion("3.3.3.3", codigo=404, ruta=f"/ruta{i}") for i in range(15)]
    r = detectar.detectar_escaneo(tabla_de(filas))
    ok("3.3.3.3" in r, "detecta 15 rutas inexistentes distintas", fallos)

    # 30 veces la MISMA ruta con 404: es una sola ruta, no un escaneo.
    filas = [peticion("4.4.4.4", codigo=404, ruta="/rota") for _ in range(30)]
    r = detectar.detectar_escaneo(tabla_de(filas))
    ok("4.4.4.4" not in r,
       "ignora 30 visitas a una MISMA ruta rota (un enlace roto, no escaneo)", fallos)

    print("\n== Inyección SQL ==")
    filas = [peticion("5.5.5.5", ruta="/p?id=1 UNION SELECT pass FROM users")]
    r = detectar.detectar_inyeccion_sql(tabla_de(filas))
    ok("5.5.5.5" in r, "detecta un UNION SELECT en la ruta", fallos)

    filas = [peticion("6.6.6.6", ruta="/productos?categoria=zapatos")]
    r = detectar.detectar_inyeccion_sql(tabla_de(filas))
    ok("6.6.6.6" not in r, "no marca una búsqueda normal de productos", fallos)

    print("\n== Volumen anómalo ==")
    # Una IP con 500 peticiones entre muchas IPs normales de ~10.
    filas = []
    for i in range(50):
        for _ in range(10):
            filas.append(peticion(f"10.0.0.{i}"))
    filas += [peticion("9.9.9.9") for _ in range(500)]
    r = detectar.detectar_volumen(tabla_de(filas))
    ok("9.9.9.9" in r, "detecta una IP con 500 peticiones (50x la mediana)", fallos)
    ok("10.0.0.1" not in r, "no marca a una IP con volumen normal", fallos)

    print("\n== Herramientas de ataque ==")
    filas = [peticion("7.7.7.7", agente="sqlmap/1.7"),
             peticion("8.8.8.8", agente="Mozilla/5.0")]
    con = detectar.herramienta_conocida(tabla_de(filas))
    ok("7.7.7.7" in con, "reconoce el user-agent de sqlmap", fallos)
    ok("8.8.8.8" not in con, "no marca un navegador normal", fallos)

    print("\n== Reporte combinado ==")
    # Una IP que escanea Y usa sqlmap debe aparecer con las dos señales.
    filas = [peticion("1.2.3.4", codigo=404, ruta=f"/x{i}", agente="sqlmap/1.7")
             for i in range(12)]
    reporte = detectar.detectar(tabla_de(filas))
    ok(len(reporte) == 1, "arma el reporte con una IP", fallos)
    if len(reporte):
        fila = reporte.iloc[0]
        ok(fila["usa_herramienta_ataque"], "marca que usó herramienta de ataque", fallos)
        ok("escaneo" in fila["tipos_detectados"], "clasifica como escaneo", fallos)

    print("\n== Umbrales coherentes ==")
    ok(detectar.MIN_FALLOS_LOGIN > 0, "el umbral de login es positivo", fallos)
    ok(detectar.MIN_RUTAS_404 > 0, "el umbral de rutas 404 es positivo", fallos)
    ok(detectar.FACTOR_VOLUMEN > 1, "el factor de volumen es mayor que 1", fallos)

    print("\n" + "=" * 60)
    if fallos:
        print(f"RESULTADO: {len(fallos)} prueba(s) fallaron")
        return 1
    print("RESULTADO: todas las pruebas pasaron")
    return 0


if __name__ == "__main__":
    sys.exit(main())
