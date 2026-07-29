#!/usr/bin/env bash
#
# Triage rápido de un log de acceso, usando solo herramientas de Linux.
#
# Esta es la primera mirada que hace un analista frente a un log: sin escribir
# un programa, con los comandos que ya trae el sistema, se obtiene en segundos
# un panorama de quién está haciendo qué. No reemplaza el análisis en Python;
# lo antecede. Sirve para saber dónde mirar.
#
# Uso:
#     bash triage/triage.sh datos/acceso.log
#
# Si no se pasa un archivo, usa datos/acceso.log por defecto.

set -euo pipefail

LOG="${1:-datos/acceso.log}"

if [[ ! -f "$LOG" ]]; then
    echo "No se encontró el log: $LOG"
    echo "Genera uno con: python3 datos/generar_logs.py"
    exit 1
fi

total=$(wc -l < "$LOG")
echo "======================================================================"
echo "TRIAGE DE $LOG"
echo "$total líneas en total"
echo "======================================================================"

# ---------------------------------------------------------------------------
# 1. Las IPs que más piden.
#    awk '{print $1}'  -> saca la primera columna de cada línea (la IP)
#    sort              -> ordena para poder agrupar
#    uniq -c           -> cuenta cuántas veces se repite cada IP
#    sort -rn          -> ordena de mayor a menor
# ---------------------------------------------------------------------------
echo
echo "### Las 10 IPs con más peticiones"
echo "(un volumen muy por encima del resto es sospechoso)"
echo
awk '{print $1}' "$LOG" | sort | uniq -c | sort -rn | head -10

# ---------------------------------------------------------------------------
# 2. Posible fuerza bruta: IPs con muchos errores 401 (login fallido).
#    El código de respuesta es la novena columna en el formato estándar.
# ---------------------------------------------------------------------------
echo
echo "### Posible fuerza bruta: IPs con más respuestas 401 (login fallido)"
echo
n401=$(awk '$9 == 401' "$LOG" | wc -l)
if [[ "$n401" -eq 0 ]]; then
    echo "  (ninguna respuesta 401 en el log)"
else
    awk '$9 == 401 {print $1}' "$LOG" | sort | uniq -c | sort -rn | head -5
fi

# ---------------------------------------------------------------------------
# 3. Posible escaneo: IPs con muchos errores 404 (página inexistente).
#    Buscar rutas que no existen una tras otra es la huella de un escáner.
# ---------------------------------------------------------------------------
echo
echo "### Posible escaneo: IPs con más respuestas 404 (ruta inexistente)"
echo
awk '$9 == 404 {print $1}' "$LOG" | sort | uniq -c | sort -rn | head -5

# ---------------------------------------------------------------------------
# 4. Rutas sensibles que alguien intentó alcanzar.
#    grep -E busca varios patrones a la vez con "expresión extendida".
#    -o imprime solo lo que coincide; -i ignora mayúsculas/minúsculas.
# ---------------------------------------------------------------------------
echo
echo "### Accesos a rutas sensibles (paneles, configuración, respaldos)"
echo
grep -ioE '/(admin|wp-admin|wp-login|phpmyadmin|\.env|\.git|config\.php|backup|shell|console|manager|actuator)' "$LOG" \
    | sort | uniq -c | sort -rn | head -10 \
    || echo "  (ninguna ruta sensible encontrada)"

# ---------------------------------------------------------------------------
# 5. Posible inyección SQL: peticiones con palabras clave de base de datos.
# ---------------------------------------------------------------------------
echo
echo "### Posible inyección SQL: peticiones con patrones de SQL"
echo
grep -iE "(union select|or '1'='1|drop table|sleep\(|--|')" "$LOG" \
    | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 \
    || echo "  (ningún patrón de inyección encontrado)"

# ---------------------------------------------------------------------------
# 6. Herramientas de ataque conocidas, identificadas por su user-agent.
# ---------------------------------------------------------------------------
echo
echo "### User-agents de herramientas de ataque conocidas"
echo
grep -ioE "(sqlmap|nikto|nmap|acunetix|netsparker|masscan)" "$LOG" \
    | sort | uniq -c | sort -rn \
    || echo "  (ninguna herramienta conocida encontrada)"

echo
echo "======================================================================"
echo "Fin del triage. Para el análisis completo y medido:"
echo "    python3 src/detectar.py"
echo "======================================================================"
