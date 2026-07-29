# Detección de ataques en logs de servidor web

Sistema que analiza logs de acceso de un servidor web y detecta comportamiento
de atacantes: fuerza bruta, escaneo, inyección SQL y volumen anómalo. Combina un
triage rápido en la terminal de Linux con un motor de detección en Python, y
**mide su propia precisión** contra una verdad conocida.

Todo es defensivo: analiza registros que ya existen para encontrar las huellas
que dejan los atacantes. No ataca, no explota, no genera tráfico malicioso.

---

## El problema

Un servidor web anota cada petición que recibe en un archivo de log: una línea
por evento, cientos de miles al día. Escondidos en ese ruido hay ataques —
alguien probando miles de contraseñas, alguien buscando páginas de
administración olvidadas, alguien inyectando comandos de base de datos en un
formulario. El reto es distinguir automáticamente esos patrones del tráfico
legítimo. Es el trabajo diario de un analista SOC.

---

## Qué detecta

| Ataque | Cómo se reconoce en el log |
|---|---|
| **Fuerza bruta** | Una IP con muchos intentos de login fallidos (código 401) |
| **Escaneo** | Una IP que pide muchas rutas distintas inexistentes (código 404) |
| **Inyección SQL** | Peticiones con patrones de base de datos (`UNION SELECT`, `OR '1'='1'`) |
| **Volumen anómalo** | Una IP con muchísimo más tráfico que el visitante típico |

Como señal adicional, identifica herramientas de ataque conocidas
(sqlmap, Nikto, Nmap, acunetix) por su user-agent.

---

## Resultados

<!-- RESULTADOS:INICIO -->

Sobre un log de prueba de **18.491 peticiones** de **1.430 IPs distintas**, con
**12 atacantes** reales mezclados en el tráfico:

| Métrica | Valor | Qué mide |
|---|---|---|
| **Precisión** | **90,9%** | De las IPs que acusó, cuántas eran atacantes reales |
| **Cobertura** | **83,3%** | De los atacantes reales, cuántos atrapó |
| **F1** | **87,0%** | Equilibrio entre las dos |

Detectó 10 de 12 atacantes, con 1 falsa alarma.

<!-- RESULTADOS:FIN -->

**El resultado no es perfecto a propósito, y ahí está lo interesante.** El log de
prueba incluye casos límite diseñados para engañar a un detector ingenuo:

- Un atacante de **fuerza bruta lenta** (15 intentos muy espaciados, bajo el
  umbral de 20) que se escapa. Es un falso negativo real: un umbral fijo tiene
  un punto ciego, y un atacante que lo conoce se queda justo debajo.
- Un **escáner lento** (6 rutas, bajo el umbral de 10) que también se escapa.
- Un **usuario legítimo muy activo** (180 peticiones) que el detector acusa por
  volumen. Es un falso positivo: tráfico intenso pero inocente.

Ese es el dilema central de la detección: bajar los umbrales atrapa a los
sigilosos pero acusa a más inocentes; subirlos hace lo contrario. No existe un
número perfecto, y el proyecto lo demuestra con datos en vez de esconderlo.

---

## Cómo está construido

```
datos/generar_logs.py   →  crea el log con ataques etiquetados
        │
        ▼
triage/triage.sh        →  primera mirada en la terminal (grep, awk, sort)
        │
        ▼
src/leer_log.py         →  convierte el log de texto en una tabla
        │
        ▼
src/detectar.py         →  aplica las cuatro reglas de detección
        │
   ┌────┴────┐
   ▼         ▼
src/medir.py   src/reportar.py
mide precisión  prioriza por gravedad
```

**Dos niveles, como en el trabajo real.** Primero el triage en la terminal de
Linux: en segundos, sin escribir un programa, se ve qué IPs piden más, cuáles
acumulan errores y quién usa herramientas de ataque. Después el motor en Python:
las reglas completas, la medición y el reporte priorizado.

---

## Por qué el log se genera en vez de descargarse

Un log descargado no dice cuáles líneas son ataques, así que "detectar" sería
adivinar sin forma de saber si se acierta. Al generar el log, se conoce la
respuesta exacta —qué IP hizo qué— y se puede medir la precisión con números.

Esa "verdad de campo" cumple el mismo papel que un dataset etiquetado en
cualquier trabajo de detección. Es la misma técnica de los conjuntos académicos
de seguridad como CSIC 2010, que también son generados. Y el generador es código
propio que demuestra entender **cómo se ve cada ataque dentro de un log**, que es
justo el conocimiento que el proyecto busca probar.

El archivo `datos/verdad.csv` guarda la etiqueta de cada actor; `src/medir.py` lo
usa como referencia para calcular precisión y cobertura.

---

## Cómo reproducirlo

Requisitos: Python 3.10+ y un sistema con `bash`, `grep`, `awk` (Linux, WSL o
macOS). Para el triage se recomienda WSL Ubuntu en Windows.

```bash
git clone https://github.com/Polvo07/deteccion-logs.git
cd deteccion-logs
pip install -r requirements.txt

python3 src/test_detectar.py           # verifica la lógica sin datos reales

python3 datos/generar_logs.py --dificil # crea el log con casos límite
bash triage/triage.sh datos/acceso.log  # triage rápido en terminal
python3 src/detectar.py                 # detección completa
python3 src/medir.py                    # mide la precisión
python3 src/reportar.py                 # reporte priorizado -> docs/reporte_ips.csv
```

---

## Evidencia de ejecución

La carpeta `docs/` guarda la salida real de cada etapa:

- `triage_salida.txt` — el triage en terminal
- `medicion_salida.txt` — precisión, cobertura y cobertura por tipo
- `reporte_salida.txt` — las IPs ordenadas por gravedad
- `reporte_ips.csv` — el reporte en formato de tabla

---

## Limitaciones

- **El log es sintético.** Reproduce patrones reales de ataque, pero un servidor
  de producción tiene más variedad y ruido. Las cifras muestran que el enfoque
  funciona, no que estos umbrales sirvan sin ajuste en cualquier entorno.
- **La detección es por reglas y umbrales fijos.** Es transparente y explicable,
  pero un atacante que conozca los umbrales puede quedarse por debajo (como
  demuestran los casos sigilosos). Un sistema de producción combinaría esto con
  análisis de comportamiento a lo largo del tiempo.
- **No hay bloqueo ni respuesta.** El sistema detecta y reporta; actuar sobre las
  IPs es una decisión que corresponde a un humano o a otra capa.

---

## Stack

Python (pandas) · Bash (grep, awk, sort, uniq) · Linux / WSL · Git

---

## Autor

**Andrés Felipe Domínguez Pallares** — Estudiante de Ingeniería Multimedia,
Universidad Simón Bolívar.
[LinkedIn](https://www.linkedin.com/in/andres-dominguez-4877a51b8/) ·
[GitHub](https://github.com/Polvo07)
