<div align="center">

<img src="assets/wifi-red.svg" alt="AURIS.net WiFi Red Logo" width="120" />

# AURIS.net

```text
┌──(auris㉿kali)-[~/AURIS.net]
└─$ sudo auris --status --version 2.1.0-wifite4

  █████╗ ██╗   ██╗██████╗ ██╗███████╗   ███╗   ██╗███████╗████████╗
 ██╔══██╗██║   ██║██╔══██╗██║██╔════╝   ████╗  ██║██╔════╝╚══██╔══╝
 ███████║██║   ██║██████╔╝██║███████╗   ██╔██╗ ██║█████╗     ██║   
 ██╔══██║██║   ██║██╔══██╗██║╚════██║   ██║╚██╗██║██╔══╝     ██║   
 ██║  ██║╚██████╔╝██║  ██║██║███████║██╗██║ ╚████║███████╗   ██║   
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   

 [+] TRANSCEIVER HAL : 12 Chipsets Supported (Atheros / Realtek / MTK / Intel)
 [+] ORCHESTRATION   : Decoupled Phase Engine (Capture / WPS / PSK / LAN / RoE)
 [+] INTELLIGENCE    : Smart Candidate Generator & ISP Fleet Knowledge Base
 [+] DEFENSE MONITOR : Active WIDS Sensor & Push-Button (PBC) Event Detector
```

**Framework modular de auditoria y evaluacion de seguridad inalambrica en routers y CPEs domesticos (Wifite4 Architecture Upgrade)**

</div>

## Descripcion

AURIS.net implementa una arquitectura desacoplada para la evaluacion de dispositivos inalambricos 802.11. Integra orquestacion de ataques por fases, abstraccion de hardware en espacio de usuario (HAL), generacion heuristica de claves y gobernanza estricta de Reglas de Compromiso (Rules of Engagement - RoE).

## Caracteristicas Principales

- **Flujo Interactivo Estilo Wifite:** Escaneo rapido del espectro (25s por defecto), pausa automatica y seleccion interactiva de objetivos (`1,3-5`, `all`, `q`). La seleccion explicita actua como firma y consentimiento RoE en tiempo real, eliminando la necesidad de precargar BSSIDs manualmente.
- **Top-20 Defaults Sigiloso (Fase PSK_DEFAULTS):** Evaluacion ultrarrapida de las 20 claves por defecto/humanas mas comunes inmediatamente tras la captura de PMKID/Handshake, con cadencia de micro-pausas y jitter (2-5s) para evadir WIDS. Si acierta, omite automaticamente las fases pesadas (WPS Pixie/PIN y cracking por diccionario masivo).
- **Hardware Abstraction Layer (HAL Userland):** Catalogo y deteccion de 14 chipsets inalambricos (Atheros AR9271, Realtek RTL8812AU/RTL8187L/RTL8814AU/RTL8821AU, MediaTek MT7601U/MT7610U/MT7612U/MT7921/MT7925, Ralink RT3070/RT5370, Intel iwlwifi), gestionando inyeccion y bandas operativas sin dependencias de alto nivel.
- **Pipeline Modular por Fases:** Motor orquestador basado en el contrato formal `PhaseProtocol`. Cada vector de prueba (Captura PMKID/Handshake con `hcxdumptool` 6.3.1+, PSK Defaults, WPS Pixie Dust dual con Reaver/Bully, Fuerza Bruta PIN, WPS PBC, PSK Cracking multi-backend) opera de manera aislada e independiente.
- **Resiliencia de Modo Monitor:** Adopcion automatica de interfaces renombradas (`wlan0mon`) aun cuando `airmon-ng` reporte retornos atipicos (`rc=1`), verificacion de NetworkManager y reinicializacion limpia al finalizar.
- **Generador Heuristico de Candidatos:** Motor de mutacion combinatoria inteligente basado en SSIDs, prefijos de proveedores de servicios (ISPs), direcciones BSSID y familias de equipos hermanos.
- **Sensor WIDS Defensivo:** Deteccion pasiva de anomalias en tiempo real, incluyendo identificacion de ventanas de asociacion WPS Push-Button (PBC).
- **Gobernanza y RoE Automatizado:** Verificacion obligatoria de listas blancas (opcional para entornos cerrados), ventanas de tiempo autorizadas y persistencia de direccion MAC para auditorias conformes a normativa.
- **Capacidad 100% Offline:** Totalmente funcional en sistemas aislados sin conexion a internet, con soporte para paquetes .deb, wheels y wordlists offline.

## Estructura del Repositorio

```text
AURIS.net/
|-- src/
|   `-- auris/
|       |-- adapters/           # Capa de integracion de herramientas externas
|       |-- phases/             # Fases de auditoria (Capture, WPS, PSK, LAN, RoE)
|       |-- hal.py              # Hardware Abstraction Layer userland
|       |-- generator.py        # Generador heuristico de candidatos
|       |-- pipeline.py         # Orquestador del flujo de ejecucion
|       |-- cli.py              # Interfaz de linea de comandos (Typer)
|       |-- decision_engine.py  # Evaluacion STRIDE y seleccion de caminos
|       |-- models.py           # Modelos de datos estructurados (Pydantic)
|       |-- monitor.py          # Gestion de interfaz y adopcion de modo monitor
|       |-- roe.py              # Validacion de Reglas de Compromiso
|       |-- scanner.py          # Descubrimiento de redes en el espectro
|       |-- terminal.py         # Interfaz de consola, tablas Rich y seleccion
|       |-- wids.py             # Monitor defensivo e IDS inalambrico
|       `-- wordlists.py        # Gestion y verificacion de diccionarios
|-- config/
|   `-- scope.example.yml       # Plantilla de configuracion de alcance
|-- data/
|   `-- seed/                   # Base de conocimiento de fabricantes (OUI) y CWE
|-- scripts/
|   |-- bootstrap.sh            # Descarga y preparacion de dependencias
|   |-- pack.sh                 # Generador de paquete comprimido para despliegue USB
|   `-- setup.sh                # Instalador desatendido para estaciones de campo
|-- tests/                      # Suite de pruebas unitarias e integracion
|-- CHANGELOG.md                # Registro historico de versiones y cambios
`-- auris.py                    # Punto de entrada de ejecucion directa
```

## Requisitos

- Sistema operativo: Linux (Kali Linux, Parrot OS, Debian 12+, Ubuntu 22.04+).
- Python: version 3.10 o superior.
- Herramientas auxiliares (segun las fases a ejecutar): `aircrack-ng`, `hcxdumptool` (6.3.1+), `hcxtools`, `reaver`, `bully`, `pixiewps`, `wash`, `iw`.

## Instalacion y Puesta en Marcha

### Despliegue en Kali Linux (Offline en Campo)

Para auditorias en estaciones aisladas sin acceso a internet utilizando el paquete autonomo `auris-kali.tar.gz` (incluye 118 paquetes .deb, wheels de Python y wordlists):

1. Extraer el paquete y ejecutar el instalador desatendido:
   ```bash
   mkdir -p ~/auris && tar xzf auris-kali.tar.gz -C ~/auris && cd ~/auris
   sudo bash setup.sh
   ```
   El script `setup.sh` instala automaticamente las herramientas de radio, configura las dependencias de Python, inicializa la base de datos SQLite y registra el comando global `/usr/local/bin/auris`.

2. Configurar el alcance de auditoria (Opcional si se usa seleccion interactiva):
   ```bash
   cp config/scope.example.yml config/scope.yml
   # Opcional: configurar institucion y ventana de tiempo (time_window).
   # NOTA: Los BSSIDs NO requieren pre-edicion obligatoria. El marcado de
   # redes tras el escaneo actua como firma y consentimiento RoE explicito.
   ```

3. Verificar el estado del entorno y hardware:
   ```bash
   sudo auris doctor
   sudo auris hal
   ```

4. Ejecutar la auditoria:
   ```bash
   # Flujo estilo Wifite: escanea 25s, marcas objetivos (ej: 1,3-5) y corre solo
   sudo auris run-all

   # Simulacion previa sin transmisiones de radio (Dry-Run)
   sudo auris run-all --dry-run

   # Auditoria desatendida / automatica por script (marcas por flag)
   sudo auris run-all --force-roe --targets "1,3-5"

   # Auditoria de todas las redes detectadas sin preguntar
   sudo auris run-all --force-roe --all
   ```

### Despliegue en Kali Linux / Debian (Con Conexion a Internet)

1. Instalar herramientas de radio del sistema:
   ```bash
   sudo apt update
   sudo apt install -y aircrack-ng hcxdumptool hcxtools reaver bully pixiewps iw macchanger wireless-tools python3-venv python3-pip
   ```

2. Clonar el repositorio y configurar el entorno:
   ```bash
   git clone https://github.com/REGT-URRED/AURIS.net.git
   cd AURIS.net
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 auris.py db-init
   ```

3. Configurar el archivo de alcance (RoE):
   ```bash
   cp config/scope.example.yml config/scope.yml
   # Opcional: ajustar institucion y time_window segun el acuerdo legal
   ```

## Uso de la Linea de Comandos

El ejecutable `auris.py` (o comando `auris`) expone los siguientes subcomandos principales:

- **Auditoria automatizada completa (flujo Wifite):**
  ```bash
  # Interactivo con seleccion de objetivos tras escaneo de 25s
  sudo auris run-all

  # Ajustar tiempo de escaneo inicial a 30s
  sudo auris run-all --scan-duration 30

  # Modo no interactivo para objetivos especificos
  sudo auris run-all --force-roe --targets "1,3-5"

  # Auditar todas las redes detectadas
  sudo auris run-all --force-roe --all

  # Reanudar la sesion interrumpida previa
  sudo auris run-all --resume-last

  # Permitir auditoria LAN sobre el gateway del laboratorio (solo lectura)
  sudo auris run-all --force-roe --allow-lan
  ```

- **Diagnostico integral del entorno y dependencias:**
  ```bash
  sudo auris doctor
  ```

- **Inventario de adaptadores y chipsets WiFi soportados (HAL):**
  ```bash
  sudo auris hal
  ```

- **Generacion heuristica de candidatos de contrasena (Wifite4):**
  ```bash
  python3 auris.py candidates "MOVISTAR_XXXX" --bssid "00:11:22:33:44:55"
  ```

- **Verificacion de integridad de la wordlist Rockyou:**
  ```bash
  python3 auris.py verify-rockyou
  ```

- **Ejecucion simulada (Dry-Run, sin transmisiones de radio):**
  ```bash
  sudo auris run-all --dry-run
  ```

## Pruebas

Para ejecutar la suite de pruebas unitarias:

```bash
PYTHONPATH=src pytest tests/ -v
```

## Aviso Legal y Etica

AURIS.net ha sido desarrollado con fines academicos, de investigacion en ciberseguridad y para la realizacion de evaluaciones tecnicas en infraestructuras propias o expresamente autorizadas por escrito mediante un acuerdo de Reglas de Compromiso (RoE). El uso no autorizado en redes ajenas es ilegal.

## Licencia

Distribuido bajo la Licencia MIT. Consulte el archivo LICENSE para mas detalles.
