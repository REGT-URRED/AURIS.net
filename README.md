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

- **Hardware Abstraction Layer (HAL Userland):** Catalogo y deteccion de 12 chipsets inalambricos (Atheros AR9271, Realtek RTL8812AU/RTL8187L/RTL8814AU, MediaTek MT7601U/MT7610U/MT7612U/MT7921, Ralink RT3070/RT5370, Intel iwlwifi), gestionando inyeccion y bandas operativas sin dependencias de alto nivel.
- **Pipeline Modular por Fases:** Motor orquestador basado en el contrato formal `PhaseProtocol`. Cada vector de prueba (Captura PMKID/Handshake, WPS Pixie Dust, Fuerza Bruta PIN, WPS PBC, PSK Cracking multi-backend) opera de manera aislada e independiente.
- **Generador Heuristico de Candidatos:** Motor de mutacion combinatoria inteligente basado en SSIDs, prefijos de proveedores de servicios (ISPs), direcciones BSSID y familias de equipos hermanos.
- **Sensor WIDS Defensivo:** Deteccion pasiva de anomalias en tiempo real, incluyendo identificacion de ventanas de asociacion WPS Push-Button (PBC).
- **Gobernanza y RoE Automatizado:** Verificacion obligatoria de listas blancas (BSSID/SSID), ventanas de tiempo autorizadas y persistencia de direccion MAC para auditorias conformes a normativa.
- **Capacidad 100% Offline:** Totalmente funcional en sistemas aislados sin conexion a internet.

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
|       |-- roe.py              # Validacion de Reglas de Compromiso
|       |-- scanner.py          # Descubrimiento de redes en el espectro
|       `-- wids.py             # Monitor defensivo e IDS inalambrico
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
- Herramientas auxiliares (segun las fases a ejecutar): `aircrack-ng`, `hcxdumptool`, `hcxtools`, `reaver`, `wash`, `iw`.

## Instalacion y Puesta en Marcha

### Despliegue en Kali Linux (Offline en Campo)

Para auditorias en estaciones aisladas sin acceso a internet utilizando el paquete autonomo `auris-kali.tar.gz` (incluye 118 paquetes .deb, wheels de Python y wordlists):

1. Extraer el paquete y ejecutar el instalador desatendido:
   ```bash
   mkdir -p ~/auris && tar xzf auris-kali.tar.gz -C ~/auris && cd ~/auris
   sudo bash setup.sh
   ```
   El script `setup.sh` instala automaticamente las herramientas de radio, configura las dependencias de Python, inicializa la base de datos SQLite y registra el comando global `/usr/local/bin/auris`.

2. Configurar el alcance de auditoria:
   ```bash
   cp config/scope.example.yml config/scope.yml
   nano config/scope.yml
   # Definir los BSSIDs autorizados y la ventana de tiempo (time_window)
   ```

3. Verificar el estado del entorno y hardware:
   ```bash
   sudo auris doctor
   sudo auris hal
   ```

4. Ejecutar la auditoria:
   ```bash
   # Simulacion previa sin transmisiones de radio
   sudo auris run-all --dry-run

   # Auditoria autorizada en el espectro (requiere interfaz en modo monitor)
   sudo auris run-all --force-roe --iface wlan0
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
   # Editar config/scope.yml con los BSSIDs autorizados y ventana temporal
   ```

## Uso de la Linea de Comandos

El ejecutable `auris.py` expone los siguientes subcomandos principales:

- **Diagnostico del entorno:**
  ```bash
  python3 auris.py doctor
  ```

- **Auditoria de adaptadores inalambricos y chipsets soportados (HAL):**
  ```bash
  python3 auris.py hal
  ```

- **Generacion heuristica de candidatos de contrasena:**
  ```bash
  python3 auris.py candidates "MOVISTAR_XXXX" --bssid "00:11:22:33:44:55"
  ```

- **Ejecucion simulada (Dry-Run, sin transmisiones de radio):**
  ```bash
  sudo python3 auris.py run-all --dry-run
  ```

- **Ejecucion de auditoria autorizada en el aire:**
  ```bash
  sudo python3 auris.py run-all --force-roe --iface wlan0
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
