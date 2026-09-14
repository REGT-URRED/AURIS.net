# AURIS.net

Framework modular de auditoria y evaluacion de seguridad inalambrica en routers y CPEs domesticos, disenado para investigacion academica y auditorias tecnicas controladas (Wifite4 Architecture Upgrade).

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

### Modo Desarrollo / Entorno Virtual

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/REGT-URRED/AURIS.net.git
   cd AURIS.net
   ```

2. Crear y activar el entorno virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

4. Inicializar la base de datos local:
   ```bash
   python3 auris.py db-init
   ```

5. Configurar el archivo de alcance (RoE):
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
