#!/bin/bash

##############################################################################
# Script de Configuración IDS/IPS (Suricata) - Sistema Ciberseguridad FEI
# 
# Descripción: Instalación y configuración de Suricata como sistema
#              de detección y prevención de intrusiones
# 
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Versión: 1.0
# Sistema: Debian 12 (VM7 - 10.10.30.20)
##############################################################################

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuración
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
RULES_DIR="/var/lib/suricata/rules"
LOG_DIR="/var/log/suricata"
INTERFACE="eth0"
HOME_NET="10.10.0.0/16"
EXTERNAL_NET="!$HOME_NET"

# Función para logging
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/suricata-install.log
}

error_message() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/suricata-install.log
}

warning_message() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/suricata-install.log
}

# Verificar privilegios de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_message "Este script debe ejecutarse como root"
        exit 1
    fi
}

# Backup de configuraciones existentes
backup_configs() {
    log_message "Creando backup de configuraciones existentes..."
    
    if [ -f "$SURICATA_CONFIG" ]; then
        cp "$SURICATA_CONFIG" "${SURICATA_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        log_message "Backup de suricata.yaml creado"
    fi
}

# Actualizar sistema
update_system() {
    log_message "Actualizando repositorios del sistema..."
    apt update -qq
    
    log_message "Actualizando paquetes del sistema..."
    apt upgrade -y -qq
}

# Instalar dependencias
install_dependencies() {
    log_message "Instalando dependencias necesarias..."
    
    apt install -y \
        software-properties-common \
        apt-transport-https \
        wget \
        curl \
        gnupg2 \
        lsb-release \
        build-essential \
        libpcap-dev \
        libyaml-dev \
        libjansson-dev \
        libpcre3-dev \
        pkg-config \
        libnss3-dev \
        libgeoip-dev \
        liblua5.1-dev \
        libhiredis-dev \
        libevent-dev \
        python3-yaml \
        jq \
        tcpdump \
        iftop \
        htop
        
    if [ $? -eq 0 ]; then
        log_message "Dependencias instaladas correctamente"
    else
        error_message "Error al instalar dependencias"
        exit 1
    fi
}

# Instalar Suricata
install_suricata() {
    log_message "Instalando Suricata IDS/IPS..."
    
    # Agregar repositorio oficial de Suricata
    add-apt-repository ppa:oisf/suricata-stable -y
    apt update -qq
    
    # Instalar Suricata
    apt install -y suricata
    
    if [ $? -eq 0 ]; then
        log_message "Suricata instalado correctamente"
        log_message "Versión instalada: $(suricata --version)"
    else
        error_message "Error al instalar Suricata"
        exit 1
    fi
}

# Configurar Suricata
configure_suricata() {
    log_message "Configurando Suricata..."
    
    # Crear directorio de configuración personalizada
    mkdir -p /etc/suricata/custom
    
    # Configuración principal de Suricata
    cat > "$SURICATA_CONFIG" << EOF
# Configuración Suricata - Sistema Ciberseguridad FEI
# Adaptado para red académica con enfoque en seguridad

%YAML 1.1
---

# Variables de red
vars:
  address-groups:
    HOME_NET: "$HOME_NET"
    EXTERNAL_NET: "$EXTERNAL_NET"
    
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

# Configuración por defecto
default-log-dir: $LOG_DIR

# Configuración de estadísticas
stats:
  enabled: yes
  interval: 8

# Configuración de outputs
outputs:
  # Logs rápidos
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  # Logs detallados
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
            tagged-packets: yes
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp
        - ssh
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow

  # Logs HTTP
  - http-log:
      enabled: yes
      filename: http.log
      append: yes

  # Logs TLS
  - tls-log:
      enabled: yes
      filename: tls.log
      append: yes

  # Logs SSH
  - ssh-log:
      enabled: yes
      filename: ssh.log
      append: yes

  # Logs DNS
  - dns-log:
      enabled: yes
      filename: dns.log
      append: yes

# Configuración de logging
logging:
  default-log-level: notice
  default-output-filter:

  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: suricata.log
    - syslog:
        enabled: yes
        facility: local5
        format: "[%i] <%d> -- "

# Configuración de aplicaciones
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 100kb
            decompress-depth: 100kb
          double-decode-path: no
          double-decode-query: no
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53

# Configuración de detección de archivos
file-extraction:
  enabled: no

# Configuración de AF_PACKET
af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
    buffer-size: 32768

# Configuración de threading
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"

# Configuración de detección
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# Configuración de motor MPM
mpm-algo: auto

# Configuración de patrones
pattern-matcher:
  - b2gc:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b2gm:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b2g:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b3g:
      search-algo: B3gSearchBNDMq
      hash-size: low
      bf-size: medium
  - wumanber:
      hash-size: low
      bf-size: medium

# Configuración de defragmentación
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

# Configuración de flujos
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30
  managers: 1
  recyclers: 1

# Configuración de vlan
vlan:
  use-for-tracking: true

# Configuración de flow timeouts
flow-timeouts:
  default:
    new: 30
    established: 300
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
    emergency-bypassed: 50
  tcp:
    new: 60
    established: 600
    closed: 60
    bypassed: 100
    emergency-new: 5
    emergency-established: 100
    emergency-closed: 10
    emergency-bypassed: 50
  udp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-bypassed: 50
  icmp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-bypassed: 50

# Configuración de stream
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Configuración de host
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# Configuración de ippair
ippair:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# Configuración de decoder
decoder:
  teredo:
    enabled: true
    ports:
      dp: 3544

# Configuración de engine analysis
engine-analysis:
  rules-fast-pattern: yes
  rules: yes

# Configuración de Lua
lua:
  - luajit: yes
  - states: 128

# Configuración de profiling
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  prefilter:
    enabled: yes
    filename: prefilter_perf.log
    append: yes
  rulegroups:
    enabled: yes
    filename: rule_group_perf.log
    append: yes
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv
  locks:
    enabled: no
    filename: lock_stats.log
    append: yes
  pcap-log:
    enabled: no
    filename: pcaplog_stats.log
    append: yes

# Include classification and reference files
include: classification.config
include: reference.config

# Include rule files
default-rule-path: $RULES_DIR

rule-files:
  - suricata.rules
  - /var/lib/suricata/rules/emerging-all.rules

# Host table configuration
host-mode: auto

# Unix socket configuration
unix-command:
  enabled: auto

EOF

    log_message "Configuración principal de Suricata creada"
}

# Actualizar reglas de Suricata
update_rules() {
    log_message "Actualizando reglas de Suricata..."
    
    # Instalar suricata-update
    pip3 install pyyaml
    pip3 install suricata-update
    
    # Configurar suricata-update
    suricata-update update-sources
    suricata-update enable-source et/open
    suricata-update enable-source oisf/trafficid
    
    # Actualizar reglas
    suricata-update
    
    if [ $? -eq 0 ]; then
        log_message "Reglas actualizadas correctamente"
    else
        warning_message "Error al actualizar reglas, usando reglas por defecto"
    fi
}

# Configurar reglas personalizadas
configure_custom_rules() {
    log_message "Configurando reglas personalizadas para FEI..."
    
    # Crear archivo de reglas personalizadas
    cat > "/var/lib/suricata/rules/fei-custom.rules" << 'EOF'
# Reglas personalizadas para Sistema Ciberseguridad FEI
# Enfoque en amenazas comunes en entornos académicos

# Detección de escaneo de puertos
alert tcp any any -> $HOME_NET any (msg:"FEI: Posible escaneo de puertos"; flags:S,12; threshold: type both, track by_src, count 10, seconds 60; sid:1000001; rev:1;)

# Detección de ataques de fuerza bruta SSH
alert tcp any any -> $HOME_NET 22 (msg:"FEI: Intento de fuerza bruta SSH"; flow:to_server,established; content:"SSH"; offset:0; depth:3; threshold: type both, track by_src, count 5, seconds 60; sid:1000002; rev:1;)

# Detección de ataques de fuerza bruta HTTP
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Intento de fuerza bruta HTTP"; flow:to_server,established; content:"POST"; http_method; threshold: type both, track by_src, count 20, seconds 60; sid:1000003; rev:1;)

# Detección de intentos de SQLi
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Posible ataque SQLi"; flow:to_server,established; content:"union"; http_uri; nocase; content:"select"; http_uri; nocase; sid:1000004; rev:1;)

# Detección de XSS
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Posible ataque XSS"; flow:to_server,established; content:"<script"; http_uri; nocase; sid:1000005; rev:1;)

# Detección de comando injection
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Posible command injection"; flow:to_server,established; pcre:"/(\||;|`|\$\(|&&)/i"; content:!"Content-Type"; sid:1000006; rev:1;)

# Detección de descarga de malware conocido
alert http any any -> $HOME_NET any (msg:"FEI: Descarga de archivo ejecutable sospechoso"; flow:established,to_client; content:".exe"; http_uri; nocase; sid:1000007; rev:1;)

# Detección de comunicación con C&C conocidos
alert tcp $HOME_NET any -> any any (msg:"FEI: Posible comunicación con C&C"; flow:established,to_server; content:"User-Agent|3a 20|Bot"; http_header; sid:1000008; rev:1;)

# Detección de DNS tunneling
alert udp $HOME_NET any -> any 53 (msg:"FEI: Posible DNS tunneling"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; dsize:>100; sid:1000009; rev:1;)

# Detección de tráfico TOR
alert tcp $HOME_NET any -> any any (msg:"FEI: Posible tráfico TOR"; flow:established; content:"|16 03|"; offset:0; depth:2; content:"|01|"; offset:5; depth:1; sid:1000010; rev:1;)

# Detección de archivos ZIP con contraseña
alert http any any -> $HOME_NET any (msg:"FEI: Archivo ZIP protegido con contraseña"; flow:established,to_client; content:"PK"; offset:0; depth:2; content:"encrypted"; nocase; sid:1000011; rev:1;)

# Detección de acceso no autorizado a directorios sensibles
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Intento de acceso a directorio sensible"; flow:to_server,established; content:"/admin"; http_uri; nocase; sid:1000012; rev:1;)
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Intento de acceso a directorio sensible"; flow:to_server,established; content:"/backup"; http_uri; nocase; sid:1000013; rev:1;)
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"FEI: Intento de acceso a directorio sensible"; flow:to_server,established; content:"/config"; http_uri; nocase; sid:1000014; rev:1;)

# Detección de exfiltración de datos
alert tcp $HOME_NET any -> any any (msg:"FEI: Posible exfiltración de datos"; flow:established,to_server; dsize:>1000000; threshold: type both, track by_src, count 5, seconds 300; sid:1000015; rev:1;)

# Detección de actividad después de horas
alert tcp any any -> $HOME_NET any (msg:"FEI: Actividad fuera de horario académico"; threshold: type both, track by_src, count 100, seconds 3600; sid:1000016; rev:1;)
EOF

    # Agregar reglas personalizadas al archivo principal
    echo "include: /var/lib/suricata/rules/fei-custom.rules" >> "$SURICATA_CONFIG"
    
    log_message "Reglas personalizadas configuradas"
}

# Configurar servicios y arranque automático
configure_services() {
    log_message "Configurando servicios del sistema..."
    
    # Habilitar y arrancar Suricata
    systemctl enable suricata
    systemctl daemon-reload
    
    # Crear script de inicio personalizado
    cat > "/etc/systemd/system/suricata-fei.service" << EOF
[Unit]
Description=Suricata IDS/IPS FEI
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i $INTERFACE
ExecReload=/bin/kill -USR2 \$MAINPID
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=5
User=root
Group=root
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable suricata-fei
    
    log_message "Servicios configurados correctamente"
}

# Configurar logrotate
configure_logrotate() {
    log_message "Configurando rotación de logs..."
    
    cat > "/etc/logrotate.d/suricata-fei" << EOF
$LOG_DIR/*.log $LOG_DIR/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root root
    postrotate
        /bin/kill -USR2 \$(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF

    log_message "Rotación de logs configurada"
}

# Crear scripts de monitoreo
create_monitoring_scripts() {
    log_message "Creando scripts de monitoreo..."
    
    # Script de monitoreo en tiempo real
    cat > "/usr/local/bin/suricata-monitor.sh" << 'EOF'
#!/bin/bash
# Monitor en tiempo real de Suricata

echo "=== Monitor Suricata IDS/IPS - FEI ==="
echo "Presiona Ctrl+C para salir"
echo ""

while true; do
    clear
    echo "=== Estado del Servicio ==="
    systemctl status suricata-fei --no-pager -l
    
    echo ""
    echo "=== Estadísticas en Tiempo Real ==="
    if [ -f /var/log/suricata/stats.log ]; then
        tail -5 /var/log/suricata/stats.log
    else
        echo "No hay estadísticas disponibles"
    fi
    
    echo ""
    echo "=== Últimas Alertas ==="
    if [ -f /var/log/suricata/fast.log ]; then
        tail -10 /var/log/suricata/fast.log
    else
        echo "No hay alertas recientes"
    fi
    
    echo ""
    echo "Actualizado: $(date)"
    sleep 10
done
EOF

    chmod +x /usr/local/bin/suricata-monitor.sh
    
    # Script de análisis de logs
    cat > "/usr/local/bin/suricata-analysis.sh" << 'EOF'
#!/bin/bash
# Análisis de logs de Suricata

LOG_DIR="/var/log/suricata"
REPORT_FILE="/tmp/suricata-report-$(date +%Y%m%d_%H%M%S).txt"

echo "=== Reporte de Análisis Suricata IDS/IPS - FEI ===" > $REPORT_FILE
echo "Generado: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== Resumen de Alertas por Tipo ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/fast.log" ]; then
    awk '{print $6}' "$LOG_DIR/fast.log" | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE
else
    echo "No hay datos de alertas disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Top 10 IPs Atacantes ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/fast.log" ]; then
    awk '{print $8}' "$LOG_DIR/fast.log" | cut -d':' -f1 | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE
else
    echo "No hay datos de IPs disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Estadísticas de Protocolos ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/eve.json" ]; then
    grep '"proto":' "$LOG_DIR/eve.json" | cut -d'"' -f4 | sort | uniq -c | sort -nr >> $REPORT_FILE
else
    echo "No hay datos de protocolos disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Alertas de Alta Prioridad (Últimas 24h) ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/fast.log" ]; then
    grep "$(date -d '1 day ago' '+%m/%d')" "$LOG_DIR/fast.log" | grep -E "(CRITICAL|HIGH)" >> $REPORT_FILE
else
    echo "No hay alertas de alta prioridad" >> $REPORT_FILE
fi

echo "Reporte generado en: $REPORT_FILE"
cat $REPORT_FILE
EOF

    chmod +x /usr/local/bin/suricata-analysis.sh
    
    log_message "Scripts de monitoreo creados"
}

# Configurar integración con SIEM
configure_siem_integration() {
    log_message "Configurando integración con SIEM..."
    
    # Instalar Filebeat para envío de logs
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
    apt update -qq
    apt install -y filebeat
    
    # Configurar Filebeat para Suricata
    cat > "/etc/filebeat/filebeat.yml" << EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    logtype: suricata
    environment: fei-production

- type: log
  enabled: true
  paths:
    - /var/log/suricata/fast.log
  fields:
    logtype: suricata-alerts
    environment: fei-production

output.logstash:
  hosts: ["10.10.30.10:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

    systemctl enable filebeat
    systemctl start filebeat
    
    log_message "Integración con SIEM configurada"
}

# Crear herramientas de testing
create_testing_tools() {
    log_message "Creando herramientas de testing..."
    
    # Script de test de detección
    cat > "/usr/local/bin/test-suricata.sh" << 'EOF'
#!/bin/bash
# Script de testing para Suricata IDS/IPS

echo "=== Test de Detección Suricata IDS/IPS - FEI ==="
echo ""

# Test 1: Simulación de escaneo de puertos
echo "Test 1: Simulando escaneo de puertos..."
nmap -sS -O 10.10.30.20 2>/dev/null | head -10

sleep 2

# Test 2: Simulación de ataque HTTP
echo ""
echo "Test 2: Simulando ataque HTTP..."
curl -s "http://10.10.10.10/admin" > /dev/null
curl -s "http://10.10.10.10/backup" > /dev/null
curl -s "http://10.10.10.10/config" > /dev/null

sleep 2

# Test 3: Simulación de SQLi
echo ""
echo "Test 3: Simulando ataque SQLi..."
curl -s "http://10.10.10.10/search?q=1' union select 1,2,3--" > /dev/null

sleep 2

# Test 4: Simulación de XSS
echo ""
echo "Test 4: Simulando ataque XSS..."
curl -s "http://10.10.10.10/search?q=<script>alert(1)</script>" > /dev/null

sleep 5

echo ""
echo "Tests completados. Verificando detecciones..."
echo ""
echo "=== Últimas alertas generadas ==="
tail -10 /var/log/suricata/fast.log | grep "$(date '+%m/%d')"
EOF

    chmod +x /usr/local/bin/test-suricata.sh
    
    log_message "Herramientas de testing creadas"
}

# Configurar firewall para IDS/IPS
configure_firewall() {
    log_message "Configurando reglas de firewall específicas..."
    
    # Permitir tráfico de monitoreo
    iptables -A INPUT -p tcp --dport 8080 -s 10.10.30.0/24 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9200 -s 10.10.30.0/24 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 5044 -d 10.10.30.10 -j ACCEPT
    
    # Guardar reglas
    iptables-save > /etc/iptables/rules.v4
    
    log_message "Reglas de firewall configuradas"
}

# Función de verificación final
verify_installation() {
    log_message "Verificando instalación..."
    
    # Verificar servicio
    if systemctl is-active --quiet suricata-fei; then
        log_message "✓ Servicio Suricata activo"
    else
        error_message "✗ Servicio Suricata no está activo"
    fi
    
    # Verificar configuración
    if suricata -T -c "$SURICATA_CONFIG" >/dev/null 2>&1; then
        log_message "✓ Configuración válida"
    else
        error_message "✗ Error en configuración"
    fi
    
    # Verificar logs
    if [ -d "$LOG_DIR" ] && [ -w "$LOG_DIR" ]; then
        log_message "✓ Directorio de logs accesible"
    else
        error_message "✗ Problema con directorio de logs"
    fi
    
    # Verificar reglas
    rule_count=$(suricata --list-app-layer-protos 2>/dev/null | wc -l)
    log_message "✓ Protocolos soportados: $rule_count"
    
    # Mostrar resumen
    echo ""
    echo -e "${BLUE}=== RESUMEN DE INSTALACIÓN ===${NC}"
    echo "Sistema IDS/IPS: Suricata $(suricata --version 2>/dev/null | awk '{print $2}')"
    echo "Configuración: $SURICATA_CONFIG"
    echo "Logs: $LOG_DIR"
    echo "Interfaz monitoreada: $INTERFACE"
    echo "Red protegida: $HOME_NET"
    echo ""
    echo -e "${GREEN}Comandos útiles:${NC}"
    echo "  Monitor en tiempo real: /usr/local/bin/suricata-monitor.sh"
    echo "  Análisis de logs: /usr/local/bin/suricata-analysis.sh"
    echo "  Test de detección: /usr/local/bin/test-suricata.sh"
    echo "  Estado del servicio: systemctl status suricata-fei"
    echo "  Logs en tiempo real: tail -f $LOG_DIR/fast.log"
}

# Función principal
main() {
    echo -e "${BLUE}"
    echo "############################################################################"
    echo "#                    Configuración IDS/IPS Suricata - FEI                 #"
    echo "#                     Sistema Integral de Ciberseguridad                  #"
    echo "############################################################################"
    echo -e "${NC}"
    
    # Verificaciones previas
    check_root
    
    # Proceso de instalación
    log_message "Iniciando configuración de IDS/IPS Suricata..."
    
    backup_configs
    update_system
    install_dependencies
    install_suricata
    configure_suricata
    update_rules
    configure_custom_rules
    configure_services
    configure_logrotate
    create_monitoring_scripts
    configure_siem_integration
    create_testing_tools
    configure_firewall
    
    # Iniciar servicios
    log_message "Iniciando servicios..."
    systemctl restart suricata-fei
    systemctl restart filebeat
    
    # Verificación final
    verify_installation
    
    echo ""
    echo -e "${GREEN}¡Configuración de IDS/IPS Suricata completada exitosamente!${NC}"
    echo ""
    echo -e "${YELLOW}Próximos pasos:${NC}"
    echo "1. Verificar que el tráfico se está monitoreando: /usr/local/bin/suricata-monitor.sh"
    echo "2. Ejecutar tests de detección: /usr/local/bin/test-suricata.sh"
    echo "3. Configurar alertas automáticas en el SIEM"
    echo "4. Revisar y ajustar reglas personalizadas según necesidades"
    echo ""
    
    log_message "Configuración de IDS/IPS completada"
}

# Ejecutar función principal
main "$@"
