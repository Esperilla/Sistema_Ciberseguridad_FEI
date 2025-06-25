#!/bin/bash
# Script de configuración automatizada para SIEM FEI (ELK Stack)
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Descripción: Instala y configura Elasticsearch, Logstash y Kibana para monitoreo centralizado

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARN $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Verificar si se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Verificar recursos del sistema
check_resources() {
    local ram_mb=$(free -m | awk 'NR==2{printf "%d", $2}')
    local disk_gb=$(df / | awk 'NR==2{printf "%d", $4/1024/1024}')
    
    if [ $ram_mb -lt 3500 ]; then
        error "Se requieren al menos 4GB de RAM. Disponible: ${ram_mb}MB"
        exit 1
    fi
    
    if [ $disk_gb -lt 20 ]; then
        error "Se requieren al menos 20GB de espacio libre. Disponible: ${disk_gb}GB"
        exit 1
    fi
    
    log "Recursos verificados: RAM: ${ram_mb}MB, Disco: ${disk_gb}GB"
}

log "Iniciando configuración del SIEM FEI (ELK Stack)..."

# Verificar recursos
check_resources

# Actualizar sistema
log "Actualizando sistema..."
apt update && apt upgrade -y

# Instalar Java 11 (requerido para ELK)
log "Instalando Java 11..."
apt install -y openjdk-11-jdk curl wget apt-transport-https gnupg

# Configurar JAVA_HOME
echo 'JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64' >> /etc/environment
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64

# Configurar red estática
log "Configurando interfaz de red..."
cat > /etc/network/interfaces << 'EOF'
# Configuración de red para Servidor SIEM FEI

auto lo
iface lo inet loopback

# Interfaz de gestión
auto ens33
iface ens33 inet static
    address 10.10.30.10
    netmask 255.255.255.0
    gateway 10.10.30.1
    dns-nameservers 8.8.8.8 8.8.4.4
EOF

# Configurar hostname
echo "siem-fei" > /etc/hostname
echo "127.0.0.1 siem-fei siem-fei.fei.local" >> /etc/hosts

# Agregar repositorio de Elastic
log "Agregando repositorio de Elastic..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
apt update

# Instalar Elasticsearch
log "Instalando Elasticsearch..."
apt install -y elasticsearch

# Configurar Elasticsearch
log "Configurando Elasticsearch..."
cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
# Configuración de Elasticsearch para SIEM FEI

# Cluster
cluster.name: fei-siem-cluster
node.name: siem-node-1

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Network
network.host: 10.10.30.10
http.port: 9200

# Discovery
discovery.type: single-node
cluster.initial_master_nodes: ["siem-node-1"]

# Security
xpack.security.enabled: false
xpack.security.enrollment.enabled: false

# Memory
bootstrap.memory_lock: true

# HTTP
http.cors.enabled: true
http.cors.allow-origin: "*"
http.cors.allow-headers: "Authorization, X-Requested-With, Content-Length, Content-Type"
EOF

# Configurar límites de memoria para Elasticsearch
cat > /etc/elasticsearch/jvm.options.d/heap.options << 'EOF'
# Configuración de heap para Elasticsearch
# Asignar 1GB (ajustar según RAM disponible)
-Xms1g
-Xmx1g
EOF

# Configurar systemd para Elasticsearch
mkdir -p /etc/systemd/system/elasticsearch.service.d/
cat > /etc/systemd/system/elasticsearch.service.d/override.conf << 'EOF'
[Service]
LimitMEMLOCK=infinity
EOF

# Instalar Logstash
log "Instalando Logstash..."
apt install -y logstash

# Configurar Logstash
log "Configurando Logstash..."

# Pipeline principal para syslog
cat > /etc/logstash/conf.d/01-syslog-input.conf << 'EOF'
# Input para logs de syslog
input {
  udp {
    port => 514
    type => "syslog"
  }
  
  tcp {
    port => 514
    type => "syslog"
  }
  
  # Input para logs de Apache
  beats {
    port => 5044
    type => "apache"
  }
  
  # Input para logs de Squid
  file {
    path => "/var/log/squid/access.log"
    start_position => "beginning"
    type => "squid"
    tags => ["squid", "proxy"]
  }
}
EOF

cat > /etc/logstash/conf.d/02-filter.conf << 'EOF'
# Filtros para procesamiento de logs
filter {
  # Procesar logs de syslog
  if [type] == "syslog" {
    grok {
      match => { 
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message_body}" 
      }
      overwrite => [ "message" ]
    }
    
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
    
    # Detectar eventos de seguridad
    if [program] == "sshd" {
      if "Failed password" in [message_body] {
        mutate {
          add_tag => [ "security", "ssh_failed_login" ]
          add_field => { "event_type" => "authentication_failure" }
          add_field => { "severity" => "medium" }
        }
      }
      
      if "Accepted password" in [message_body] {
        mutate {
          add_tag => [ "security", "ssh_successful_login" ]
          add_field => { "event_type" => "authentication_success" }
          add_field => { "severity" => "low" }
        }
      }
    }
    
    # Detectar eventos de firewall
    if "FW-INPUT-DROP" in [message_body] or "FW-FORWARD-DROP" in [message_body] {
      mutate {
        add_tag => [ "security", "firewall_drop" ]
        add_field => { "event_type" => "network_blocked" }
        add_field => { "severity" => "medium" }
      }
    }
  }
  
  # Procesar logs de Squid
  if [type] == "squid" {
    grok {
      match => { 
        "message" => "%{POSINT:timestamp}%{SPACE}%{POSINT:duration} %{IPORHOST:client_ip} %{WORD:squid_request_status}/%{POSINT:http_status_code} %{POSINT:reply_size} %{WORD:request_method} %{URIPROTO:request_protocol}://%{URIHOST:request_domain}(?:%{URIPATH:request_path})?(?:%{URIPARAM:request_params})? %{NOTSPACE:user} %{WORD:squid_hierarchy_status}/%{IPORHOST:server_ip} %{NOTSPACE:content_type}"
      }
    }
    
    date {
      match => [ "timestamp", "UNIX" ]
    }
    
    # Detectar accesos denegados
    if [squid_request_status] == "TCP_DENIED" {
      mutate {
        add_tag => [ "security", "proxy_denied" ]
        add_field => { "event_type" => "access_denied" }
        add_field => { "severity" => "low" }
      }
    }
    
    # Detectar sitios sospechosos
    if [request_domain] =~ /malware|virus|trojan|botnet/ {
      mutate {
        add_tag => [ "security", "malicious_domain" ]
        add_field => { "event_type" => "malware_attempt" }
        add_field => { "severity" => "high" }
      }
    }
  }
  
  # Procesar logs de Apache
  if [type] == "apache" {
    grok {
      match => { 
        "message" => "%{COMMONAPACHELOG}" 
      }
    }
    
    # Detectar ataques web
    if [request] =~ /(\.\.|script|javascript|<script|union.*select|exec|eval)/ {
      mutate {
        add_tag => [ "security", "web_attack" ]
        add_field => { "event_type" => "web_attack_attempt" }
        add_field => { "severity" => "high" }
      }
    }
    
    # Detectar errores 4xx y 5xx
    if [response] >= 400 {
      mutate {
        add_tag => [ "error" ]
        add_field => { "event_type" => "http_error" }
        add_field => { "severity" => "medium" }
      }
    }
  }
  
  # Enriquecimiento de GeoIP
  geoip {
    source => "client_ip"
    target => "geoip"
  }
}
EOF

cat > /etc/logstash/conf.d/03-output.conf << 'EOF'
# Output hacia Elasticsearch
output {
  elasticsearch {
    hosts => ["10.10.30.10:9200"]
    
    # Índices por tipo de log y fecha
    if [type] == "syslog" {
      index => "syslog-%{+YYYY.MM.dd}"
    } else if [type] == "squid" {
      index => "proxy-%{+YYYY.MM.dd}"
    } else if [type] == "apache" {
      index => "web-%{+YYYY.MM.dd}"
    } else {
      index => "logs-%{+YYYY.MM.dd}"
    }
    
    # Template para optimización
    template_name => "fei-logs"
    template_overwrite => true
  }
  
  # Output de debug (opcional)
  if "security" in [tags] {
    file {
      path => "/var/log/logstash/security-events.log"
      codec => rubydebug
    }
  }
}
EOF

# Configurar heap de Logstash
cat > /etc/logstash/jvm.options.d/heap.options << 'EOF'
# Configuración de heap para Logstash
-Xms512m
-Xmx512m
EOF

# Instalar Kibana
log "Instalando Kibana..."
apt install -y kibana

# Configurar Kibana
log "Configurando Kibana..."
cat > /etc/kibana/kibana.yml << 'EOF'
# Configuración de Kibana para SIEM FEI

# Server
server.port: 5601
server.host: "10.10.30.10"
server.name: "kibana-fei"

# Elasticsearch
elasticsearch.hosts: ["http://10.10.30.10:9200"]

# Logging
logging.dest: /var/log/kibana/kibana.log

# Security
xpack.security.enabled: false

# Interface
server.rewriteBasePath: false

# Monitoring
monitoring.enabled: false

# Maps (opcional)
map.includeElasticMapsService: true
EOF

# Crear directorios de logs
mkdir -p /var/log/kibana /var/log/logstash
chown kibana:kibana /var/log/kibana
chown logstash:logstash /var/log/logstash

# Instalar Filebeat para envío de logs locales
log "Instalando Filebeat..."
apt install -y filebeat

# Configurar Filebeat
cat > /etc/filebeat/filebeat.yml << 'EOF'
# Configuración de Filebeat para SIEM FEI

# Inputs
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/kern.log
  fields:
    log_type: system
    source_host: siem-fei

- type: log
  enabled: true
  paths:
    - /var/log/elasticsearch/*.log
  fields:
    log_type: elasticsearch
    source_host: siem-fei

- type: log
  enabled: true
  paths:
    - /var/log/kibana/*.log
  fields:
    log_type: kibana
    source_host: siem-fei

# Output
output.logstash:
  hosts: ["10.10.30.10:5044"]

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

# Configurar rsyslog para recibir logs remotos
log "Configurando rsyslog para logs remotos..."
cat > /etc/rsyslog.d/49-remote.conf << 'EOF'
# Configuración para recibir logs remotos

# Habilitar UDP syslog reception
$ModLoad imudp
$UDPServerRun 514
$UDPServerAddress 10.10.30.10

# Habilitar TCP syslog reception
$ModLoad imtcp
$InputTCPServerRun 514
$InputTCPServerBindRuleset remote

# Template para logs remotos
$template RemoteLogs,"/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log"

# Rutear logs remotos
if $fromhost-ip != '127.0.0.1' then ?RemoteLogs
& stop
EOF

# Crear directorios para logs remotos
mkdir -p /var/log/remote
chown syslog:adm /var/log/remote

# Crear script de configuración inicial de Kibana
log "Creando script de configuración inicial..."
cat > /usr/local/bin/setup-kibana-dashboards.sh << 'EOF'
#!/bin/bash
# Script para configurar dashboards iniciales en Kibana

KIBANA_URL="http://10.10.30.10:5601"

# Esperar a que Kibana esté disponible
echo "Esperando a que Kibana esté disponible..."
while ! curl -s $KIBANA_URL > /dev/null; do
    sleep 5
done

echo "Kibana disponible, configurando index patterns..."

# Crear index patterns
curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern/syslog-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "syslog-*",
      "timeFieldName": "@timestamp"
    }
  }'

curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern/proxy-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "proxy-*",
      "timeFieldName": "@timestamp"
    }
  }'

curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern/web-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "web-*",
      "timeFieldName": "@timestamp"
    }
  }'

echo "Index patterns creados exitosamente"
EOF

chmod +x /usr/local/bin/setup-kibana-dashboards.sh

# Crear script de monitoreo del SIEM
cat > /usr/local/bin/siem-monitor.sh << 'EOF'
#!/bin/bash
# Script de monitoreo para SIEM FEI

LOG_FILE="/var/log/siem-monitor.log"
ALERT_FILE="/var/log/siem-alerts.log"

# Función para logging
log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> $LOG_FILE
}

# Función para alertas
send_alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ALERT - $message" >> $ALERT_FILE
    logger "SIEM-ALERT: $message"
}

# Verificar servicios del stack ELK
check_elk_services() {
    services=("elasticsearch" "logstash" "kibana" "filebeat")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            send_alert "Servicio $service no está activo"
        fi
    done
}

# Verificar conectividad de Elasticsearch
check_elasticsearch() {
    if ! curl -s http://10.10.30.10:9200/_cluster/health > /dev/null; then
        send_alert "Elasticsearch no responde"
        return 1
    fi
    
    # Verificar estado del cluster
    local health=$(curl -s http://10.10.30.10:9200/_cluster/health | jq -r '.status' 2>/dev/null || echo "unknown")
    if [ "$health" != "green" ] && [ "$health" != "yellow" ]; then
        send_alert "Estado del cluster Elasticsearch: $health"
    fi
}

# Verificar uso de disco de índices
check_index_size() {
    local indices_size=$(curl -s "http://10.10.30.10:9200/_cat/indices?h=store.size" | awk '{sum += $1} END {print sum}')
    # Convertir a MB si es necesario y alertar si > 5GB
    if [ "$indices_size" -gt 5000 ]; then
        send_alert "Tamaño de índices grande: ${indices_size}MB"
    fi
}

# Verificar logs de seguridad recientes
check_security_events() {
    local security_events=$(tail -100 /var/log/logstash/security-events.log 2>/dev/null | wc -l)
    if [ "$security_events" -gt 50 ]; then
        send_alert "Alto número de eventos de seguridad: $security_events en últimas 100 entradas"
    fi
}

# Ejecutar verificaciones
check_elk_services
check_elasticsearch
check_index_size
check_security_events

log_event "Monitoreo SIEM completado"
EOF

chmod +x /usr/local/bin/siem-monitor.sh

# Crear script de limpieza de índices antiguos
cat > /usr/local/bin/cleanup-indices.sh << 'EOF'
#!/bin/bash
# Script para limpiar índices antiguos de Elasticsearch

RETENTION_DAYS=30
ES_URL="http://10.10.30.10:9200"

# Obtener índices más antiguos que RETENTION_DAYS
indices_to_delete=$(curl -s "$ES_URL/_cat/indices?h=index,creation.date.string" | \
    awk -v retention_days=$RETENTION_DAYS '
    {
        # Convertir fecha de creación a timestamp
        cmd = "date -d \"" $2 "\" +%s"
        cmd | getline creation_timestamp
        close(cmd)
        
        # Obtener timestamp actual
        cmd = "date +%s"
        cmd | getline current_timestamp
        close(cmd)
        
        # Calcular días transcurridos
        days_old = (current_timestamp - creation_timestamp) / 86400
        
        if (days_old > retention_days) {
            print $1
        }
    }')

# Eliminar índices antiguos
for index in $indices_to_delete; do
    echo "Eliminando índice antiguo: $index"
    curl -X DELETE "$ES_URL/$index"
done

echo "Limpieza de índices completada"
EOF

chmod +x /usr/local/bin/cleanup-indices.sh

# Configurar tareas programadas
log "Configurando tareas programadas..."
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/siem-monitor.sh") | crontab -
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/cleanup-indices.sh") | crontab -

# Configurar firewall local
log "Configurando firewall local..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.10.30.0/24 to any port 22
ufw allow from 10.10.10.0/24 to any port 9200
ufw allow from 10.10.20.0/24 to any port 9200
ufw allow from 10.10.30.0/24 to any port 5601
ufw allow from 10.10.30.0/24 to any port 5044
ufw allow 514/udp
ufw allow 514/tcp

# Configurar límites del sistema
log "Configurando límites del sistema..."
cat >> /etc/security/limits.conf << 'EOF'
# Límites para Elasticsearch
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536

# Límites para Logstash
logstash soft nofile 65536
logstash hard nofile 65536
EOF

# Configurar systemd services
systemctl daemon-reload
systemctl enable elasticsearch
systemctl enable logstash
systemctl enable kibana
systemctl enable filebeat

# Reiniciar red
systemctl restart networking

# Iniciar servicios en orden
log "Iniciando servicios ELK..."
systemctl start elasticsearch

# Esperar a que Elasticsearch esté disponible
log "Esperando a que Elasticsearch inicie..."
sleep 30

# Verificar que Elasticsearch esté funcionando
max_attempts=12
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://10.10.30.10:9200/_cluster/health > /dev/null; then
        log "✓ Elasticsearch está funcionando"
        break
    fi
    sleep 10
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    error "✗ Elasticsearch no pudo iniciar correctamente"
    exit 1
fi

# Iniciar Logstash
systemctl start logstash
sleep 20

# Iniciar Kibana
systemctl start kibana
sleep 20

# Iniciar Filebeat
systemctl start filebeat

# Reiniciar rsyslog para aplicar configuración remota
systemctl restart rsyslog

# Configurar dashboards iniciales
log "Configurando dashboards iniciales..."
sleep 30
/usr/local/bin/setup-kibana-dashboards.sh

# Verificación final
log "Verificando funcionamiento del SIEM..."

# Verificar Elasticsearch
if curl -s http://10.10.30.10:9200/_cluster/health | grep -q '"status":"green\|yellow"'; then
    log "✓ Elasticsearch funcionando correctamente"
else
    warn "⚠ Elasticsearch puede tener problemas"
fi

# Verificar Kibana
if curl -s http://10.10.30.10:5601 > /dev/null; then
    log "✓ Kibana funcionando correctamente"
else
    warn "⚠ Kibana puede tener problemas"
fi

# Verificar Logstash
if systemctl is-active --quiet logstash; then
    log "✓ Logstash funcionando correctamente"
else
    warn "⚠ Logstash puede tener problemas"
fi

# Mostrar información de configuración
echo
info "=== CONFIGURACIÓN DEL SIEM COMPLETADA ==="
info "Elasticsearch: http://10.10.30.10:9200"
info "Kibana: http://10.10.30.10:5601"
info "Syslog UDP/TCP: 10.10.30.10:514"
info "Beats input: 10.10.30.10:5044"
echo
info "=== ACCESO A KIBANA ==="
info "URL: http://10.10.30.10:5601"
info "No se requiere autenticación (configuración de laboratorio)"
echo
info "=== INDEX PATTERNS CREADOS ==="
info "- syslog-*: Logs del sistema"
info "- proxy-*: Logs del proxy Squid"
info "- web-*: Logs del servidor web"
echo
warn "=== CONFIGURACIÓN DE CLIENTES ==="
warn "Para enviar logs al SIEM, configurar en otros servidores:"
warn "  Syslog: *.* @@10.10.30.10:514"
warn "  Filebeat: hosts: ['10.10.30.10:5044']"
echo
info "=== ARCHIVOS DE CONFIGURACIÓN ==="
info "- Elasticsearch: /etc/elasticsearch/elasticsearch.yml"
info "- Logstash: /etc/logstash/conf.d/"
info "- Kibana: /etc/kibana/kibana.yml"
info "- Filebeat: /etc/filebeat/filebeat.yml"
echo
info "=== LOGS DE MONITOREO ==="
info "- Monitor SIEM: /var/log/siem-monitor.log"
info "- Alertas: /var/log/siem-alerts.log"
info "- Eventos de seguridad: /var/log/logstash/security-events.log"
echo
log "¡Configuración del SIEM completada exitosamente!"
log "Acceda a Kibana en http://10.10.30.10:5601 para comenzar a visualizar los logs"
