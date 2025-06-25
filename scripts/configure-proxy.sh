#!/bin/bash
# Script de configuración automatizada para Servidor Proxy FEI
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Descripción: Configura Squid como proxy transparente con filtrado de contenido

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

log "Iniciando configuración del Servidor Proxy FEI..."

# Actualizar sistema
log "Actualizando sistema..."
apt update && apt upgrade -y

# Instalar Squid y herramientas relacionadas
log "Instalando Squid y herramientas de filtrado..."
apt install -y squid squidguard squid-langpack apache2-utils \
    fail2ban ufw rsyslog logrotate \
    curl wget dnsutils net-tools htop

# Configurar red estática
log "Configurando interfaz de red..."
cat > /etc/network/interfaces << 'EOF'
# Configuración de red para Servidor Proxy FEI

auto lo
iface lo inet loopback

# Interfaz LAN
auto ens33
iface ens33 inet static
    address 10.10.20.10
    netmask 255.255.255.0
    gateway 10.10.20.1
    dns-nameservers 8.8.8.8 8.8.4.4
EOF

# Configurar hostname
echo "proxy-fei" > /etc/hostname
echo "127.0.0.1 proxy-fei proxy-fei.fei.local" >> /etc/hosts

# Crear directorios necesarios
mkdir -p /etc/squid/lists
mkdir -p /var/log/squid-custom
mkdir -p /var/cache/squid-custom

# Backup de configuración original
cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

# Configurar Squid
log "Configurando Squid Proxy..."
cat > /etc/squid/squid.conf << 'EOF'
# Configuración de Squid para FEI
# Proxy transparente con filtrado de contenido

# Puerto del proxy
http_port 3128

# Puerto transparente para interceptar tráfico HTTP
http_port 3129 intercept

# Puerto para HTTPS bump (opcional)
https_port 3130 cert=/etc/squid/ssl/squid.pem

# ACLs de red - Definir redes autorizadas
acl localnet src 10.10.20.0/24      # Red LAN
acl localnet src 10.10.30.0/24      # Red de gestión

# ACLs de tiempo - Horarios de acceso
acl business_hours time MTWHF 08:00-18:00
acl weekend time SA 09:00-17:00
acl sunday time SU 10:00-16:00

# ACLs de puertos seguros
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # puertos altos
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http

# Método CONNECT
acl CONNECT method CONNECT

# ACLs de sitios bloqueados
acl blocked_sites dstdomain "/etc/squid/lists/blocked_sites"
acl adult_sites dstdomain "/etc/squid/lists/adult_sites"
acl social_media dstdomain "/etc/squid/lists/social_media"
acl streaming_sites dstdomain "/etc/squid/lists/streaming_sites"

# ACLs de sitios permitidos (whitelist)
acl allowed_sites dstdomain "/etc/squid/lists/allowed_sites"
acl educational_sites dstdomain "/etc/squid/lists/educational_sites"

# ACLs de tipos de archivo bloqueados
acl blocked_files urlpath_regex -i "/etc/squid/lists/blocked_extensions"

# ACLs para autenticación por grupos (opcional)
# acl admin_users proxy_auth "/etc/squid/lists/admin_users"
# acl student_users proxy_auth "/etc/squid/lists/student_users"

# === REGLAS DE ACCESO ===

# Denegar acceso a puertos inseguros
http_access deny !Safe_ports

# Denegar CONNECT a puertos que no sean SSL
http_access deny CONNECT !SSL_ports

# Permitir acceso de gestión desde localhost
http_access allow localhost manager
http_access deny manager

# Sitios siempre permitidos (educativos, institucionales)
http_access allow educational_sites

# Bloquear sitios de contenido adulto siempre
http_access deny adult_sites

# Reglas de horario de trabajo
http_access allow localnet business_hours !blocked_sites !social_media !streaming_sites
http_access allow localnet weekend !blocked_sites !adult_sites
http_access allow localnet sunday educational_sites

# Bloquear archivos potencialmente peligrosos
http_access deny blocked_files

# Permitir acceso desde redes locales en horario restringido
http_access allow localnet educational_sites

# Denegar todo lo demás
http_access deny all

# === CONFIGURACIÓN DE CACHE ===

# Directorio de cache
cache_dir ufs /var/spool/squid 1024 16 256

# Tamaño máximo de objeto en cache
maximum_object_size 50 MB
maximum_object_size_in_memory 512 KB

# Memoria para cache
cache_mem 256 MB

# === CONFIGURACIÓN DE LOGGING ===

# Logs de acceso
access_log /var/log/squid/access.log squid
access_log /var/log/squid-custom/detailed.log combined

# Log de cache
cache_log /var/log/squid/cache.log

# Store log (opcional)
# cache_store_log /var/log/squid/store.log

# === CONFIGURACIÓN DE HEADERS ===

# Ocultar información del cliente
forwarded_for delete
via off

# Headers de seguridad
request_header_access Referer deny all
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all

# === CONFIGURACIÓN DE RENDIMIENTO ===

# Límites de conexión
http_access_log_limit 100
client_lifetime 1 hour
half_closed_clients off

# DNS
dns_nameservers 8.8.8.8 8.8.4.4

# === CONFIGURACIÓN DE TRANSPARENCIA ===

# Para proxy transparente
always_direct allow all

# === CONFIGURACIÓN DE ERRORES ===

# Página de error personalizada
error_directory /etc/squid/errors/es

# === CONFIGURACIÓN DE AUTENTICACIÓN (Opcional) ===
# auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
# auth_param basic children 5
# auth_param basic realm Proxy FEI
# auth_param basic credentialsttl 2 hours

# === CONFIGURACIÓN ADICIONAL ===

# Refresh patterns para cache
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# Configuración de memoria
memory_pools on
memory_pools_limit 64 MB

# Configuración de shutdown
shutdown_lifetime 10 seconds
EOF

# Crear listas de filtrado
log "Creando listas de filtrado de contenido..."

# Lista de sitios bloqueados
cat > /etc/squid/lists/blocked_sites << 'EOF'
# Sitios generalmente bloqueados
torrent.com
thepiratebay.org
kickass.to
1337x.to
extratorrent.cc
rarbg.to
# Gambling
bet365.com
pokerstars.com
888casino.com
# Malware conocido
malware-traffic-analysis.net
# Otros
4chan.org
EOF

# Lista de sitios para adultos
cat > /etc/squid/lists/adult_sites << 'EOF'
# Contenido para adultos
.xxx
.porn
.sex
.adult
pornhub.com
xvideos.com
xnxx.com
youporn.com
redtube.com
EOF

# Lista de redes sociales
cat > /etc/squid/lists/social_media << 'EOF'
# Redes sociales (bloqueadas en horario de trabajo)
facebook.com
www.facebook.com
m.facebook.com
instagram.com
www.instagram.com
twitter.com
www.twitter.com
x.com
www.x.com
tiktok.com
www.tiktok.com
snapchat.com
www.snapchat.com
linkedin.com
www.linkedin.com
EOF

# Lista de sitios de streaming
cat > /etc/squid/lists/streaming_sites << 'EOF'
# Sitios de streaming (restringidos en horario de trabajo)
youtube.com
www.youtube.com
m.youtube.com
netflix.com
www.netflix.com
hulu.com
www.hulu.com
twitch.tv
www.twitch.tv
spotify.com
www.spotify.com
EOF

# Lista de sitios educativos (siempre permitidos)
cat > /etc/squid/lists/educational_sites << 'EOF'
# Sitios educativos y académicos
.edu
.edu.mx
.gob.mx
uv.mx
www.uv.mx
google.com
www.google.com
scholar.google.com
wikipedia.org
www.wikipedia.org
es.wikipedia.org
github.com
www.github.com
stackoverflow.com
www.stackoverflow.com
coursera.org
www.coursera.org
edx.org
www.edx.org
khanacademy.org
www.khanacademy.org
mit.edu
www.mit.edu
stanford.edu
www.stanford.edu
ieee.org
www.ieee.org
acm.org
www.acm.org
EOF

# Lista de sitios siempre permitidos
cat > /etc/squid/lists/allowed_sites << 'EOF'
# Sitios institucionales y necesarios
fei.local
www.fei.local
localhost
ubuntu.com
www.ubuntu.com
debian.org
www.debian.org
microsoft.com
www.microsoft.com
office.com
www.office.com
zoom.us
www.zoom.us
teams.microsoft.com
EOF

# Lista de extensiones de archivo bloqueadas
cat > /etc/squid/lists/blocked_extensions << 'EOF'
# Extensiones de archivo potencialmente peligrosas
\.(exe|bat|cmd|com|pif|scr|vbs|js|jar|msi)$
\.(torrent)$
\.(rar|zip|7z).*\.(exe|bat|cmd)$
EOF

# Configurar permisos de archivos
chown -R proxy:proxy /etc/squid/lists
chmod 644 /etc/squid/lists/*

# Configurar directorios de log
chown -R proxy:proxy /var/log/squid-custom
chmod 755 /var/log/squid-custom

# Crear páginas de error personalizadas en español
log "Configurando páginas de error personalizadas..."
mkdir -p /etc/squid/errors/es

cat > /etc/squid/errors/es/ERR_ACCESS_DENIED << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Acceso Denegado - Proxy FEI</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: #e74c3c; color: white; padding: 20px; text-align: center; border-radius: 5px; margin-bottom: 20px; }
        .content { text-align: center; }
        .details { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; text-align: left; }
        .contact { background: #3498db; color: white; padding: 15px; border-radius: 5px; margin-top: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚫 Acceso Denegado</h1>
        </div>
        
        <div class="content">
            <h2>Su solicitud ha sido bloqueada</h2>
            <p>El contenido que intenta acceder está restringido por las políticas de seguridad de la FEI.</p>
            
            <div class="details">
                <strong>Detalles del bloqueo:</strong><br>
                URL: %U<br>
                Hora: %T<br>
                Cliente: %i<br>
                Motivo: Sitio no autorizado según políticas institucionales
            </div>
            
            <h3>Razones comunes de bloqueo:</h3>
            <ul style="text-align: left;">
                <li>Contenido no relacionado con actividades académicas</li>
                <li>Sitios de entretenimiento durante horario de trabajo</li>
                <li>Contenido inapropiado o potencialmente peligroso</li>
                <li>Sitios que consumen excesivo ancho de banda</li>
            </ul>
            
            <div class="contact">
                <strong>¿Necesita acceso a este sitio?</strong><br>
                Contacte al administrador de TI: ti@fei.edu<br>
                Extensión: 2502
            </div>
        </div>
    </div>
</body>
</html>
EOF

# Configurar fail2ban para Squid
log "Configurando fail2ban para Squid..."
cat > /etc/fail2ban/filter.d/squid.conf << 'EOF'
[Definition]
failregex = ^%(__prefix_line)s.*TCP_DENIED.* <HOST> .*$
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/squid.conf << 'EOF'
[squid]
enabled = true
port = 3128,3129,3130
filter = squid
logpath = /var/log/squid/access.log
maxretry = 10
bantime = 3600
findtime = 600
EOF

# Configurar logrotate para Squid
cat > /etc/logrotate.d/squid-fei << 'EOF'
/var/log/squid/*.log /var/log/squid-custom/*.log {
    daily
    compress
    delaycompress
    rotate 30
    missingok
    notifempty
    create 644 proxy proxy
    postrotate
        /usr/sbin/squid -k rotate 2>/dev/null || true
    endscript
}
EOF

# Crear script de monitoreo
log "Creando script de monitoreo para Squid..."
cat > /usr/local/bin/proxy-monitor.sh << 'EOF'
#!/bin/bash
# Script de monitoreo para Squid Proxy FEI

LOG_FILE="/var/log/proxy-monitor.log"
ALERT_FILE="/var/log/proxy-alerts.log"
SQUID_ACCESS_LOG="/var/log/squid/access.log"

# Función para logging
log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> $LOG_FILE
}

# Función para alertas
send_alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ALERT - $message" >> $ALERT_FILE
    logger "PROXY-ALERT: $message"
}

# Verificar estado de Squid
check_squid_status() {
    if ! systemctl is-active --quiet squid; then
        send_alert "Servicio Squid no está activo"
        return 1
    fi
    
    # Verificar si responde en el puerto
    if ! netstat -ln | grep -q ":3128 "; then
        send_alert "Squid no está escuchando en puerto 3128"
        return 1
    fi
    
    return 0
}

# Verificar uso de memoria
check_memory_usage() {
    local memory_usage=$(ps aux | grep squid | grep -v grep | awk '{sum+=$4} END {print sum}')
    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        send_alert "Alto uso de memoria por Squid: ${memory_usage}%"
    fi
}

# Verificar espacio de cache
check_cache_usage() {
    local cache_usage=$(du -sh /var/spool/squid 2>/dev/null | awk '{print $1}')
    local cache_usage_mb=$(du -sm /var/spool/squid 2>/dev/null | awk '{print $1}')
    
    if [ "$cache_usage_mb" -gt 900 ]; then
        send_alert "Cache de Squid cerca del límite: ${cache_usage}"
    fi
}

# Analizar logs para detectar patrones sospechosos
analyze_access_patterns() {
    if [ ! -f "$SQUID_ACCESS_LOG" ]; then
        return
    fi
    
    # Detectar muchas conexiones denegadas del mismo IP
    local denied_ips=$(tail -1000 "$SQUID_ACCESS_LOG" | grep "TCP_DENIED" | awk '{print $3}' | sort | uniq -c | sort -rn | head -5)
    
    while read -r count ip; do
        if [ "$count" -gt 50 ]; then
            send_alert "IP $ip con $count intentos denegados en últimas 1000 entradas"
        fi
    done <<< "$denied_ips"
    
    # Detectar intentos de acceso a sitios maliciosos
    local malware_attempts=$(tail -1000 "$SQUID_ACCESS_LOG" | grep -iE "(malware|virus|trojan|botnet)" | wc -l)
    if [ "$malware_attempts" -gt 0 ]; then
        send_alert "Detectados $malware_attempts intentos de acceso a sitios maliciosos"
    fi
}

# Generar estadísticas de uso
generate_usage_stats() {
    if [ ! -f "$SQUID_ACCESS_LOG" ]; then
        return
    fi
    
    local total_requests=$(tail -1000 "$SQUID_ACCESS_LOG" | wc -l)
    local denied_requests=$(tail -1000 "$SQUID_ACCESS_LOG" | grep "TCP_DENIED" | wc -l)
    local allowed_requests=$((total_requests - denied_requests))
    
    log_event "Estadísticas (últimas 1000 entradas): Total: $total_requests, Permitidas: $allowed_requests, Denegadas: $denied_requests"
}

# Ejecutar verificaciones
check_squid_status
if [ $? -eq 0 ]; then
    check_memory_usage
    check_cache_usage
    analyze_access_patterns
    generate_usage_stats
    log_event "Monitoreo completado - Squid funcionando correctamente"
else
    log_event "Monitoreo completado - Squid con problemas"
fi
EOF

chmod +x /usr/local/bin/proxy-monitor.sh

# Crear script de estadísticas diarias
cat > /usr/local/bin/proxy-stats.sh << 'EOF'
#!/bin/bash
# Script para generar estadísticas diarias del proxy

SQUID_ACCESS_LOG="/var/log/squid/access.log"
STATS_DIR="/var/log/proxy-stats"
DATE=$(date +%Y-%m-%d)

mkdir -p $STATS_DIR

if [ ! -f "$SQUID_ACCESS_LOG" ]; then
    echo "Log de acceso no encontrado: $SQUID_ACCESS_LOG"
    exit 1
fi

# Generar reporte diario
{
    echo "=== REPORTE DIARIO DE PROXY FEI - $DATE ==="
    echo
    
    echo "Top 10 sitios más visitados:"
    awk '{print $7}' "$SQUID_ACCESS_LOG" | grep -v "^-$" | sort | uniq -c | sort -rn | head -10
    echo
    
    echo "Top 10 IPs con más solicitudes:"
    awk '{print $3}' "$SQUID_ACCESS_LOG" | sort | uniq -c | sort -rn | head -10
    echo
    
    echo "Solicitudes denegadas por categoría:"
    grep "TCP_DENIED" "$SQUID_ACCESS_LOG" | awk '{print $7}' | sort | uniq -c | sort -rn | head -10
    echo
    
    echo "Resumen de códigos de respuesta:"
    awk '{print $4}' "$SQUID_ACCESS_LOG" | sort | uniq -c | sort -rn
    echo
    
    echo "Horario de mayor actividad:"
    awk '{print substr($1,12,2)}' "$SQUID_ACCESS_LOG" | sort | uniq -c | sort -rn
    
} > "$STATS_DIR/daily-report-$DATE.txt"

echo "Reporte generado: $STATS_DIR/daily-report-$DATE.txt"
EOF

chmod +x /usr/local/bin/proxy-stats.sh

# Configurar crontab para monitoreo y estadísticas
log "Configurando tareas programadas..."
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/proxy-monitor.sh") | crontab -
(crontab -l 2>/dev/null; echo "0 6 * * * /usr/local/bin/proxy-stats.sh") | crontab -

# Configurar UFW (firewall local)
log "Configurando firewall local..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.10.20.0/24 to any port 3128
ufw allow from 10.10.30.0/24 to any port 22
ufw allow from 10.10.30.0/24 to any port 3128

# Inicializar cache de Squid
log "Inicializando cache de Squid..."
squid -z

# Configurar y reiniciar servicios
log "Configurando servicios..."
systemctl enable squid
systemctl restart squid
systemctl enable fail2ban
systemctl restart fail2ban
systemctl restart networking

# Esperar a que Squid inicie completamente
sleep 10

# Verificar funcionamiento
log "Verificando funcionamiento del proxy..."
if netstat -ln | grep -q ":3128 "; then
    log "✓ Squid está escuchando en puerto 3128"
else
    error "✗ Squid no está escuchando en puerto 3128"
fi

if systemctl is-active --quiet squid; then
    log "✓ Servicio Squid está activo"
else
    error "✗ Servicio Squid no está activo"
fi

# Probar conectividad básica
if curl -x localhost:3128 -s http://www.google.com > /dev/null; then
    log "✓ Proxy responde correctamente"
else
    warn "⚠ Proxy puede tener problemas de conectividad"
fi

# Mostrar información de configuración
echo
info "=== CONFIGURACIÓN COMPLETADA ==="
info "Servidor Proxy: 10.10.20.10:3128"
info "Configuración: /etc/squid/squid.conf"
info "Listas de filtrado: /etc/squid/lists/"
info "Logs de acceso: /var/log/squid/access.log"
info "Logs personalizados: /var/log/squid-custom/"
info "Monitor: /usr/local/bin/proxy-monitor.sh"
info "Estadísticas: /usr/local/bin/proxy-stats.sh"
echo
warn "=== CONFIGURACIÓN DE CLIENTES ==="
warn "Configurar navegadores para usar proxy:"
warn "  HTTP Proxy: 10.10.20.10:3128"
warn "  HTTPS Proxy: 10.10.20.10:3128"
warn "  No usar proxy para: localhost, 127.0.0.1, 10.10.*.*, fei.local"
echo
info "=== ARCHIVOS DE CONFIGURACIÓN IMPORTANTES ==="
info "- Sitios bloqueados: /etc/squid/lists/blocked_sites"
info "- Sitios educativos: /etc/squid/lists/educational_sites"
info "- Redes sociales: /etc/squid/lists/social_media"
info "- Streaming: /etc/squid/lists/streaming_sites"
echo
log "¡Configuración del servidor proxy completada exitosamente!"
