#!/bin/bash
# Script de configuración automatizada para Firewall FEI
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Descripción: Configura iptables como firewall principal

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Verificar si se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

log "Iniciando configuración del Firewall FEI..."

# Actualizar sistema
log "Actualizando sistema..."
apt update && apt upgrade -y

# Instalar herramientas necesarias
log "Instalando herramientas necesarias..."
apt install -y iptables-persistent netfilter-persistent fail2ban ufw rsyslog curl wget vim

# Habilitar forwarding de IP
log "Habilitando IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.send_redirects=0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.send_redirects=0' >> /etc/sysctl.conf
sysctl -p

# Crear directorio para scripts de firewall
mkdir -p /etc/firewall
mkdir -p /var/log/firewall

# Crear script principal de firewall
log "Creando script de firewall..."
cat > /etc/firewall/firewall.sh << 'EOF'
#!/bin/bash
# Script principal de Firewall FEI
# Configuración de iptables

# Limpiar todas las reglas existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Establecer políticas por defecto (denegar todo)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir tráfico de loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir tráfico establecido y relacionado
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# === REGLAS DE GESTIÓN ===
# SSH desde red de gestión únicamente
iptables -A INPUT -p tcp -s 10.10.30.0/24 --dport 22 -j ACCEPT

# SNMP desde red de gestión
iptables -A INPUT -p udp -s 10.10.30.0/24 --dport 161 -j ACCEPT

# === REGLAS PARA DMZ ===
# HTTP y HTTPS hacia servidor web en DMZ
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.10 --dport 443 -j ACCEPT

# SSH desde red de gestión hacia DMZ
iptables -A FORWARD -p tcp -s 10.10.30.0/24 -d 10.10.10.0/24 --dport 22 -j ACCEPT

# DNS desde DMZ hacia exterior
iptables -A FORWARD -p udp -s 10.10.10.0/24 --dport 53 -j ACCEPT
iptables -A FORWARD -p tcp -s 10.10.10.0/24 --dport 53 -j ACCEPT

# === REGLAS PARA LAN INTERNA ===
# Proxy web desde LAN
iptables -A FORWARD -p tcp -s 10.10.20.0/24 -d 10.10.20.10 --dport 3128 -j ACCEPT

# DNS desde LAN
iptables -A FORWARD -p udp -s 10.10.20.0/24 --dport 53 -j ACCEPT
iptables -A FORWARD -p tcp -s 10.10.20.0/24 --dport 53 -j ACCEPT

# LDAP hacia servidor de autenticación
iptables -A FORWARD -p tcp -s 10.10.20.0/24 -d 10.10.20.40 --dport 389 -j ACCEPT
iptables -A FORWARD -p tcp -s 10.10.20.0/24 -d 10.10.20.40 --dport 636 -j ACCEPT

# === REGLAS DE NAT ===
# NAT para DMZ
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ens33 -j MASQUERADE

# NAT para LAN Interna
iptables -t nat -A POSTROUTING -s 10.10.20.0/24 -o ens33 -j MASQUERADE

# NAT para Red de Gestión
iptables -t nat -A POSTROUTING -s 10.10.30.0/24 -o ens33 -j MASQUERADE

# === PORT FORWARDING (DNAT) ===
# Redirigir HTTP hacia servidor web
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination 10.10.10.10:80

# Redirigir HTTPS hacia servidor web
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 443 -j DNAT --to-destination 10.10.10.10:443

# === PROTECCIÓN CONTRA ATAQUES ===
# Protección contra port scanning
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Protección contra ping flooding
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Protección contra SYN flooding
iptables -A INPUT -p tcp --syn -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# === LOGGING ===
# Log intentos de conexión denegados (limitado para evitar spam)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-INPUT-DROP: " --log-level 4
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "FW-FORWARD-DROP: " --log-level 4

echo "$(date): Firewall rules aplicadas correctamente" >> /var/log/firewall/firewall.log
EOF

# Hacer el script ejecutable
chmod +x /etc/firewall/firewall.sh

# Crear script de backup de reglas
log "Creando script de backup..."
cat > /etc/firewall/backup-rules.sh << 'EOF'
#!/bin/bash
# Script para respaldar reglas de iptables

BACKUP_DIR="/var/backups/firewall"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Respaldar reglas actuales
iptables-save > $BACKUP_DIR/iptables-$DATE.rules
ip6tables-save > $BACKUP_DIR/ip6tables-$DATE.rules

echo "$(date): Backup de reglas creado en $BACKUP_DIR/iptables-$DATE.rules"
EOF

chmod +x /etc/firewall/backup-rules.sh

# Crear script de restauración
log "Creando script de restauración..."
cat > /etc/firewall/restore-rules.sh << 'EOF'
#!/bin/bash
# Script para restaurar reglas de iptables desde backup

if [ $# -eq 0 ]; then
    echo "Uso: $0 <archivo_de_backup>"
    echo "Archivos disponibles:"
    ls -la /var/backups/firewall/
    exit 1
fi

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Archivo $BACKUP_FILE no encontrado"
    exit 1
fi

echo "Restaurando reglas desde $BACKUP_FILE..."
iptables-restore < $BACKUP_FILE
echo "Reglas restauradas exitosamente"
EOF

chmod +x /etc/firewall/restore-rules.sh

# Configurar fail2ban
log "Configurando fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 1800

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/error.log

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/access.log
bantime = 86400
maxretry = 1

[apache-noscript]
enabled = true
port = http,https
logpath = /var/log/apache2/access.log

[apache-overflows]
enabled = true
port = http,https
logpath = /var/log/apache2/access.log
maxretry = 2
EOF

# Configurar logging específico del firewall
log "Configurando logging..."
cat > /etc/rsyslog.d/30-firewall.conf << 'EOF'
# Logging específico del firewall
:msg,contains,"FW-INPUT-DROP" /var/log/firewall/input-drops.log
:msg,contains,"FW-FORWARD-DROP" /var/log/firewall/forward-drops.log
& stop
EOF

# Crear logrotate para logs del firewall
cat > /etc/logrotate.d/firewall << 'EOF'
/var/log/firewall/*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Configurar red estática
log "Configurando interfaces de red..."
cat > /etc/network/interfaces << 'EOF'
# Configuración de red para Firewall FEI

auto lo
iface lo inet loopback

# WAN - Conexión hacia router
auto ens33
iface ens33 inet static
    address 192.168.1.2
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4

# DMZ - Red desmilitarizada
auto ens34
iface ens34 inet static
    address 10.10.10.1
    netmask 255.255.255.0

# LAN - Red interna
auto ens35
iface ens35 inet static
    address 10.10.20.1
    netmask 255.255.255.0

# Management - Red de gestión
auto ens36
iface ens36 inet static
    address 10.10.30.1
    netmask 255.255.255.0
EOF

# Crear script de monitoreo del firewall
log "Creando script de monitoreo..."
cat > /usr/local/bin/firewall-monitor.sh << 'EOF'
#!/bin/bash
# Script de monitoreo del firewall

LOG_FILE="/var/log/firewall/monitor.log"
ALERT_THRESHOLD=100

# Función para enviar alertas
send_alert() {
    local message="$1"
    echo "$(date): ALERT - $message" >> $LOG_FILE
    logger "FIREWALL ALERT: $message"
    # Aquí se podría agregar envío por email
}

# Verificar servicios críticos
check_services() {
    if ! systemctl is-active --quiet netfilter-persistent; then
        send_alert "Servicio netfilter-persistent no está activo"
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        send_alert "Servicio fail2ban no está activo"
    fi
}

# Verificar cantidad de conexiones bloqueadas
check_blocked_connections() {
    local drops=$(grep "FW-INPUT-DROP" /var/log/firewall/input-drops.log 2>/dev/null | tail -100 | wc -l)
    if [ $drops -gt $ALERT_THRESHOLD ]; then
        send_alert "Alto número de conexiones bloqueadas: $drops en la última hora"
    fi
}

# Verificar conectividad
check_connectivity() {
    if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        send_alert "Sin conectividad hacia Internet"
    fi
}

# Ejecutar verificaciones
check_services
check_blocked_connections
check_connectivity

echo "$(date): Monitoreo completado" >> $LOG_FILE
EOF

chmod +x /usr/local/bin/firewall-monitor.sh

# Agregar monitoreo al crontab
log "Configurando monitoreo automático..."
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/firewall-monitor.sh") | crontab -

# Crear script de inicio
log "Configurando script de inicio..."
cat > /etc/systemd/system/firewall-fei.service << 'EOF'
[Unit]
Description=Firewall FEI
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/firewall/firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Habilitar servicio personalizado
systemctl enable firewall-fei.service

# Ejecutar configuración de firewall
log "Aplicando reglas de firewall..."
/etc/firewall/firewall.sh

# Guardar reglas para persistencia
iptables-save > /etc/iptables/rules.v4

# Reiniciar servicios
systemctl restart rsyslog
systemctl enable fail2ban
systemctl start fail2ban

# Crear primer backup
/etc/firewall/backup-rules.sh

log "Configuración del firewall completada exitosamente!"
log "Archivos importantes:"
log "  - Script principal: /etc/firewall/firewall.sh"
log "  - Backup de reglas: /etc/firewall/backup-rules.sh"
log "  - Restaurar reglas: /etc/firewall/restore-rules.sh"
log "  - Monitor: /usr/local/bin/firewall-monitor.sh"
log "  - Logs: /var/log/firewall/"

warn "IMPORTANTE:"
warn "1. Verificar conectividad SSH desde red de gestión (10.10.30.0/24)"
warn "2. Confirmar que las interfaces de red estén correctamente configuradas"
warn "3. Probar conectividad entre segmentos de red"
warn "4. Revisar logs en /var/log/firewall/ para verificar funcionamiento"

echo
log "Reiniciando interfaces de red..."
systemctl restart networking

log "¡Configuración completada! El firewall está activo y funcionando."
