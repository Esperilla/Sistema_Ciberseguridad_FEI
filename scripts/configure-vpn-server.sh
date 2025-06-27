#!/bin/bash

# Script de Configuración VPN Server - Sistema Ciberseguridad FEI

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

# Variables de configuración
VPN_DIR="/etc/openvpn"
SERVER_CONFIG="$VPN_DIR/server.conf"
CLIENT_CONFIG_DIR="/etc/openvpn/client-configs"
KEY_DIR="/etc/openvpn/easy-rsa/keys"
SERVER_IP="10.10.20.30"
VPN_NETWORK="10.8.0.0"
VPN_NETMASK="255.255.255.0"
VPN_PORT="1194"
INTERFACE="tun0"

# Función para logging
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/openvpn-install.log
}

error_message() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/openvpn-install.log
}

warning_message() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/openvpn-install.log
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
    
    if [ -f "$SERVER_CONFIG" ]; then
        cp "$SERVER_CONFIG" "${SERVER_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        log_message "Backup de server.conf creado"
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
        openvpn \
        easy-rsa \
        iptables \
        iptables-persistent \
        ufw \
        curl \
        wget \
        openssl \
        ca-certificates \
        gnupg \
        lsb-release \
        net-tools \
        bridge-utils
        
    if [ $? -eq 0 ]; then
        log_message "Dependencias instaladas correctamente"
    else
        error_message "Error al instalar dependencias"
        exit 1
    fi
}

# Configurar Easy-RSA para gestión de certificados
setup_easy_rsa() {
    log_message "Configurando Easy-RSA..."
    
    # Crear directorio de Easy-RSA
    mkdir -p /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    
    # Copiar scripts de Easy-RSA
    cp -r /usr/share/easy-rsa/* .
    
    # Crear archivo vars para configuración
    cat > vars << EOF
# Variables de configuración para Easy-RSA - FEI
export KEY_COUNTRY="MX"
export KEY_PROVINCE="Veracruz"
export KEY_CITY="Xalapa"
export KEY_ORG="Universidad Veracruzana"
export KEY_OU="Facultad de Estadistica e Informatica"
export KEY_NAME="FEI-VPN-Server"
export KEY_EMAIL="admin@fei.uv.mx"
export KEY_SIZE=2048
export CA_EXPIRE=3650
export KEY_EXPIRE=365
EOF

    # Configurar permisos
    chmod 700 /etc/openvpn/easy-rsa
    
    log_message "Easy-RSA configurado correctamente"
}

# Generar certificados y claves
generate_certificates() {
    log_message "Generando certificados y claves..."
    
    cd /etc/openvpn/easy-rsa
    source ./vars
    
    # Limpiar configuración anterior si existe
    ./clean-all
    
    # Generar CA (Autoridad Certificadora)
    log_message "Generando Autoridad Certificadora..."
    ./build-ca --batch
    
    # Generar certificado y clave del servidor
    log_message "Generando certificado del servidor..."
    ./build-key-server --batch server
    
    # Generar parámetros Diffie-Hellman
    log_message "Generando parámetros Diffie-Hellman..."
    ./build-dh
    
    # Generar clave TLS-Auth para mayor seguridad
    log_message "Generando clave TLS-Auth..."
    openvpn --genkey --secret keys/ta.key
    
    # Crear directorio de certificados
    mkdir -p /etc/openvpn/certs
    
    # Copiar certificados necesarios
    cp keys/ca.crt /etc/openvpn/certs/
    cp keys/server.crt /etc/openvpn/certs/
    cp keys/server.key /etc/openvpn/certs/
    cp keys/dh2048.pem /etc/openvpn/certs/
    cp keys/ta.key /etc/openvpn/certs/
    
    # Configurar permisos de seguridad
    chmod 600 /etc/openvpn/certs/server.key
    chmod 600 /etc/openvpn/certs/ta.key
    
    log_message "Certificados generados correctamente"
}

# Configurar servidor OpenVPN
configure_openvpn_server() {
    log_message "Configurando servidor OpenVPN..."
    
    cat > "$SERVER_CONFIG" << EOF
# Configuración del Servidor OpenVPN - Sistema Ciberseguridad FEI
# Universidad Veracruzana - Facultad de Estadística e Informática

# Puerto y protocolo
port $VPN_PORT
proto udp

# Tipo de interfaz
dev tun

# Certificados y claves
ca /etc/openvpn/certs/ca.crt
cert /etc/openvpn/certs/server.crt
key /etc/openvpn/certs/server.key
dh /etc/openvpn/certs/dh2048.pem

# Red VPN
server $VPN_NETWORK $VPN_NETMASK

# Configuración de rutas
push "route 10.10.0.0 255.255.0.0"
push "route 192.168.1.0 255.255.255.0"

# DNS servers para clientes
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 10.10.30.10"

# Redireccionar todo el tráfico a través de la VPN (opcional)
# push "redirect-gateway def1 bypass-dhcp"

# Pool de direcciones para clientes
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Configuración de seguridad
tls-auth /etc/openvpn/certs/ta.key 0
cipher AES-256-CBC
auth SHA256
tls-version-min 1.2

# Configuración de compresión
comp-lzo

# Configuración de usuarios
duplicate-cn
max-clients 50

# Configuración de timeouts
keepalive 10 120
ping-timer-rem
persist-tun
persist-key

# Configuración de privilegios
user nobody
group nogroup

# Logging
status /var/log/openvpn/status.log 20
log-append /var/log/openvpn/server.log
verb 3
mute 10

# Configuración de scripting
script-security 2
up /etc/openvpn/scripts/server-up.sh
down /etc/openvpn/scripts/server-down.sh

# Configuración de cliente
client-config-dir /etc/openvpn/ccd

# Configuración de management
management 127.0.0.1 7505

# Configuración adicional de seguridad
remote-cert-tls client
tls-crypt /etc/openvpn/certs/ta.key
auth-nocache
EOF

    log_message "Configuración del servidor OpenVPN creada"
}

# Crear scripts de inicio y parada
create_scripts() {
    log_message "Creando scripts de gestión..."
    
    # Crear directorio de scripts
    mkdir -p /etc/openvpn/scripts
    
    # Script de inicio
    cat > "/etc/openvpn/scripts/server-up.sh" << 'EOF'
#!/bin/bash
# Script ejecutado al iniciar OpenVPN

# Configurar IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configurar NAT para clientes VPN
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Guardar reglas
iptables-save > /etc/iptables/rules.v4

# Log del evento
logger "OpenVPN Server FEI iniciado - $(date)"
EOF

    # Script de parada
    cat > "/etc/openvpn/scripts/server-down.sh" << 'EOF'
#!/bin/bash
# Script ejecutado al parar OpenVPN

# Limpiar reglas de iptables específicas de VPN
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null
iptables -D INPUT -i tun0 -j ACCEPT 2>/dev/null
iptables -D FORWARD -i tun0 -j ACCEPT 2>/dev/null
iptables -D FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -D FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null

# Log del evento
logger "OpenVPN Server FEI detenido - $(date)"
EOF

    chmod +x /etc/openvpn/scripts/*.sh
    
    log_message "Scripts de gestión creados"
}

# Configurar firewall
configure_firewall() {
    log_message "Configurando firewall para VPN..."
    
    # Habilitar IP forwarding permanentemente
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configurar reglas de iptables
    iptables -A INPUT -p udp --dport $VPN_PORT -j ACCEPT
    iptables -A INPUT -i tun0 -j ACCEPT
    iptables -A FORWARD -i tun0 -j ACCEPT
    iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    
    # Guardar reglas
    iptables-save > /etc/iptables/rules.v4
    
    log_message "Firewall configurado para VPN"
}

# Crear directorio de configuraciones de cliente
setup_client_configs() {
    log_message "Configurando directorio de clientes..."
    
    # Crear directorios necesarios
    mkdir -p "$CLIENT_CONFIG_DIR"
    mkdir -p "$CLIENT_CONFIG_DIR/files"
    mkdir -p "$CLIENT_CONFIG_DIR/keys"
    mkdir -p /etc/openvpn/ccd
    
    # Configuración base para clientes
    cat > "$CLIENT_CONFIG_DIR/base.conf" << EOF
# Configuración base para clientes VPN - FEI
client
dev tun
proto udp
remote $SERVER_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
mute-replay-warnings
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
cipher AES-256-CBC
auth SHA256
verb 3
mute 10
comp-lzo
auth-nocache
remote-cert-tls server
EOF

    log_message "Configuración de clientes preparada"
}

# Función para generar certificado de cliente
generate_client_cert() {
    local client_name=$1
    
    if [ -z "$client_name" ]; then
        error_message "Nombre de cliente requerido"
        return 1
    fi
    
    log_message "Generando certificado para cliente: $client_name"
    
    cd /etc/openvpn/easy-rsa
    source ./vars
    
    # Generar certificado del cliente
    ./build-key --batch "$client_name"
    
    if [ $? -eq 0 ]; then
        log_message "Certificado para $client_name generado correctamente"
        return 0
    else
        error_message "Error al generar certificado para $client_name"
        return 1
    fi
}

# Función para crear archivo de configuración de cliente
create_client_config() {
    local client_name=$1
    
    if [ -z "$client_name" ]; then
        error_message "Nombre de cliente requerido"
        return 1
    fi
    
    log_message "Creando configuración para cliente: $client_name"
    
    local client_dir="$CLIENT_CONFIG_DIR/files/$client_name"
    mkdir -p "$client_dir"
    
    # Copiar certificados del cliente
    cp /etc/openvpn/easy-rsa/keys/ca.crt "$client_dir/"
    cp /etc/openvpn/easy-rsa/keys/$client_name.crt "$client_dir/"
    cp /etc/openvpn/easy-rsa/keys/$client_name.key "$client_dir/"
    cp /etc/openvpn/easy-rsa/keys/ta.key "$client_dir/"
    
    # Crear configuración del cliente
    cp "$CLIENT_CONFIG_DIR/base.conf" "$client_dir/$client_name.ovpn"
    
    # Crear configuración unificada (embedded certificates)
    cat > "$client_dir/${client_name}-unified.ovpn" << EOF
# Configuración VPN Cliente - $client_name
# Sistema Ciberseguridad FEI - Universidad Veracruzana

client
dev tun
proto udp
remote $SERVER_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
mute-replay-warnings
cipher AES-256-CBC
auth SHA256
verb 3
mute 10
comp-lzo
auth-nocache
remote-cert-tls server

<ca>
$(cat $client_dir/ca.crt)
</ca>

<cert>
$(cat $client_dir/$client_name.crt)
</cert>

<key>
$(cat $client_dir/$client_name.key)
</key>

<tls-auth>
$(cat $client_dir/ta.key)
</tls-auth>
key-direction 1
EOF

    log_message "Configuración para $client_name creada en $client_dir"
}

# Crear clientes predefinidos
create_default_clients() {
    log_message "Creando clientes predefinidos..."
    
    # Lista de clientes por defecto
    local clients=("admin-fei" "profesor-fei" "estudiante-fei" "invitado-fei")
    
    for client in "${clients[@]}"; do
        generate_client_cert "$client"
        create_client_config "$client"
    done
    
    log_message "Clientes predefinidos creados"
}

# Configurar servicios
configure_services() {
    log_message "Configurando servicios del sistema..."
    
    # Crear directorio de logs
    mkdir -p /var/log/openvpn
    chown nobody:nogroup /var/log/openvpn
    
    # Habilitar y configurar servicio
    systemctl enable openvpn@server
    systemctl daemon-reload
    
    log_message "Servicios configurados correctamente"
}

# Configurar logrotate para logs de VPN
configure_logrotate() {
    log_message "Configurando rotación de logs..."
    
    cat > "/etc/logrotate.d/openvpn-fei" << EOF
/var/log/openvpn/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 nobody nogroup
    postrotate
        systemctl reload openvpn@server
    endscript
}
EOF

    log_message "Rotación de logs configurada"
}

# Crear herramientas de administración
create_admin_tools() {
    log_message "Creando herramientas de administración..."
    
    # Script de monitoreo de VPN
    cat > "/usr/local/bin/vpn-monitor.sh" << 'EOF'
#!/bin/bash
# Monitor VPN Server FEI

echo "=== Monitor Servidor VPN - FEI ==="
echo "Presiona Ctrl+C para salir"
echo ""

while true; do
    clear
    echo "=== Estado del Servicio ==="
    systemctl status openvpn@server --no-pager -l
    
    echo ""
    echo "=== Clientes Conectados ==="
    if [ -f /var/log/openvpn/status.log ]; then
        echo "Clientes activos:"
        grep "^CLIENT_LIST" /var/log/openvpn/status.log | awk -F',' '{print $2 " - " $3 " (" $4 ")"}'
        echo ""
        echo "Estadísticas de routing:"
        grep "^ROUTING_TABLE" /var/log/openvpn/status.log | awk -F',' '{print $2 " -> " $3}'
    else
        echo "No hay información de estado disponible"
    fi
    
    echo ""
    echo "=== Estadísticas de Red ==="
    echo "Interfaz tun0:"
    ip addr show tun0 2>/dev/null || echo "Interfaz tun0 no disponible"
    
    echo ""
    echo "=== Últimos Logs ==="
    if [ -f /var/log/openvpn/server.log ]; then
        tail -5 /var/log/openvpn/server.log
    else
        echo "No hay logs disponibles"
    fi
    
    echo ""
    echo "Actualizado: $(date)"
    sleep 10
done
EOF

    chmod +x /usr/local/bin/vpn-monitor.sh
    
    # Script de gestión de clientes
    cat > "/usr/local/bin/vpn-client-manager.sh" << 'EOF'
#!/bin/bash
# Gestor de clientes VPN FEI

CLIENT_CONFIG_DIR="/etc/openvpn/client-configs"
EASY_RSA_DIR="/etc/openvpn/easy-rsa"

show_help() {
    echo "Uso: $0 [OPCIÓN] [CLIENTE]"
    echo ""
    echo "Opciones:"
    echo "  create <nombre>    Crear nuevo cliente VPN"
    echo "  revoke <nombre>    Revocar cliente VPN"
    echo "  list              Listar clientes existentes"
    echo "  status            Mostrar estado del servidor"
    echo "  help              Mostrar esta ayuda"
}

create_client() {
    local client_name=$1
    
    if [ -z "$client_name" ]; then
        echo "Error: Nombre de cliente requerido"
        exit 1
    fi
    
    echo "Creando cliente: $client_name"
    
    cd $EASY_RSA_DIR
    source ./vars
    
    # Generar certificado
    ./build-key --batch "$client_name"
    
    if [ $? -eq 0 ]; then
        # Crear configuración
        local client_dir="$CLIENT_CONFIG_DIR/files/$client_name"
        mkdir -p "$client_dir"
        
        cp keys/ca.crt "$client_dir/"
        cp keys/$client_name.crt "$client_dir/"
        cp keys/$client_name.key "$client_dir/"
        cp keys/ta.key "$client_dir/"
        cp $CLIENT_CONFIG_DIR/base.conf "$client_dir/$client_name.ovpn"
        
        echo "Cliente $client_name creado exitosamente"
        echo "Archivos disponibles en: $client_dir"
    else
        echo "Error al crear cliente $client_name"
    fi
}

revoke_client() {
    local client_name=$1
    
    if [ -z "$client_name" ]; then
        echo "Error: Nombre de cliente requerido"
        exit 1
    fi
    
    echo "Revocando cliente: $client_name"
    
    cd $EASY_RSA_DIR
    source ./vars
    
    ./revoke-full "$client_name"
    
    if [ $? -eq 0 ]; then
        echo "Cliente $client_name revocado exitosamente"
        systemctl restart openvpn@server
    else
        echo "Error al revocar cliente $client_name"
    fi
}

list_clients() {
    echo "=== Clientes VPN Configurados ==="
    
    if [ -d "$CLIENT_CONFIG_DIR/files" ]; then
        ls -1 "$CLIENT_CONFIG_DIR/files" | while read client; do
            if [ -d "$CLIENT_CONFIG_DIR/files/$client" ]; then
                echo "  - $client"
            fi
        done
    else
        echo "No hay clientes configurados"
    fi
    
    echo ""
    echo "=== Clientes Conectados ==="
    if [ -f /var/log/openvpn/status.log ]; then
        grep "^CLIENT_LIST" /var/log/openvpn/status.log | awk -F',' '{print "  - " $2 " (" $3 ")"}'
    else
        echo "No hay información de conexiones disponible"
    fi
}

show_status() {
    echo "=== Estado del Servidor VPN ==="
    systemctl status openvpn@server --no-pager
    
    echo ""
    echo "=== Estadísticas ==="
    if [ -f /var/log/openvpn/status.log ]; then
        echo "Clientes conectados: $(grep -c "^CLIENT_LIST" /var/log/openvpn/status.log)"
        echo "Última actualización: $(grep "^TIME" /var/log/openvpn/status.log | cut -d',' -f2)"
    fi
}

case "$1" in
    create)
        create_client "$2"
        ;;
    revoke)
        revoke_client "$2"
        ;;
    list)
        list_clients
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Opción no válida: $1"
        show_help
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-client-manager.sh
    
    log_message "Herramientas de administración creadas"
}

# Configurar integración con SIEM
configure_siem_integration() {
    log_message "Configurando integración con SIEM..."
    
    # Configurar rsyslog para VPN
    cat > "/etc/rsyslog.d/30-openvpn.conf" << EOF
# Configuración rsyslog para OpenVPN - FEI
if \$programname == 'ovpn-server' then /var/log/openvpn/server.log
if \$programname == 'ovpn-server' then @@10.10.30.10:514
& stop
EOF

    systemctl restart rsyslog
    
    log_message "Integración con SIEM configurada"
}

# Función de verificación final
verify_installation() {
    log_message "Verificando instalación..."
    
    # Verificar servicio
    if systemctl is-active --quiet openvpn@server; then
        log_message "✓ Servicio OpenVPN activo"
    else
        warning_message "✗ Servicio OpenVPN no está activo"
    fi
    
    # Verificar configuración
    if openvpn --config "$SERVER_CONFIG" --test-crypto >/dev/null 2>&1; then
        log_message "✓ Configuración válida"
    else
        error_message "✗ Error en configuración"
    fi
    
    # Verificar certificados
    if [ -f "/etc/openvpn/certs/server.crt" ]; then
        log_message "✓ Certificados del servidor disponibles"
        cert_expire=$(openssl x509 -in /etc/openvpn/certs/server.crt -noout -enddate | cut -d'=' -f2)
        log_message "✓ Certificado válido hasta: $cert_expire"
    else
        error_message "✗ Certificados del servidor no encontrados"
    fi
    
    # Verificar interfaz de red
    if ip link show tun0 >/dev/null 2>&1; then
        log_message "✓ Interfaz tun0 activa"
    else
        warning_message "✗ Interfaz tun0 no disponible (normal si el servicio no está iniciado)"
    fi
    
    # Verificar puerto
    if netstat -ulnp | grep -q ":$VPN_PORT "; then
        log_message "✓ Puerto $VPN_PORT en escucha"
    else
        warning_message "✗ Puerto $VPN_PORT no está en escucha"
    fi
    
    # Mostrar resumen
    echo ""
    echo -e "${BLUE}=== RESUMEN DE INSTALACIÓN ===${NC}"
    echo "Servidor VPN: OpenVPN $(openvpn --version 2>&1 | head -1 | awk '{print $2}')"
    echo "Configuración: $SERVER_CONFIG"
    echo "Puerto: $VPN_PORT (UDP)"
    echo "Red VPN: $VPN_NETWORK"
    echo "Dirección servidor: $SERVER_IP"
    echo ""
    echo -e "${GREEN}Comandos útiles:${NC}"
    echo "  Monitor VPN: /usr/local/bin/vpn-monitor.sh"
    echo "  Gestión clientes: /usr/local/bin/vpn-client-manager.sh"
    echo "  Estado servicio: systemctl status openvpn@server"
    echo "  Clientes conectados: cat /var/log/openvpn/status.log"
    echo ""
    echo -e "${GREEN}Archivos de cliente en:${NC}"
    echo "  $CLIENT_CONFIG_DIR/files/"
}

# Función principal
main() {
    echo -e "${BLUE}"
    echo "############################################################################"
    echo "#                     Configuración Servidor VPN - FEI                    #"
    echo "#                     Sistema Integral de Ciberseguridad                  #"
    echo "############################################################################"
    echo -e "${NC}"
    
    # Verificaciones previas
    check_root
    
    # Proceso de instalación
    log_message "Iniciando configuración del servidor VPN..."
    
    backup_configs
    update_system
    install_dependencies
    setup_easy_rsa
    generate_certificates
    configure_openvpn_server
    create_scripts
    configure_firewall
    setup_client_configs
    create_default_clients
    configure_services
    configure_logrotate
    create_admin_tools
    configure_siem_integration
    
    # Iniciar servicio
    log_message "Iniciando servicio OpenVPN..."
    systemctl restart openvpn@server
    
    # Esperar un momento para que el servicio se inicie
    sleep 5
    
    # Verificación final
    verify_installation
    
    echo ""
    echo -e "${GREEN}¡Configuración del servidor VPN completada exitosamente!${NC}"
    echo ""
    echo -e "${YELLOW}Próximos pasos:${NC}"
    echo "1. Verificar estado del servidor: systemctl status openvpn@server"
    echo "2. Distribuir configuraciones de cliente a usuarios autorizados"
    echo "3. Probar conexión desde cliente externo"
    echo "4. Configurar monitoreo en SIEM"
    echo ""
    echo -e "${YELLOW}Configuraciones de cliente disponibles en:${NC}"
    echo "$CLIENT_CONFIG_DIR/files/"
    echo ""
    
    log_message "Configuración de servidor VPN completada"
}

# Ejecutar función principal
main "$@"
