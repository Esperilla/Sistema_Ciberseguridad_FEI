#!/bin/bash

##############################################################################
# Script de Monitoreo Integral - Sistema Ciberseguridad FEI
# 
# Descripción: Monitoreo centralizado de todos los componentes del sistema
#              de ciberseguridad de la FEI
# 
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Versión: 1.0
# Sistema: Debian 12 (Para ejecutar desde cualquier VM de gestión)
##############################################################################

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables de configuración de IPs
ROUTER_IP="192.168.1.1"
FIREWALL_IP="192.168.1.2"
WEBSERVER_IP="10.10.10.10"
HONEYPOT_IP="10.10.10.20"
PROXY_IP="10.10.20.10"
VPN_IP="10.10.20.30"
AUTH_IP="10.10.20.40"
USER_WS_IP="10.10.20.50"
SIEM_IP="10.10.30.10"
IDS_IP="10.10.30.20"
ADMIN_WS_IP="10.10.30.50"

# Archivos de configuración
CONFIG_FILE="/etc/fei-monitor/config.conf"
LOG_FILE="/var/log/fei-monitor.log"
REPORT_DIR="/var/reports/fei-security"

# Función para logging
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error_message() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

warning_message() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

info_message() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[INFO] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Crear directorios necesarios
setup_directories() {
    mkdir -p /etc/fei-monitor
    mkdir -p /var/log
    mkdir -p "$REPORT_DIR"
    mkdir -p "$REPORT_DIR/daily"
    mkdir -p "$REPORT_DIR/weekly"
    mkdir -p "$REPORT_DIR/incidents"
}

# Verificar conectividad a un host
check_connectivity() {
    local host=$1
    local name=$2
    
    if ping -c 1 -W 2 "$host" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name ($host) - Conectividad OK"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name ($host) - Sin conectividad"
        return 1
    fi
}

# Verificar servicio en puerto específico
check_service_port() {
    local host=$1
    local port=$2
    local service=$3
    
    if timeout 5 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $service ($host:$port) - Servicio activo"
        return 0
    else
        echo -e "  ${RED}✗${NC} $service ($host:$port) - Servicio inactivo"
        return 1
    fi
}

# Monitoreo de infraestructura básica
monitor_infrastructure() {
    echo -e "${CYAN}=== MONITOREO DE INFRAESTRUCTURA ===${NC}"
    
    local total_hosts=0
    local active_hosts=0
    
    # Router/Gateway
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$ROUTER_IP" "Router/Gateway"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # Firewall
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$FIREWALL_IP" "Firewall Principal"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # Servidor Web
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$WEBSERVER_IP" "Servidor Web"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # Honeypot
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$HONEYPOT_IP" "Honeypot"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # Proxy
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$PROXY_IP" "Servidor Proxy"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # VPN
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$VPN_IP" "Servidor VPN"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # Autenticación
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$AUTH_IP" "Servidor Autenticación"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # SIEM
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$SIEM_IP" "SIEM (ELK Stack)"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    # IDS/IPS
    total_hosts=$((total_hosts + 1))
    if check_connectivity "$IDS_IP" "IDS/IPS (Suricata)"; then
        active_hosts=$((active_hosts + 1))
    fi
    
    echo ""
    echo -e "  ${BLUE}Resumen de conectividad: $active_hosts/$total_hosts hosts activos${NC}"
    
    if [ $active_hosts -eq $total_hosts ]; then
        echo -e "  ${GREEN}✓ Todos los componentes están conectados${NC}"
    elif [ $active_hosts -ge $((total_hosts * 80 / 100)) ]; then
        echo -e "  ${YELLOW}⚠ Algunos componentes no responden${NC}"
    else
        echo -e "  ${RED}✗ Múltiples componentes fuera de línea${NC}"
    fi
    
    echo ""
}

# Monitoreo de servicios de seguridad
monitor_security_services() {
    echo -e "${CYAN}=== MONITOREO DE SERVICIOS DE SEGURIDAD ===${NC}"
    
    # Servicios web
    check_service_port "$WEBSERVER_IP" "80" "HTTP Web Server"
    check_service_port "$WEBSERVER_IP" "443" "HTTPS Web Server"
    
    # Servicios de proxy
    check_service_port "$PROXY_IP" "3128" "Squid Proxy"
    check_service_port "$PROXY_IP" "8080" "Proxy Management"
    
    # Servicios VPN
    check_service_port "$VPN_IP" "1194" "OpenVPN Server"
    
    # Servicios de autenticación
    check_service_port "$AUTH_IP" "389" "LDAP Server"
    check_service_port "$AUTH_IP" "1812" "RADIUS Server"
    check_service_port "$AUTH_IP" "80" "phpLDAPadmin"
    
    # Servicios SIEM
    check_service_port "$SIEM_IP" "9200" "Elasticsearch"
    check_service_port "$SIEM_IP" "5601" "Kibana"
    check_service_port "$SIEM_IP" "5044" "Logstash"
    
    # Honeypots
    check_service_port "$HONEYPOT_IP" "2222" "Cowrie SSH Honeypot"
    check_service_port "$HONEYPOT_IP" "8080" "Web Honeypot"
    
    echo ""
}

# Monitoreo de amenazas en tiempo real
monitor_threats() {
    echo -e "${CYAN}=== MONITOREO DE AMENAZAS EN TIEMPO REAL ===${NC}"
    
    # Análisis de logs de Suricata (IDS/IPS)
    if ssh -o ConnectTimeout=5 root@$IDS_IP "test -f /var/log/suricata/fast.log" 2>/dev/null; then
        local alerts_today=$(ssh root@$IDS_IP "grep '$(date '+%m/%d')' /var/log/suricata/fast.log 2>/dev/null | wc -l")
        echo -e "  ${BLUE}IDS/IPS Alertas hoy: $alerts_today${NC}"
        
        if [ "$alerts_today" -gt 100 ]; then
            echo -e "  ${RED}⚠ Alto número de alertas detectadas${NC}"
        elif [ "$alerts_today" -gt 50 ]; then
            echo -e "  ${YELLOW}⚠ Número moderado de alertas${NC}"
        else
            echo -e "  ${GREEN}✓ Nivel normal de alertas${NC}"
        fi
    else
        echo -e "  ${RED}✗ No se pueden obtener datos del IDS/IPS${NC}"
    fi
    
    # Análisis de honeypot
    if ssh -o ConnectTimeout=5 cowrie@$HONEYPOT_IP "test -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log" 2>/dev/null; then
        local honeypot_attacks=$(ssh cowrie@$HONEYPOT_IP "grep '$(date '+%Y-%m-%d')' /home/cowrie/cowrie/var/log/cowrie/cowrie.log 2>/dev/null | wc -l")
        echo -e "  ${BLUE}Honeypot intentos hoy: $honeypot_attacks${NC}"
        
        if [ "$honeypot_attacks" -gt 50 ]; then
            echo -e "  ${RED}⚠ Alta actividad maliciosa detectada${NC}"
        elif [ "$honeypot_attacks" -gt 20 ]; then
            echo -e "  ${YELLOW}⚠ Actividad maliciosa moderada${NC}"
        else
            echo -e "  ${GREEN}✓ Actividad maliciosa baja${NC}"
        fi
    else
        echo -e "  ${RED}✗ No se pueden obtener datos del honeypot${NC}"
    fi
    
    # Verificar conexiones VPN activas
    if ssh -o ConnectTimeout=5 root@$VPN_IP "test -f /var/log/openvpn/status.log" 2>/dev/null; then
        local vpn_clients=$(ssh root@$VPN_IP "grep '^CLIENT_LIST' /var/log/openvpn/status.log 2>/dev/null | wc -l")
        echo -e "  ${BLUE}Clientes VPN conectados: $vpn_clients${NC}"
    else
        echo -e "  ${YELLOW}⚠ No se pueden obtener estadísticas VPN${NC}"
    fi
    
    echo ""
}

# Análisis de rendimiento del sistema
monitor_performance() {
    echo -e "${CYAN}=== MONITOREO DE RENDIMIENTO ===${NC}"
    
    # Función para obtener estadísticas de un host
    get_host_stats() {
        local host=$1
        local name=$2
        
        if ping -c 1 -W 2 "$host" >/dev/null 2>&1; then
            # Intentar obtener estadísticas básicas vía SSH
            if ssh -o ConnectTimeout=5 root@$host "uptime; free -m | grep '^Mem:'; df -h | grep -E '/$|/var|/home' | head -3" 2>/dev/null; then
                echo -e "  ${GREEN}✓ Estadísticas obtenidas para $name${NC}"
            else
                echo -e "  ${YELLOW}⚠ $name responde pero sin acceso SSH${NC}"
            fi
        else
            echo -e "  ${RED}✗ $name no responde${NC}"
        fi
        echo ""
    }
    
    # Monitorear componentes principales
    echo "Servidor Web ($WEBSERVER_IP):"
    get_host_stats "$WEBSERVER_IP" "Servidor Web"
    
    echo "SIEM ($SIEM_IP):"
    get_host_stats "$SIEM_IP" "SIEM"
    
    echo "IDS/IPS ($IDS_IP):"
    get_host_stats "$IDS_IP" "IDS/IPS"
}

# Generar reporte de seguridad
generate_security_report() {
    local report_file="$REPORT_DIR/daily/security-report-$(date +%Y%m%d_%H%M%S).txt"
    
    echo "=== REPORTE DE SEGURIDAD DIARIO - SISTEMA FEI ===" > "$report_file"
    echo "Generado: $(date)" >> "$report_file"
    echo "========================================================" >> "$report_file"
    echo "" >> "$report_file"
    
    # Resumen ejecutivo
    echo "RESUMEN EJECUTIVO:" >> "$report_file"
    echo "- Sistema de monitoreo integral activo" >> "$report_file"
    echo "- Componentes monitoreados: 9 sistemas principales" >> "$report_file"
    echo "- Período del reporte: $(date)" >> "$report_file"
    echo "" >> "$report_file"
    
    # Estadísticas de amenazas
    echo "ESTADÍSTICAS DE AMENAZAS:" >> "$report_file"
    
    # IDS/IPS
    if ssh -o ConnectTimeout=5 root@$IDS_IP "test -f /var/log/suricata/fast.log" 2>/dev/null; then
        local alerts_today=$(ssh root@$IDS_IP "grep '$(date '+%m/%d')' /var/log/suricata/fast.log 2>/dev/null | wc -l")
        echo "- Alertas IDS/IPS detectadas hoy: $alerts_today" >> "$report_file"
        
        # Top 5 tipos de alertas
        echo "- Top 5 tipos de alertas:" >> "$report_file"
        ssh root@$IDS_IP "grep '$(date '+%m/%d')' /var/log/suricata/fast.log 2>/dev/null | awk '{print \$6}' | sort | uniq -c | sort -nr | head -5" >> "$report_file" 2>/dev/null
    fi
    
    # Honeypot
    if ssh -o ConnectTimeout=5 cowrie@$HONEYPOT_IP "test -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log" 2>/dev/null; then
        local honeypot_attacks=$(ssh cowrie@$HONEYPOT_IP "grep '$(date '+%Y-%m-%d')' /home/cowrie/cowrie/var/log/cowrie/cowrie.log 2>/dev/null | wc -l")
        echo "- Intentos de acceso malicioso (Honeypot): $honeypot_attacks" >> "$report_file"
        
        # Top 5 IPs atacantes
        echo "- Top 5 IPs atacantes:" >> "$report_file"
        ssh cowrie@$HONEYPOT_IP "grep '$(date '+%Y-%m-%d')' /home/cowrie/cowrie/var/log/cowrie/cowrie.log 2>/dev/null | awk '{print \$4}' | cut -d',' -f1 | sort | uniq -c | sort -nr | head -5" >> "$report_file" 2>/dev/null
    fi
    
    echo "" >> "$report_file"
    
    # Estado de servicios
    echo "ESTADO DE SERVICIOS CRÍTICOS:" >> "$report_file"
    echo "- Firewall: $(ping -c 1 -W 2 $FIREWALL_IP >/dev/null 2>&1 && echo "Activo" || echo "Inactivo")" >> "$report_file"
    echo "- SIEM: $(timeout 5 bash -c "echo >/dev/tcp/$SIEM_IP/9200" 2>/dev/null && echo "Activo" || echo "Inactivo")" >> "$report_file"
    echo "- IDS/IPS: $(timeout 5 bash -c "echo >/dev/tcp/$IDS_IP/22" 2>/dev/null && echo "Activo" || echo "Inactivo")" >> "$report_file"
    echo "- VPN: $(timeout 5 bash -c "echo >/dev/udp/$VPN_IP/1194" 2>/dev/null && echo "Activo" || echo "Inactivo")" >> "$report_file"
    echo "- Proxy: $(timeout 5 bash -c "echo >/dev/tcp/$PROXY_IP/3128" 2>/dev/null && echo "Activo" || echo "Inactivo")" >> "$report_file"
    echo "" >> "$report_file"
    
    # Recomendaciones
    echo "RECOMENDACIONES:" >> "$report_file"
    echo "- Revisar alertas de alta prioridad en el SIEM" >> "$report_file"
    echo "- Analizar patrones de ataque en honeypot" >> "$report_file"
    echo "- Verificar actualizaciones de seguridad pendientes" >> "$report_file"
    echo "- Validar configuraciones de firewall" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "Reporte generado en: $report_file"
}

# Verificar alertas críticas
check_critical_alerts() {
    echo -e "${CYAN}=== VERIFICACIÓN DE ALERTAS CRÍTICAS ===${NC}"
    
    local critical_count=0
    
    # Verificar servicios críticos caídos
    if ! timeout 5 bash -c "echo >/dev/tcp/$SIEM_IP/9200" 2>/dev/null; then
        echo -e "  ${RED}🚨 CRÍTICO: SIEM no responde${NC}"
        critical_count=$((critical_count + 1))
    fi
    
    if ! timeout 5 bash -c "echo >/dev/tcp/$FIREWALL_IP/22" 2>/dev/null; then
        echo -e "  ${RED}🚨 CRÍTICO: Firewall no responde${NC}"
        critical_count=$((critical_count + 1))
    fi
    
    # Verificar alta actividad maliciosa
    if ssh -o ConnectTimeout=5 root@$IDS_IP "test -f /var/log/suricata/fast.log" 2>/dev/null; then
        local recent_alerts=$(ssh root@$IDS_IP "grep '$(date '+%m/%d %H')' /var/log/suricata/fast.log 2>/dev/null | wc -l")
        if [ "$recent_alerts" -gt 50 ]; then
            echo -e "  ${RED}🚨 CRÍTICO: $recent_alerts alertas en la última hora${NC}"
            critical_count=$((critical_count + 1))
        fi
    fi
    
    # Verificar espacio en disco crítico
    for host in $SIEM_IP $IDS_IP $WEBSERVER_IP; do
        if ssh -o ConnectTimeout=5 root@$host "df -h | awk '\$5 ~ /9[0-9]%/ {print \$0}'" 2>/dev/null | grep -q .; then
            echo -e "  ${RED}🚨 CRÍTICO: Espacio en disco bajo en $host${NC}"
            critical_count=$((critical_count + 1))
        fi
    done
    
    if [ $critical_count -eq 0 ]; then
        echo -e "  ${GREEN}✓ No se detectaron alertas críticas${NC}"
    else
        echo -e "  ${RED}⚠ $critical_count alertas críticas detectadas${NC}"
        
        # Enviar notificación (implementar según necesidades)
        echo "ALERTA CRÍTICA: $critical_count problemas detectados en sistema FEI - $(date)" >> "$LOG_FILE"
    fi
    
    echo ""
}

# Monitoreo en tiempo real interactivo
interactive_monitor() {
    echo -e "${PURPLE}=== MONITOR INTERACTIVO SISTEMA CIBERSEGURIDAD FEI ===${NC}"
    echo "Presiona Ctrl+C para salir"
    echo ""
    
    while true; do
        clear
        echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${PURPLE}║           MONITOR SISTEMA CIBERSEGURIDAD FEI                  ║${NC}"
        echo -e "${PURPLE}║                Universidad Veracruzana                        ║${NC}"
        echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        # Mostrar timestamp
        echo -e "${CYAN}Última actualización: $(date)${NC}"
        echo ""
        
        # Estado general del sistema
        monitor_infrastructure
        monitor_security_services
        monitor_threats
        check_critical_alerts
        
        # Esperar antes de la siguiente actualización
        echo -e "${YELLOW}Actualizando en 30 segundos... (Ctrl+C para salir)${NC}"
        sleep 30
    done
}

# Mostrar ayuda
show_help() {
    echo "Sistema de Monitoreo Integral - Ciberseguridad FEI"
    echo ""
    echo "Uso: $0 [OPCIÓN]"
    echo ""
    echo "Opciones:"
    echo "  monitor              Monitoreo interactivo en tiempo real"
    echo "  check                Verificación única de todos los sistemas"
    echo "  infrastructure       Verificar solo infraestructura"
    echo "  services             Verificar solo servicios"
    echo "  threats              Verificar solo amenazas"
    echo "  performance          Verificar solo rendimiento"
    echo "  critical             Verificar solo alertas críticas"
    echo "  report               Generar reporte de seguridad"
    echo "  status               Estado resumido del sistema"
    echo "  help                 Mostrar esta ayuda"
    echo ""
    echo "Ejemplos:"
    echo "  $0 monitor           # Monitoreo en tiempo real"
    echo "  $0 check             # Verificación completa una vez"
    echo "  $0 critical          # Solo alertas críticas"
    echo "  $0 report            # Generar reporte diario"
}

# Estado resumido del sistema
show_status() {
    echo -e "${CYAN}=== ESTADO RESUMIDO DEL SISTEMA ===${NC}"
    
    # Contadores
    local total_services=0
    local active_services=0
    
    # Lista de servicios críticos para verificar
    declare -A services=(
        ["$FIREWALL_IP:22"]="Firewall SSH"
        ["$WEBSERVER_IP:80"]="Web Server HTTP"
        ["$WEBSERVER_IP:443"]="Web Server HTTPS"
        ["$PROXY_IP:3128"]="Proxy Server"
        ["$VPN_IP:1194"]="VPN Server"
        ["$AUTH_IP:389"]="LDAP Server"
        ["$AUTH_IP:1812"]="RADIUS Server"
        ["$SIEM_IP:9200"]="Elasticsearch"
        ["$SIEM_IP:5601"]="Kibana"
        ["$HONEYPOT_IP:2222"]="SSH Honeypot"
    )
    
    echo "Servicios críticos:"
    for service_endpoint in "${!services[@]}"; do
        local host=$(echo $service_endpoint | cut -d':' -f1)
        local port=$(echo $service_endpoint | cut -d':' -f2)
        local name=${services[$service_endpoint]}
        
        total_services=$((total_services + 1))
        
        if timeout 3 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $name"
            active_services=$((active_services + 1))
        else
            echo -e "  ${RED}✗${NC} $name"
        fi
    done
    
    echo ""
    echo -e "Estado general: $active_services/$total_services servicios activos"
    
    # Calcular porcentaje de disponibilidad
    local availability=$((active_services * 100 / total_services))
    
    if [ $availability -ge 95 ]; then
        echo -e "${GREEN}✓ Sistema operacional: $availability% disponibilidad${NC}"
    elif [ $availability -ge 80 ]; then
        echo -e "${YELLOW}⚠ Sistema con problemas menores: $availability% disponibilidad${NC}"
    else
        echo -e "${RED}✗ Sistema con problemas críticos: $availability% disponibilidad${NC}"
    fi
    
    echo ""
}

# Función principal
main() {
    # Crear directorios necesarios
    setup_directories
    
    # Procesar argumentos
    case "${1:-check}" in
        monitor)
            interactive_monitor
            ;;
        check)
            echo -e "${PURPLE}=== VERIFICACIÓN COMPLETA DEL SISTEMA ===${NC}"
            echo ""
            monitor_infrastructure
            monitor_security_services
            monitor_threats
            monitor_performance
            check_critical_alerts
            ;;
        infrastructure)
            monitor_infrastructure
            ;;
        services)
            monitor_security_services
            ;;
        threats)
            monitor_threats
            ;;
        performance)
            monitor_performance
            ;;
        critical)
            check_critical_alerts
            ;;
        report)
            generate_security_report
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
}

# Ejecutar función principal
main "$@"
