#!/bin/bash
# Script para limpiar completamente instalaciones previas de Squid
# Usar antes de ejecutar configure-proxy.sh

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARN $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Verificar si se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Este script debe ejecutarse como root${NC}"
   exit 1
fi

log "Iniciando limpieza completa de Squid..."

# Detener servicio Squid
log "Deteniendo servicio Squid..."
systemctl stop squid 2>/dev/null || true
systemctl disable squid 2>/dev/null || true

# Esperar a que termine completamente
sleep 5

# Eliminar procesos residuales
log "Eliminando procesos Squid residuales..."
pkill -9 -f squid 2>/dev/null || true
pkill -9 -f squidguard 2>/dev/null || true

# Limpiar archivos PID
log "Limpiando archivos PID..."
rm -f /run/squid.pid /var/run/squid.pid 2>/dev/null || true

# Limpiar cache existente
log "Limpiando cache de Squid..."
rm -rf /var/spool/squid/* 2>/dev/null || true
rm -rf /var/cache/squid/* 2>/dev/null || true
rm -rf /var/cache/squid-custom/* 2>/dev/null || true

# Limpiar logs antiguos
log "Limpiando logs antiguos..."
rm -f /var/log/squid/*.log* 2>/dev/null || true
rm -f /var/log/squid-custom/*.log* 2>/dev/null || true

# Limpiar configuraciones temporales
log "Limpiando configuraciones temporales..."
rm -f /etc/squid/squid.conf.tmp 2>/dev/null || true

# Verificar estado final
log "Verificando estado de limpieza..."

if pgrep -f squid > /dev/null; then
    warn "Aún hay procesos Squid ejecutándose:"
    pgrep -f squid || true
else
    log "✓ No hay procesos Squid ejecutándose"
fi

if [ -f /run/squid.pid ] || [ -f /var/run/squid.pid ]; then
    warn "Aún existen archivos PID"
else
    log "✓ No hay archivos PID residuales"
fi

if systemctl is-active --quiet squid; then
    warn "El servicio Squid aún está activo"
else
    log "✓ Servicio Squid completamente detenido"
fi

log "Limpieza de Squid completada"
log "Ahora puede ejecutar configure-proxy.sh de forma segura"
