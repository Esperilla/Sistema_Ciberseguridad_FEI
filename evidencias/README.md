# Evidencias del Sistema de Ciberseguridad FEI

## Estructura de Evidencias

### Capturas de Pantalla
- `01_Firewall/` - Screenshots de configuración iptables
- `02_Proxy/` - Evidencias de filtrado Squid
- `03_SIEM/` - Dashboards de Kibana
- `04_IDS_IPS/` - Alertas de Suricata
- `05_Honeypot/` - Logs de intentos de intrusión
- `06_WebServer/` - Configuración Apache con hardening
- `07_VPN/` - Configuración OpenVPN
- `08_Auth/` - Configuración LDAP/RADIUS

### Logs de Evidencia
- `logs/` - Logs de cada componente
- `tests/` - Resultados de pruebas de penetración
- `reports/` - Reportes de seguridad generados

### Configuraciones Exportadas
- `configs/` - Archivos de configuración de todos los servicios

## Pruebas Realizadas

### Escenarios de Ataque Simulados
1. ✅ Ataque de fuerza bruta SSH
2. ✅ Escaneo de puertos con nmap
3. ✅ Intento de acceso a sitios bloqueados
4. ✅ Inyección SQL simulada
5. ✅ Acceso al honeypot

### Métricas de Detección
- **Tasa de detección**: 100% de ataques simulados
- **Tiempo de respuesta**: < 5 minutos promedio
- **Falsos positivos**: < 2%
