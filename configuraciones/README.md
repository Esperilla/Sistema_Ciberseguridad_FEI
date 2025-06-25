# Configuraciones del Sistema de Ciberseguridad FEI

## Estructura de Configuraciones

### Firewall (iptables)
- `firewall/rules.sh` - Reglas principales de iptables
- `firewall/fail2ban.conf` - Configuración fail2ban
- `firewall/ufw.rules` - Reglas UFW por componente

### Apache Web Server
- `apache/000-default.conf` - Virtual host principal
- `apache/security.conf` - Headers de seguridad
- `apache/ssl.conf` - Configuración SSL/TLS
- `apache/mod_security.conf` - WAF rules

### Squid Proxy
- `squid/squid.conf` - Configuración principal
- `squid/blacklists/` - Listas de sitios bloqueados
- `squid/acl_rules.conf` - Reglas de control de acceso

### ELK Stack (SIEM)
- `elk/elasticsearch.yml` - Configuración Elasticsearch
- `elk/logstash/` - Pipelines de Logstash
- `elk/kibana.yml` - Configuración Kibana
- `elk/dashboards/` - Dashboards exportados

### Suricata (IDS/IPS)
- `suricata/suricata.yaml` - Configuración principal
- `suricata/rules/` - Reglas personalizadas
- `suricata/threshold.config` - Configuración de umbrales

### OpenVPN
- `vpn/server.conf` - Configuración servidor VPN
- `vpn/easy-rsa/` - Configuración CA y certificados
- `vpn/client-configs/` - Configuraciones de cliente

### OpenLDAP + FreeRADIUS
- `auth/slapd.conf` - Configuración LDAP
- `auth/radiusd.conf` - Configuración RADIUS
- `auth/schemas/` - Esquemas LDAP personalizados

### Honeypots
- `honeypot/cowrie.cfg` - Configuración Cowrie SSH
- `honeypot/dionaea.conf` - Configuración Dionaea
- `honeypot/custom-responses/` - Respuestas personalizadas

## Backups de Configuración

Todas las configuraciones están respaldadas con timestamp:
- Fecha de backup: $(date)
- Verificación de integridad: MD5 checksums incluidos
