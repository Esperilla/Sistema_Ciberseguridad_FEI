# Arquitectura de Red - Sistema de Ciberseguridad FEI

## Visión General

Este documento define la arquitectura de red para la implementación del Sistema Integral de Ciberseguridad de la FEI usando máquinas virtuales Debian en VMware Workstation.

## Diseño de Red

### Topología de Red

```
Internet
    |
[Router Simulado - VM1]
    |
[Firewall/Gateway - VM2] (pfsense o iptables)
    |
    +-- [DMZ] ---- [Servidor Web - VM3]
    |              [Honeypot - VM4]
    |
    +-- [Red Interna]
            |
            +-- [Proxy Server - VM5] (Squid)
            +-- [SIEM/Log Server - VM6] (ELK Stack)
            +-- [IDS/IPS - VM7] (Suricata)
            +-- [VPN Server - VM8] (OpenVPN)
            +-- [Servidor de Autenticación - VM9] (LDAP/Kerberos)
            +-- [Estación de Trabajo Admin - VM10]
            +-- [Estación de Trabajo Usuario - VM11]
```

### Segmentación de Red

| Segmento | VLAN/Subnet | Rango IP | Propósito |
|----------|-------------|----------|-----------|
| WAN Simulado | - | 192.168.1.0/24 | Conexión externa simulada |
| DMZ | VLAN 10 | 10.10.10.0/24 | Servicios públicos |
| Red Interna | VLAN 20 | 10.10.20.0/24 | Servicios internos |
| Red de Gestión | VLAN 30 | 10.10.30.0/24 | Administración y monitoreo |
| Red VPN | - | 10.10.40.0/24 | Acceso remoto |

## Especificaciones de Máquinas Virtuales

### VM1 - Router Simulado (Internet Gateway)
- **OS**: Debian 12 (Bookworm)
- **RAM**: 1 GB
- **Almacenamiento**: 20 GB
- **Interfaces de Red**: 
  - eth0: NAT (simula conexión a Internet)
  - eth1: Red interna VMware (192.168.1.1/24)
- **Servicios**: iptables, DHCP, DNS forwarder

### VM2 - Firewall/Gateway Principal
- **OS**: pfSense Community Edition o Debian 12 con iptables
- **RAM**: 2 GB
- **Almacenamiento**: 30 GB
- **Interfaces de Red**:
  - eth0: Conexión a Router (192.168.1.2/24)
  - eth1: DMZ (10.10.10.1/24)
  - eth2: Red Interna (10.10.20.1/24)
  - eth3: Red de Gestión (10.10.30.1/24)

### VM3 - Servidor Web (DMZ)
- **OS**: Debian 12
- **RAM**: 2 GB
- **Almacenamiento**: 30 GB
- **IP**: 10.10.10.10/24
- **Servicios**: Apache/Nginx, MySQL/PostgreSQL, fail2ban

### VM4 - Honeypot
- **OS**: Debian 12
- **RAM**: 1 GB
- **Almacenamiento**: 20 GB
- **IP**: 10.10.10.20/24
- **Servicios**: Cowrie, Dionaea, T-Pot

### VM5 - Proxy Server
- **OS**: Debian 12
- **RAM**: 2 GB
- **Almacenamiento**: 30 GB
- **IP**: 10.10.20.10/24
- **Servicios**: Squid, SquidGuard, HAVP

### VM6 - SIEM/Log Server
- **OS**: Debian 12
- **RAM**: 4 GB
- **Almacenamiento**: 50 GB
- **IP**: 10.10.30.10/24
- **Servicios**: Elasticsearch, Logstash, Kibana, Rsyslog

### VM7 - IDS/IPS
- **OS**: Debian 12
- **RAM**: 2 GB
- **Almacenamiento**: 30 GB
- **IP**: 10.10.30.20/24
- **Servicios**: Suricata, Zeek/Bro

### VM8 - VPN Server
- **OS**: Debian 12
- **RAM**: 1 GB
- **Almacenamiento**: 20 GB
- **IP**: 10.10.20.30/24
- **Servicios**: OpenVPN, easy-rsa

### VM9 - Servidor de Autenticación
- **OS**: Debian 12
- **RAM**: 2 GB
- **Almacenamiento**: 30 GB
- **IP**: 10.10.20.40/24
- **Servicios**: OpenLDAP, Kerberos

### VM10 - Estación Admin
- **OS**: Debian 12 con GUI (GNOME/XFCE)
- **RAM**: 3 GB
- **Almacenamiento**: 40 GB
- **IP**: 10.10.30.50/24
- **Servicios**: SSH client, herramientas de administración

### VM11 - Estación Usuario
- **OS**: Debian 12 con GUI
- **RAM**: 2 GB
- **Almacenamiento**: 30 GB
- **IP**: 10.10.20.50/24
- **Servicios**: Navegador, aplicaciones de usuario

## Flujo de Tráfico

### Tráfico de Usuario Normal
1. Usuario → Proxy (autenticación) → Firewall → Internet
2. Logs enviados a SIEM para análisis

### Tráfico Administrativo
1. Admin → VPN → Red de Gestión → Servicios
2. Monitoreo centralizado vía SIEM

### Detección de Amenazas
1. IDS/IPS analiza tráfico en tiempo real
2. Alertas enviadas a SIEM
3. Honeypot atrae atacantes para análisis

## Consideraciones de VMware Workstation

### Configuración de Red Virtual
- **NAT Network**: Para simular conexión a Internet
- **Host-Only Networks**: Para segmentos internos aislados
- **Custom Networks**: Para VLANs específicas

### Snapshots y Backup
- Snapshot inicial de cada VM después de instalación base
- Snapshots antes de configuraciones críticas
- Backup regular de configuraciones y datos

### Recursos del Host
- **RAM mínima recomendada**: 16 GB
- **Almacenamiento**: 500 GB disponibles
- **CPU**: Procesador con virtualización habilitada

## Mapeo NIST CSF 2.0

| Función | Implementación en Arquitectura |
|---------|--------------------------------|
| **Identificar** | Inventario de VMs, servicios y configuraciones |
| **Proteger** | Firewall, Proxy, VPN, Autenticación |
| **Detectar** | IDS/IPS, SIEM, Honeypot, Logs |
| **Responder** | Procedimientos automatizados vía scripts |
| **Recuperar** | Snapshots, backups, procedimientos de restauración |

## Próximos Pasos

1. Instalación y configuración base de VMs
2. Configuración de red y conectividad
3. Implementación de servicios de seguridad
4. Configuración de monitoreo y logging
5. Pruebas de funcionalidad y seguridad
