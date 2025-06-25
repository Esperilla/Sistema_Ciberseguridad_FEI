# Guía de Implementación Paso a Paso - Sistema Ciberseguridad FEI

## 📋 Información General

**Proyecto:** Sistema Integral de Ciberseguridad para la Facultad de Estadística e Informática  
**Framework:** NIST Cybersecurity Framework 2.0  
**Plataforma:** VMware Workstation con Debian 12  
**Tiempo estimado:** 8-12 horas para implementación completa

## 🎯 Prerrequisitos

### Hardware Mínimo
- **CPU:** Intel i5/AMD Ryzen 5 o superior (con soporte de virtualización)
- **RAM:** 16 GB mínimo (recomendado 32 GB)
- **Almacenamiento:** 500 GB espacio libre
- **Red:** Conexión a Internet estable

### Software Requerido
- **VMware Workstation Pro 17+** (versión completa, no Player)
- **Debian 12 ISO** descargada desde sitio oficial
- **Acceso administrativo** al sistema host

## 🚀 Implementación Paso a Paso

### Fase 1: Preparación del Entorno (30-45 minutos)

#### 1.1 Configuración de Redes Virtuales en VMware
```bash
# Crear redes virtuales personalizadas en VMware:
# - VMnet1: Red Externa (NAT) - 192.168.1.0/24
# - VMnet2: Red DMZ (Host-Only) - 10.10.10.0/24  
# - VMnet3: Red LAN (Host-Only) - 10.10.20.0/24
# - VMnet4: Red MGMT (Host-Only) - 10.10.30.0/24

# En VMware Workstation:
# Edit → Virtual Network Editor → Add Network → Configure cada VMnet
```

#### 1.2 Creación de VM Base
```bash
# Configuración VM Base:
# - Memoria: 2 GB
# - Disco: 40 GB (dinámico)
# - Red: VMnet1 (temporal para instalación)
# - Sistema: Debian 12 netinst

# Instalación básica de Debian:
# - Particionado: LVM con /boot separado
# - Software: SSH server + utilidades estándar
# - Usuario: Crear usuario admin con sudo
```

#### 1.3 Configuración Base del Sistema
```bash
# Una vez instalado Debian, ejecutar en la VM base:

# Actualizar sistema
apt update && apt upgrade -y

# Instalar herramientas básicas
apt install -y curl wget git vim nano htop net-tools \
               iptables-persistent openssh-server sudo \
               build-essential dkms linux-headers-$(uname -r)

# Configurar sudoers
usermod -aG sudo admin

# Instalar VMware Tools (opcional pero recomendado)
# mount /dev/cdrom /mnt
# cp /mnt/VMwareTools-*.tar.gz /tmp/
# tar -xzf /tmp/VMwareTools-*.tar.gz -C /tmp/
# cd /tmp/vmware-tools-distrib && ./vmware-install.pl -d

# Crear snapshot "Base-Clean"
# VM → Snapshot → Take Snapshot → "Base-Clean"
```

### Fase 2: Despliegue de Máquinas Virtuales (45-60 minutos)

#### 2.1 Clonación de VMs
```bash
# En VMware Workstation, clonar VM base 11 veces:
# VM → Manage → Clone → Create linked clone from snapshot "Base-Clean"

# Nombres y configuraciones:
VM1-Router:    192.168.1.1    (2GB RAM, VMnet1)
VM2-Firewall:  Multiple IPs    (4GB RAM, VMnet1+2+3+4)
VM3-WebServer: 10.10.10.10    (2GB RAM, VMnet2)
VM4-Honeypot:  10.10.10.20    (2GB RAM, VMnet2)
VM5-Proxy:     10.10.20.10    (2GB RAM, VMnet3)
VM6-SIEM:      10.10.30.10    (8GB RAM, VMnet4)
VM7-IDS:       10.10.30.20    (4GB RAM, VMnet4)
VM8-VPN:       10.10.20.30    (2GB RAM, VMnet3)
VM9-Auth:      10.10.20.40    (2GB RAM, VMnet3)
VM10-AdminWS:  10.10.30.50    (2GB RAM, VMnet4)
VM11-UserWS:   10.10.20.50    (2GB RAM, VMnet3)
```

#### 2.2 Configuración de Red por VM
```bash
# Para cada VM, editar /etc/network/interfaces según su segmento:

# Ejemplo VM3-WebServer (DMZ):
auto ens33
iface ens33 inet static
    address 10.10.10.10
    netmask 255.255.255.0
    gateway 10.10.10.1
    dns-nameservers 8.8.8.8 8.8.4.4

# Ejemplo VM5-Proxy (LAN):
auto ens33
iface ens33 inet static
    address 10.10.20.10
    netmask 255.255.255.0
    gateway 10.10.20.1
    dns-nameservers 8.8.8.8 8.8.4.4

# Aplicar cambios:
systemctl restart networking
```

### Fase 3: Implementación de Componentes de Seguridad (4-6 horas)

#### 3.1 Configuración del Firewall Principal (VM2)
```bash
# En VM2-Firewall:
cd /path/to/scripts
chmod +x configure-firewall.sh
./configure-firewall.sh

# Verificar configuración:
systemctl status iptables
iptables -L -n
fail2ban-client status

# Tiempo estimado: 45 minutos
```

#### 3.2 Configuración del Servidor Web Seguro (VM3)
```bash
# En VM3-WebServer:
cd /path/to/scripts
chmod +x configure-webserver.sh
./configure-webserver.sh

# Verificar configuración:
systemctl status apache2
curl -I http://10.10.10.10
curl -I https://10.10.10.10

# Tiempo estimado: 30 minutos
```

#### 3.3 Configuración del Honeypot (VM4)
```bash
# En VM4-Honeypot:
cd /path/to/scripts
chmod +x configure-honeypot.sh
./configure-honeypot.sh

# Verificar configuración:
systemctl status cowrie
netstat -tlnp | grep 2222
curl -I http://10.10.10.20:8080

# Tiempo estimado: 60 minutos
```

#### 3.4 Configuración del Servidor Proxy (VM5)
```bash
# En VM5-Proxy:
cd /path/to/scripts
chmod +x configure-proxy.sh
./configure-proxy.sh

# Verificar configuración:
systemctl status squid
curl --proxy 10.10.20.10:3128 -I google.com

# Tiempo estimado: 45 minutos
```

#### 3.5 Configuración del SIEM (VM6)
```bash
# En VM6-SIEM:
cd /path/to/scripts
chmod +x configure-siem.sh
./configure-siem.sh

# Verificar configuración:
curl -X GET "10.10.30.10:9200/_cluster/health?pretty"
curl -I http://10.10.30.10:5601

# Tiempo estimado: 90 minutos
```

#### 3.6 Configuración del IDS/IPS (VM7)
```bash
# En VM7-IDS:
cd /path/to/scripts
chmod +x configure-ids-ips.sh
./configure-ids-ips.sh

# Verificar configuración:
systemctl status suricata-fei
/usr/local/bin/suricata-monitor.sh

# Tiempo estimado: 60 minutos
```

#### 3.7 Configuración del Servidor VPN (VM8)
```bash
# En VM8-VPN:
cd /path/to/scripts
chmod +x configure-vpn-server.sh
./configure-vpn-server.sh

# Verificar configuración:
systemctl status openvpn@server
/usr/local/bin/vpn-monitor.sh

# Tiempo estimado: 75 minutos
```

#### 3.8 Configuración del Servidor de Autenticación (VM9)
```bash
# En VM9-Auth:
cd /path/to/scripts
chmod +x configure-auth-server.sh
./configure-auth-server.sh

# Verificar configuración:
systemctl status slapd freeradius apache2
ldapsearch -x -H ldap://10.10.20.40 -b "dc=fei,dc=uv,dc=mx"

# Tiempo estimado: 90 minutos
```

### Fase 4: Configuración del Monitoreo (30-45 minutos)

#### 4.1 Instalación del Monitor Integral (VM10)
```bash
# En VM10-AdminWS:
cd /path/to/scripts
chmod +x monitor-integral.sh
cp monitor-integral.sh /usr/local/bin/

# Verificar funcionamiento:
monitor-integral.sh status
monitor-integral.sh check

# Tiempo estimado: 30 minutos
```

#### 4.2 Configuración de Estación de Usuario (VM11)
```bash
# En VM11-UserWS:
# Configurar como estación de trabajo estándar
apt install -y firefox-esr libreoffice-writer

# Configurar proxy del navegador apuntando a 10.10.20.10:3128
# Tiempo estimado: 15 minutos
```

### Fase 5: Pruebas y Validación (2-3 horas)

#### 5.1 Pruebas de Conectividad
```bash
# Desde VM10-AdminWS ejecutar:
monitor-integral.sh check

# Verificar conectividad entre segmentos:
ping -c 3 10.10.10.10    # Servidor Web
ping -c 3 10.10.20.10    # Proxy  
ping -c 3 10.10.30.10    # SIEM

# Tiempo estimado: 30 minutos
```

#### 5.2 Pruebas de Servicios
```bash
# Verificar servicios web:
curl -I http://10.10.10.10
curl -I https://10.10.10.10

# Verificar proxy:
curl --proxy 10.10.20.10:3128 -I google.com

# Verificar SIEM:
curl -X GET "10.10.30.10:9200/_cluster/health?pretty"

# Verificar autenticación:
radtest admin.fei password 10.10.20.40 0 FEI_Radius_Secret_2025!

# Tiempo estimado: 45 minutos
```

#### 5.3 Simulación de Incidentes de Seguridad
```bash
# Desde VM11-UserWS o externa:

# Test 1: Intento de acceso SSH al honeypot
ssh admin@10.10.10.20

# Test 2: Escaneo de puertos
nmap -sS 10.10.10.20

# Test 3: Intento de acceso a sitio bloqueado
curl --proxy 10.10.20.10:3128 http://facebook.com

# Test 4: Inyección SQL simulada
curl "http://10.10.10.10/search?q=1' union select 1,2,3--"

# Verificar detección en dashboards y logs
# Tiempo estimado: 60 minutos
```

#### 5.4 Validación del Monitoreo
```bash
# Ejecutar desde VM10-AdminWS:
monitor-integral.sh monitor    # Monitor en tiempo real

# Verificar alertas en componentes específicos:
/usr/local/bin/suricata-analysis.sh      # Análisis IDS/IPS
/usr/local/bin/honeypot-analysis.sh      # Análisis honeypot

# Generar reporte:
monitor-integral.sh report

# Tiempo estimado: 45 minutos
```

### Fase 6: Documentación y Evidencias (1-2 horas)

#### 6.1 Captura de Evidencias
```bash
# Tomar capturas de pantalla de:
# - Dashboards de Kibana funcionando
# - Alertas de Suricata detectando ataques
# - Logs de honeypot con intentos de acceso
# - Configuraciones de servicios
# - Resultados de pruebas de conectividad

# Exportar configuraciones:
# - Reglas de firewall
# - Configuraciones de Apache
# - Filtros de Squid
# - Dashboards de Kibana
# - Certificados y claves (sin información sensible)

# Tiempo estimado: 60 minutos
```

#### 6.2 Generación de Reportes
```bash
# Ejecutar desde VM10-AdminWS:
monitor-integral.sh report

# Compilar evidencias en carpeta estructurada:
mkdir -p /evidencias/{capturas,logs,configuraciones,reportes}

# Tiempo estimado: 30 minutos
```

## ✅ Lista de Verificación Final

### Infraestructura
- [ ] 11 VMs creadas y funcionando
- [ ] Redes virtuales configuradas correctamente
- [ ] Conectividad entre segmentos validada
- [ ] Asignación de IPs correcta

### Servicios de Seguridad
- [ ] Firewall bloqueando tráfico no autorizado
- [ ] Servidor web respondiendo con HTTPS
- [ ] Proxy filtrando contenido correctamente
- [ ] SIEM recibiendo y procesando logs
- [ ] IDS/IPS detectando amenazas
- [ ] VPN permitiendo conexiones autorizadas
- [ ] Honeypot capturando intentos maliciosos
- [ ] Autenticación centralizada funcionando

### Monitoreo
- [ ] Monitor integral funcionando
- [ ] Alertas automáticas configuradas
- [ ] Reportes generándose correctamente
- [ ] Dashboards mostrando datos en tiempo real

### Documentación
- [ ] Capturas de pantalla tomadas
- [ ] Configuraciones exportadas
- [ ] Logs de pruebas guardados
- [ ] Reportes de incidentes documentados

## 🔧 Comandos de Troubleshooting

### Problemas Comunes

#### VM no arranca o no tiene red
```bash
# Verificar configuración de red
ip addr show
systemctl status networking

# Reiniciar red
systemctl restart networking
```

#### Servicio no responde
```bash
# Verificar estado del servicio
systemctl status <servicio>

# Ver logs del servicio
journalctl -u <servicio> -f

# Reiniciar servicio
systemctl restart <servicio>
```

#### No hay conectividad entre VMs
```bash
# Verificar routing
route -n

# Verificar firewall
iptables -L -n

# Test de conectividad específica
telnet <ip> <puerto>
```

#### SIEM no recibe logs
```bash
# Verificar Filebeat
systemctl status filebeat

# Verificar Logstash
curl -X GET "10.10.30.10:9600/_node/stats/pipelines?pretty"

# Verificar configuración de rsyslog
systemctl status rsyslog
```

## 📞 Soporte y Contacto

### Recursos Adicionales
- **Documentación técnica:** `documentacion/` folder
- **Scripts de configuración:** `scripts/` folder
- **Bitácora de trabajo:** `bitacora/06_Bitacora_Trabajo.md`

### Información del Proyecto
- **Universidad:** Universidad Veracruzana
- **Facultad:** Estadística e Informática
- **Programa:** Licenciatura en Redes y Servicios de Cómputo
- **Materia:** Ciberseguridad
- **Período:** Febrero-Julio 2025

---

*Esta guía proporciona los pasos detallados para implementar completamente el Sistema Integral de Ciberseguridad FEI. Seguir estos pasos en orden garantiza una implementación exitosa y funcional del sistema.*
