# Guía de Instalación y Configuración - Debian 12

## 1. Preparación del Entorno VMware

### 1.1 Requisitos del Sistema Host
- **VMware Workstation Pro 17** o superior
- **RAM**: Mínimo 16 GB (recomendado 32 GB)
- **Almacenamiento**: 500 GB disponibles
- **CPU**: Procesador con soporte de virtualización (VT-x/AMD-V)
- **Red**: Conexión a Internet estable

### 1.2 Configuración de Redes Virtuales en VMware

#### Crear Redes Personalizadas
1. Abrir VMware Workstation
2. Ir a **Edit → Virtual Network Editor**
3. Crear las siguientes redes:

```bash
# Red WAN Simulada
VMnet1 (Host-only)
Subnet: 192.168.1.0/24
Gateway: 192.168.1.1

# Red DMZ  
VMnet2 (Host-only)
Subnet: 10.10.10.0/24
Gateway: 10.10.10.1

# Red Interna
VMnet3 (Host-only) 
Subnet: 10.10.20.0/24
Gateway: 10.10.20.1

# Red de Gestión
VMnet4 (Host-only)
Subnet: 10.10.30.0/24
Gateway: 10.10.30.1
```

### 1.3 Descarga de Debian 12
```bash
# Descargar imagen ISO oficial
# URL: https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/
# Archivo: debian-12.x.x-amd64-netinst.iso
```

## 2. Instalación Base de Debian 12

### 2.1 Configuración de VM Base
```bash
# Especificaciones para VM Base (plantilla)
Memoria RAM: 2 GB
Almacenamiento: 30 GB (thin provisioning)
Tipo de disco: SCSI
Red: NAT (solo para instalación inicial)
```

### 2.2 Proceso de Instalación

#### 2.2.1 Configuración Inicial
```bash
# Durante la instalación:
Idioma: Spanish
País: México  
Distribución de teclado: Latinoamericano
Hostname: debian-base
Dominio: fei.local
```

#### 2.2.2 Configuración de Usuarios
```bash
# Usuario root
Password: [Password complejo según política]

# Usuario administrativo
Nombre completo: Administrador FEI
Usuario: admin-fei
Password: [Password complejo según política]
```

#### 2.2.3 Particionado de Disco
```bash
# Esquema recomendado:
/boot     - 512 MB (ext4)
/         - 15 GB (ext4)  
/var      - 8 GB (ext4)
/var/log  - 4 GB (ext4)
/home     - 2 GB (ext4)
swap      - 1 GB
```

#### 2.2.4 Selección de Software
```bash
# Paquetes a instalar:
☑ SSH server
☑ Standard system utilities  
☐ Desktop environment (solo para VMs con GUI)
☐ Web server
☐ Print server
```

### 2.3 Configuración Post-Instalación

#### 2.3.1 Actualización del Sistema
```bash
# Actualizar repositorios y sistema
sudo apt update && sudo apt upgrade -y

# Instalar herramientas básicas
sudo apt install -y vim curl wget net-tools htop tree \
    software-properties-common apt-transport-https \
    ca-certificates gnupg lsb-release
```

#### 2.3.2 Configuración de Red Estática
```bash
# Editar configuración de red
sudo vim /etc/network/interfaces

# Configuración base (ajustar según VM específica)
auto lo
iface lo inet loopback

auto ens33
iface ens33 inet static
    address 10.10.20.10
    netmask 255.255.255.0
    gateway 10.10.20.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

#### 2.3.3 Configuración SSH
```bash
# Editar configuración SSH
sudo vim /etc/ssh/sshd_config

# Configuraciones de seguridad:
Port 22
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Reiniciar servicio SSH
sudo systemctl restart sshd
sudo systemctl enable sshd
```

#### 2.3.4 Configuración de Firewall Base (Solo para VMs específicas)
```bash
# IMPORTANTE: Este paso solo aplica para:
# VM3-WebServer, VM4-Honeypot, VM7-IDS, VM8-VPN, VM9-Auth
# 
# NO instalar UFW en: VM2-Firewall, VM6-SIEM, VM10-AdminWS, VM11-UserWS

# Instalar y configurar UFW básico
sudo apt install -y ufw

# Configuración básica de seguridad
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh

# NO habilitar aún - se configurará específicamente en cada script
# sudo ufw enable
```

**Nota:** La configuración específica del firewall para cada VM se realizará mediante los scripts de configuración especializados. El firewall principal del sistema está en VM2-Firewall.

#### 2.3.5 Configuración de Logging
```bash
# Configurar rsyslog para centralización
sudo vim /etc/rsyslog.conf

# Agregar al final:
*.*    @@10.10.30.10:514

# Reiniciar rsyslog
sudo systemctl restart rsyslog
```

### 2.4 Creación de Snapshot Base
```bash
# En VMware:
1. Apagar la VM correctamente: sudo shutdown -h now
2. Click derecho en VM → Snapshot → Take Snapshot
3. Nombre: "Debian-12-Base-Configured"
4. Descripción: "Sistema base con configuraciones de seguridad"
```

## 3. VM1 - Router Simulado (Gateway Internet)

### 3.1 Configuración de VM
```bash
# Clonar VM base
# Configurar interfaces de red:
# - ens33: NAT (Internet)
# - ens34: VMnet1 (192.168.1.0/24)
```

### 3.2 Configuración de Red
```bash
# /etc/network/interfaces
auto lo
iface lo inet loopback

# Interfaz WAN (NAT)
auto ens33
iface ens33 inet dhcp

# Interfaz LAN
auto ens34  
iface ens34 inet static
    address 192.168.1.1
    netmask 255.255.255.0
```

### 3.3 Configuración de Routing y NAT
```bash
# Habilitar IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Instalar iptables-persistent
sudo apt install -y iptables-persistent

# Configurar reglas de NAT
sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
sudo iptables -A FORWARD -i ens34 -o ens33 -j ACCEPT
sudo iptables -A FORWARD -i ens33 -o ens34 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Guardar reglas
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 3.4 Configuración DHCP
```bash
# Instalar isc-dhcp-server
sudo apt install -y isc-dhcp-server

# Configurar /etc/dhcp/dhcpd.conf
sudo vim /etc/dhcp/dhcpd.conf

# Contenido:
default-lease-time 600;
max-lease-time 7200;
authoritative;

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option domain-name "fei.local";
    option domain-name-servers 8.8.8.8, 8.8.4.4;
    option routers 192.168.1.1;
}

# Configurar interfaz para DHCP
echo 'INTERFACESv4="ens34"' | sudo tee /etc/default/isc-dhcp-server

# Iniciar servicio
sudo systemctl enable isc-dhcp-server
sudo systemctl start isc-dhcp-server
```

## 4. VM2 - Firewall Principal (pfSense o iptables)

### 4.1 Opción A: Usando iptables en Debian

```bash
# Configuración de interfaces
# /etc/network/interfaces
auto lo
iface lo inet loopback

# WAN
auto ens33
iface ens33 inet static
    address 192.168.1.2
    netmask 255.255.255.0
    gateway 192.168.1.1

# DMZ
auto ens34
iface ens34 inet static
    address 10.10.10.1
    netmask 255.255.255.0

# LAN
auto ens35
iface ens35 inet static
    address 10.10.20.1
    netmask 255.255.255.0

# Management
auto ens36
iface ens36 inet static
    address 10.10.30.1
    netmask 255.255.255.0
```

### 4.2 Script de Firewall
```bash
# Crear script de firewall
sudo vim /etc/firewall/firewall.sh

#!/bin/bash
# Firewall FEI - Script de configuración

# Limpiar reglas existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Políticas por defecto
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir tráfico establecido
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH desde red de gestión
iptables -A INPUT -p tcp -s 10.10.30.0/24 --dport 22 -j ACCEPT

# Reglas DMZ
# HTTP/HTTPS hacia servidor web
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.10 --dport 443 -j ACCEPT

# Reglas LAN
# Permitir LAN hacia Internet via proxy
iptables -A FORWARD -p tcp -s 10.10.20.0/24 -d 192.168.1.0/24 --dport 3128 -j ACCEPT

# NAT para DMZ y LAN
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ens33 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.10.20.0/24 -o ens33 -j MASQUERADE

# Port forwarding para servicios DMZ
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination 10.10.10.10:80
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 443 -j DNAT --to-destination 10.10.10.10:443

# Logging
iptables -A INPUT -j LOG --log-prefix "FW-INPUT-DROP: "
iptables -A FORWARD -j LOG --log-prefix "FW-FORWARD-DROP: "

# Hacer script ejecutable
sudo chmod +x /etc/firewall/firewall.sh

# Ejecutar al inicio
echo '/etc/firewall/firewall.sh' | sudo tee -a /etc/rc.local
```

## 5. VM3 - Servidor Web (DMZ)

### 5.1 Configuración de Red
```bash
# /etc/network/interfaces
auto ens33
iface ens33 inet static
    address 10.10.10.10
    netmask 255.255.255.0
    gateway 10.10.10.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

### 5.2 Instalación de LAMP Stack
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Apache
sudo apt install -y apache2

# Instalar MySQL
sudo apt install -y mariadb-server
sudo mysql_secure_installation

# Instalar PHP
sudo apt install -y php php-mysql php-cli php-curl php-gd php-mbstring php-xml libapache2-mod-php

# Habilitar módulos Apache
sudo a2enmod rewrite
sudo a2enmod ssl
sudo systemctl restart apache2
```

### 5.3 Configuración de Seguridad Apache
```bash
# Configurar headers de seguridad
sudo vim /etc/apache2/conf-available/security.conf

# Agregar/modificar:
ServerTokens Prod
ServerSignature Off
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'"

# Habilitar configuración
sudo a2enmod headers
sudo a2enconf security
sudo systemctl restart apache2
```

### 5.4 Instalación de fail2ban
```bash
# Instalar fail2ban
sudo apt install -y fail2ban

# Configurar para Apache
sudo vim /etc/fail2ban/jail.local

[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true

# Iniciar servicio
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## 6. VM4 - Honeypot

### 6.1 Configuración de Red
```bash
# /etc/network/interfaces
auto ens33
iface ens33 inet static
    address 10.10.10.20
    netmask 255.255.255.0
    gateway 10.10.10.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

### 6.2 Instalación de Cowrie (SSH Honeypot)
```bash
# Instalar dependencias
sudo apt install -y python3-pip python3-venv git

# Crear usuario para cowrie
sudo adduser --disabled-password cowrie

# Cambiar a usuario cowrie
sudo su - cowrie

# Clonar Cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie

# Crear entorno virtual
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Instalar Cowrie
pip install --upgrade pip
pip install --upgrade -r requirements.txt

# Configurar Cowrie
cp etc/cowrie.cfg.dist etc/cowrie.cfg
vim etc/cowrie.cfg

# Configuración básica:
[honeypot]
hostname = srv-fei-01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]  
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

# Generar claves SSH
cd var
../bin/createfs

# Volver a root y configurar redirección de puertos
exit

# Redirigir puerto 22 a 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
```

### 6.3 Instalación de Dionaea (Malware Honeypot)
```bash
# Instalar dependencias
sudo apt install -y cmake check cython3 libcurl4-openssl-dev libemu-dev \
    libev-dev libglib2.0-dev libloudmouth1-dev libnetfilter-queue-dev \
    libnl-3-dev libpcap-dev libssl-dev libudns-dev python3 python3-dev \
    python3-bson python3-yaml python3-boto3

# Clonar y compilar Dionaea
cd /opt
sudo git clone https://github.com/DinoTools/dionaea.git
cd dionaea
sudo mkdir build
cd build
sudo cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..
sudo make
sudo make install
```

## 7. VM5 - Proxy Server (Squid)

### 7.1 Configuración de Red
```bash
# /etc/network/interfaces
auto ens33
iface ens33 inet static
    address 10.10.20.10
    netmask 255.255.255.0
    gateway 10.10.20.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

### 7.2 Instalación y Configuración de Squid
```bash
# Instalar Squid
sudo apt install -y squid squidguard

# Backup configuración original
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

# Configurar Squid
sudo vim /etc/squid/squid.conf

# Configuración básica:
# Puerto y dirección
http_port 3128

# ACLs de red
acl localnet src 10.10.20.0/24
acl localnet src 10.10.30.0/24

# ACLs de tiempo
acl business_hours time MTWHF 08:00-18:00

# ACLs de sitios bloqueados
acl blocked_sites dstdomain "/etc/squid/blocked_sites"
acl adult_sites dstdomain "/etc/squid/adult_sites"

# Reglas de acceso
http_access allow localnet business_hours
http_access deny blocked_sites
http_access deny adult_sites
http_access deny all

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
```

### 7.3 Configurar Listas de Bloqueo
```bash
# Crear lista de sitios bloqueados
sudo vim /etc/squid/blocked_sites
facebook.com
twitter.com
youtube.com
instagram.com

# Crear lista de sitios para adultos
sudo vim /etc/squid/adult_sites
.xxx
.porn
.adult

# Reiniciar Squid
sudo systemctl restart squid
sudo systemctl enable squid
```

## 8. VM6 - SIEM/Log Server (ELK Stack)

### 8.1 Configuración de Red
```bash
# /etc/network/interfaces
auto ens33
iface ens33 inet static
    address 10.10.30.10
    netmask 255.255.255.0
    gateway 10.10.30.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

### 8.2 Instalación de Elasticsearch
```bash
# Instalar Java 11
sudo apt install -y openjdk-11-jdk

# Agregar repositorio de Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Instalar Elasticsearch
sudo apt update
sudo apt install -y elasticsearch

# Configurar Elasticsearch
sudo vim /etc/elasticsearch/elasticsearch.yml

# Configuración básica:
cluster.name: fei-siem
node.name: siem-node-1
network.host: 10.10.30.10
http.port: 9200
discovery.type: single-node

# Iniciar servicio
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

### 8.3 Instalación de Logstash
```bash
# Instalar Logstash
sudo apt install -y logstash

# Configurar pipeline básico
sudo vim /etc/logstash/conf.d/syslog.conf

input {
  udp {
    port => 514
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{PROG:program}: %{GREEDYDATA:message}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["10.10.30.10:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
}

# Iniciar servicio
sudo systemctl enable logstash
sudo systemctl start logstash
```

### 8.4 Instalación de Kibana
```bash
# Instalar Kibana
sudo apt install -y kibana

# Configurar Kibana
sudo vim /etc/kibana/kibana.yml

# Configuración básica:
server.port: 5601
server.host: "10.10.30.10"
elasticsearch.hosts: ["http://10.10.30.10:9200"]

# Iniciar servicio
sudo systemctl enable kibana
sudo systemctl start kibana
```

## 9. Automatización con Scripts

### 9.1 Script de Instalación Automatizada
```bash
# Crear script de automatización
vim /root/install-vm.sh

#!/bin/bash
# Script de instalación automatizada para VMs FEI

VM_TYPE=$1
VM_NAME=$2
VM_IP=$3

case $VM_TYPE in
    "firewall")
        echo "Configurando Firewall..."
        # Comandos específicos para firewall
        ;;
    "web")
        echo "Configurando Servidor Web..."
        # Comandos específicos para web server
        ;;
    "proxy")
        echo "Configurando Proxy..."
        # Comandos específicos para proxy
        ;;
    *)
        echo "Tipo de VM no reconocido"
        exit 1
        ;;
esac

echo "VM $VM_NAME configurada exitosamente"
```

### 9.2 Scripts de Monitoreo
```bash
# Script de monitoreo de servicios
vim /usr/local/bin/monitor-services.sh

#!/bin/bash
# Monitor de servicios críticos

SERVICES=("ssh" "apache2" "mysql" "squid" "elasticsearch")
LOG_FILE="/var/log/service-monitor.log"

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "$(date): $service - OK" >> $LOG_FILE
    else
        echo "$(date): $service - FAILED" >> $LOG_FILE
        # Enviar alerta
        logger "ALERT: Service $service is down"
    fi
done
```

## 10. Procedimientos de Backup y Snapshots

### 10.1 Estrategia de Snapshots en VMware
```bash
# Script PowerShell para automatizar snapshots (ejecutar en host Windows)
# snapshot-vms.ps1

$VMs = @("Router-FEI", "Firewall-FEI", "Web-FEI", "Proxy-FEI", "SIEM-FEI")
$SnapshotName = "Daily-Backup-$(Get-Date -Format 'yyyy-MM-dd')"

foreach ($VM in $VMs) {
    Write-Host "Creating snapshot for $VM"
    & "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" snapshot "C:\VMs\$VM\$VM.vmx" $SnapshotName
}
```

### 10.2 Backup de Configuraciones
```bash
# Script de backup de configuraciones
vim /usr/local/bin/backup-configs.sh

#!/bin/bash
BACKUP_DIR="/var/backups/configs"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/config-backup-$DATE.tar.gz"

mkdir -p $BACKUP_DIR

# Respaldar configuraciones importantes
tar -czf $BACKUP_FILE \
    /etc/network/interfaces \
    /etc/apache2/ \
    /etc/squid/ \
    /etc/ssh/sshd_config \
    /etc/iptables/ \
    /etc/fail2ban/

echo "Backup completed: $BACKUP_FILE"
```

## 3. Estrategia de Firewall por Máquina Virtual

### 3.1 Matriz de Configuración de Firewall

| VM | Nombre | Función | Firewall Local | Razón |
|----|--------|---------|----------------|-------|
| VM1 | Router | Gateway simulado | iptables básico | Routing entre redes |
| **VM2** | **Firewall** | **Firewall principal** | **iptables avanzado** | **Control perimetral completo** |
| VM3 | WebServer | Servidor web DMZ | UFW + iptables | Servidor público expuesto |
| VM4 | Honeypot | Honeypot DMZ | UFW básico | Protección del sistema honeypot |
| VM5 | Proxy | Servidor proxy | UFW básico | Filtrado de contenido |
| VM6 | SIEM | Análisis logs | Sin firewall local | Red interna segura |
| VM7 | IDS | Detección intrusiones | UFW básico | Sistema crítico de detección |
| VM8 | VPN | Servidor VPN | UFW + iptables | Punto acceso remoto |
| VM9 | Auth | Autenticación | UFW básico | Servicios críticos LDAP/RADIUS |
| VM10 | AdminWS | Estación admin | Sin firewall local | Red de gestión segura |
| VM11 | UserWS | Estación usuario | Sin firewall local | Red interna protegida |

### 3.2 Justificación de la Estrategia

#### 🔥 **Firewall Principal (VM2)**
- **Función:** Control perimetral completo del sistema
- **Tecnología:** iptables con reglas avanzadas + fail2ban
- **Responsabilidad:** Filtrado entre todas las redes (WAN, DMZ, LAN, MGMT)

#### 🛡️ **Firewalls Locales (VMs Específicas)**
- **Función:** Protección adicional en servicios críticos o expuestos
- **Tecnología:** UFW para configuración sencilla
- **Principio:** Defensa en profundidad (Defense in Depth)

#### 🔒 **Sin Firewall Local (VMs Internas)**
- **Función:** Sistemas en redes internas ya protegidas por firewall principal
- **Justificación:** Evitar complejidad innecesaria y posibles conflictos
- **Seguridad:** Protegidas por segmentación de red y firewall perimetral

### 3.3 Configuración Específica por Tipo

#### Para VMs con UFW (VM3, VM4, VM7, VM8, VM9):
```bash
# Instalación básica durante preparación de VM base
sudo apt install -y ufw

# Configuración inicial (sin activar)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh

# La activación y reglas específicas se realizan 
# mediante los scripts de configuración especializados
```

#### Para VM2-Firewall:
```bash
# NO instalar UFW - usar iptables directamente
# La configuración se realiza con configure-firewall.sh
```

#### Para VMs sin firewall local (VM6, VM10, VM11):
```bash
# NO instalar UFW ni configurar iptables
# Confiar en la segmentación de red y firewall principal
```

### 3.4 Ventajas de esta Estrategia

1. **Simplicidad:** Evita conflictos entre múltiples firewalls
2. **Centralización:** Control principal en VM2-Firewall
3. **Defensa en profundidad:** Protección adicional donde es necesaria
4. **Mantenibilidad:** Configuración clara y específica por función
5. **Rendimiento:** Sin overhead innecesario en VMs internas
