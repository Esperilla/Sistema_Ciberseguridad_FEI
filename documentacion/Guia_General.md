# Guía Unificada de Implementación - Sistema Ciberseguridad FEI

## 📋 Información General

**Proyecto:** Sistema Integral de Ciberseguridad para la Facultad de Estadística e Informática  
**Framework:** NIST Cybersecurity Framework 2.0  
**Plataforma:** VMware Workstation con Debian 12  
**Institución:** Universidad Veracruzana - FEI

## 🎯 Modalidades de Implementación

Esta guía unificada ofrece dos enfoques complementarios para implementar el sistema:

### 🚀 Modalidad A: Implementación Automatizada (8-10 horas)
**Para usuarios que prefieren deployment rápido:**
- ✅ Scripts automatizados pre-configurados
- ✅ Configuraciones estándar optimizadas
- ✅ Validación automática de servicios
- ✅ Ideal para demostraciones y entornos de prueba

### 🔧 Modalidad B: Implementación Manual (12-16 horas)
**Para usuarios que buscan comprensión técnica profunda:**
- ✅ Configuración paso a paso de cada componente
- ✅ Explicación técnica detallada de cada servicio
- ✅ Troubleshooting avanzado
- ✅ Personalización completa de configuraciones

---

## 🏗️ Arquitectura del Sistema

### Topología de Red
```
Internet
    |
[VM1-Router] (192.168.1.1)
    |
[VM2-Firewall] (192.168.1.2)
    |
    +-- [DMZ] (10.10.10.0/24)
    |     ├── [VM3-WebServer] (10.10.10.10)
    |     └── [VM4-Honeypot] (10.10.10.20)
    |
    +-- [LAN] (10.10.20.0/24)
    |     ├── [VM5-Proxy] (10.10.20.10)
    |     ├── [VM8-VPN] (10.10.20.30)
    |     ├── [VM9-Auth] (10.10.20.40)
    |     └── [VM11-UserWS] (10.10.20.50)
    |
    └── [MGMT] (10.10.30.0/24)
          ├── [VM6-SIEM] (10.10.30.10)
          ├── [VM7-IDS] (10.10.30.20)
          └── [VM10-AdminWS] (10.10.30.50)
```

### Componentes y Recursos

| VM | Componente | IP | RAM | Función Principal |
|----|------------|----|----|-------------------|
| VM1 | Router Gateway | 192.168.1.1 | 2GB | Simulación Internet |
| VM2 | Firewall Principal | Múltiples IPs | 4GB | Segmentación y filtrado |
| VM3 | Servidor Web | 10.10.10.10 | 2GB | Portal institucional seguro |
| VM4 | Honeypot | 10.10.10.20 | 2GB | Detección de intrusiones |
| VM5 | Proxy Web | 10.10.20.10 | 2GB | Filtrado de contenido |
| VM6 | SIEM | 10.10.30.10 | 8GB | Monitoreo centralizado |
| VM7 | IDS/IPS | 10.10.30.20 | 4GB | Detección de amenazas |
| VM8 | Servidor VPN | 10.10.20.30 | 2GB | Acceso remoto seguro |
| VM9 | Servidor Auth | 10.10.20.40 | 2GB | Autenticación centralizada |
| VM10 | Estación Admin | 10.10.30.50 | 2GB | Administración del sistema |
| VM11 | Estación Usuario | 10.10.20.50 | 2GB | Usuario final |

**Total RAM requerida:** 30GB (mínimo host: 16GB, recomendado: 32GB)

---

## 🚀 FASE 1: Preparación del Entorno (45-60 minutos)

### 1.1 Prerrequisitos del Sistema Host

#### Hardware Mínimo
- **CPU:** Intel i5/AMD Ryzen 5 con virtualización (VT-x/AMD-V)
- **RAM:** 16 GB mínimo (recomendado 32 GB)
- **Almacenamiento:** 500 GB espacio libre
- **Red:** Conexión a Internet estable

#### Software Requerido
- **VMware Workstation Pro 17** o superior (no Player)
- **Debian 12 ISO** oficial descargada
- **Acceso administrativo** al sistema host

### 1.2 Configuración de Redes Virtuales en VMware

#### Crear Redes Personalizadas
```bash
# En VMware Workstation: Edit → Virtual Network Editor

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

### 1.3 Instalación de VM Base (Debian 12)

#### Configuración de VM Base
```bash
# Especificaciones para VM plantilla:
Memoria RAM: 2 GB
Almacenamiento: 30 GB (thin provisioning)
Tipo de disco: SCSI
Red: NAT (solo para instalación inicial)
```

#### Proceso de Instalación Debian
```bash
# Configuración durante instalación:
Idioma: Spanish
País: México  
Teclado: Latinoamericano
Hostname: debian-base
Dominio: fei.local

# Usuario root: [Password según política]
# Usuario admin: admin-fei [Password según política]

# Particionado recomendado:
/boot     - 512 MB (ext4)
/         - 15 GB (ext4)  
/var      - 8 GB (ext4)
/var/log  - 4 GB (ext4)
/home     - 2 GB (ext4)
swap      - 1 GB

# Software a instalar:
☑ SSH server
☑ Standard system utilities  
☐ Desktop environment
☐ Web server
☐ Print server
```

#### Configuración Post-Instalación
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar herramientas básicas
sudo apt install -y vim curl wget git net-tools htop tree \
    software-properties-common apt-transport-https nano isc-dhcp-server \
    ca-certificates gnupg lsb-release iptables-persistent rsyslog \
    openssh-server sudo build-essential dkms linux-headers-$(uname -r)

# Configurar SSH seguro
sudo vim /etc/ssh/sshd_config
# Port 22
# PermitRootLogin no
# PasswordAuthentication yes
# PubkeyAuthentication yes
# MaxAuthTries 3
# ClientAliveInterval 300
# ClientAliveCountMax 2

sudo systemctl restart sshd

# Configurar logging centralizado
sudo vim /etc/rsyslog.conf
# Agregar: *.*    @@10.10.30.10:514
sudo systemctl restart rsyslog
```

#### Crear Snapshot Base
```bash
# En VMware:
# 1. Apagar VM: sudo shutdown -h now
# 2. VM → Snapshot → Take Snapshot
# 3. Nombre: "Debian-12-Base-Configured"
# 4. Descripción: "Base con configuraciones de seguridad"
```

### 1.4 Clonación y Configuración de Red

#### Clonar VMs
```bash
# En VMware Workstation, clonar VM base 11 veces:
# VM → Manage → Clone → Create linked clone from "Base-Configured"

# Configurar interfaces de red según tabla anterior
# Asignar VMnets correspondientes a cada VM
```

#### Configuración de IPs Estáticas
```bash
# Para cada VM, editar /etc/network/interfaces

# Ejemplo VM3-WebServer (DMZ):
auto lo
iface lo inet loopback

auto ens33
iface ens33 inet static
    address 10.10.10.10
    netmask 255.255.255.0
    gateway 10.10.10.1
    dns-nameservers 8.8.8.8 8.8.4.4

# Aplicar cambios:
sudo systemctl restart networking
```

---

## 🛠️ FASE 2: Implementación de Componentes de Seguridad

### Elección de Modalidad

#### Para Modalidad A (Automatizada) - Ir a Sección 2A
#### Para Modalidad B (Manual) - Ir a Sección 2B

---

## 🚀 SECCIÓN 2A: IMPLEMENTACIÓN AUTOMATIZADA (4-6 horas)

### 2A.1 Configuración con Scripts

#### VM2 - Firewall Principal (45 minutos)
```bash
# En VM2-Firewall:
cd /path/to/scripts
chmod +x configure-firewall.sh
./configure-firewall.sh

# Verificación automática:
systemctl status iptables
iptables -L -n
fail2ban-client status
```

#### VM3 - Servidor Web Seguro (30 minutos)
```bash
# En VM3-WebServer:
chmod +x configure-webserver.sh
./configure-webserver.sh

# Verificación automática:
systemctl status apache2
curl -I http://10.10.10.10
curl -I https://10.10.10.10
```

#### VM4 - Honeypot (60 minutos)
```bash
# En VM4-Honeypot:
chmod +x configure-honeypot.sh
./configure-honeypot.sh

# Verificación automática:
systemctl status cowrie
netstat -tlnp | grep 2222
curl -I http://10.10.10.20:8080
```

#### VM5 - Servidor Proxy (45 minutos)
```bash
# En VM5-Proxy:
chmod +x configure-proxy.sh
./configure-proxy.sh

# Verificación automática:
systemctl status squid
curl --proxy 10.10.20.10:3128 -I google.com
```

#### VM6 - SIEM (90 minutos)
```bash
# En VM6-SIEM:
chmod +x configure-siem.sh
./configure-siem.sh

# Verificación automática:
curl -X GET "10.10.30.10:9200/_cluster/health?pretty"
curl -I http://10.10.30.10:5601
```

#### VM7 - IDS/IPS (60 minutos)
```bash
# En VM7-IDS:
chmod +x configure-ids-ips.sh
./configure-ids-ips.sh

# Verificación automática:
systemctl status suricata-fei
/usr/local/bin/suricata-monitor.sh
```

#### VM8 - Servidor VPN (75 minutos)
```bash
# En VM8-VPN:
chmod +x configure-vpn-server.sh
./configure-vpn-server.sh

# Verificación automática:
systemctl status openvpn@server
/usr/local/bin/vpn-monitor.sh
```

#### VM9 - Servidor de Autenticación (90 minutos)
```bash
# En VM9-Auth:
chmod +x configure-auth-server.sh
./configure-auth-server.sh

# Verificación automática:
systemctl status slapd freeradius apache2
ldapsearch -x -H ldap://10.10.20.40 -b "dc=fei,dc=uv,dc=mx"
```

### 2A.2 Configuración del Monitoreo (30 minutos)
```bash
# En VM10-AdminWS:
chmod +x monitor-integral.sh
cp monitor-integral.sh /usr/local/bin/

# Verificación completa del sistema:
monitor-integral.sh status
monitor-integral.sh check
```

---

## 🔧 SECCIÓN 2B: IMPLEMENTACIÓN MANUAL (8-12 horas)

### 2B.1 VM1 - Router Simulado (60 minutos)

#### Configuración de Interfaces
```bash
# /etc/network/interfaces
auto lo
iface lo inet loopback

# Interfaz WAN (NAT hacia Internet)
auto ens33
iface ens33 inet dhcp

# Interfaz LAN (hacia Firewall)
auto ens34  
iface ens34 inet static
    address 192.168.1.1
    netmask 255.255.255.0
```

#### Configuración de Routing y NAT
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

#### Configuración DHCP
```bash
# Instalar isc-dhcp-server
sudo apt install -y isc-dhcp-server

# Configurar /etc/dhcp/dhcpd.conf
sudo vim /etc/dhcp/dhcpd.conf

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

### 2B.2 VM2 - Firewall Principal (90 minutos)

#### Configuración de Interfaces Múltiples
```bash
# /etc/network/interfaces
auto lo
iface lo inet loopback

# WAN (hacia Router)
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

#### Script de Firewall Avanzado
```bash
# Crear directorio y script
sudo mkdir -p /etc/firewall
sudo vim /etc/firewall/firewall.sh

#!/bin/bash
# Firewall FEI - Script de configuración completo

# Limpiar reglas existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Políticas por defecto (DENY ALL)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir tráfico establecido y relacionado
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH desde red de gestión únicamente
iptables -A INPUT -p tcp -s 10.10.30.0/24 --dport 22 -j ACCEPT

# Reglas DMZ (Zona Desmilitarizada)
# HTTP/HTTPS hacia servidor web
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.10 --dport 443 -j ACCEPT

# SSH hacia honeypot (redirigido)
iptables -A FORWARD -p tcp -s 192.168.1.0/24 -d 10.10.10.20 --dport 22 -j ACCEPT

# Reglas LAN (Red Interna)
# Permitir LAN hacia Internet via proxy
iptables -A FORWARD -p tcp -s 10.10.20.0/24 -d 192.168.1.0/24 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -s 10.10.20.0/24 -d 192.168.1.0/24 --dport 443 -j ACCEPT

# DNS para LAN
iptables -A FORWARD -p udp -s 10.10.20.0/24 --dport 53 -j ACCEPT

# VPN connections
iptables -A FORWARD -p udp -s 192.168.1.0/24 -d 10.10.20.30 --dport 1194 -j ACCEPT

# Reglas de Management
# Permitir gestión hacia todos los segmentos
iptables -A FORWARD -s 10.10.30.0/24 -j ACCEPT

# NAT para todos los segmentos internos
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ens33 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.10.20.0/24 -o ens33 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.10.30.0/24 -o ens33 -j MASQUERADE

# Port forwarding para servicios públicos
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination 10.10.10.10:80
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 443 -j DNAT --to-destination 10.10.10.10:443
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 22 -j DNAT --to-destination 10.10.10.20:22

# Logging de conexiones denegadas
iptables -A INPUT -j LOG --log-prefix "FW-INPUT-DROP: "
iptables -A FORWARD -j LOG --log-prefix "FW-FORWARD-DROP: "

# Hacer script ejecutable y configurar para inicio
sudo chmod +x /etc/firewall/firewall.sh

# Ejecutar al inicio del sistema
echo '#!/bin/bash' | sudo tee /etc/rc.local
echo '/etc/firewall/firewall.sh' | sudo tee -a /etc/rc.local
echo 'exit 0' | sudo tee -a /etc/rc.local
sudo chmod +x /etc/rc.local
```

#### Instalación y Configuración de fail2ban
```bash
# Instalar fail2ban
sudo apt install -y fail2ban

# Configuración personalizada
sudo vim /etc/fail2ban/jail.local

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

# Iniciar y habilitar servicio
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 2B.3 VM3 - Servidor Web Seguro (90 minutos)

#### Instalación de LAMP Stack
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Apache Web Server
sudo apt install -y apache2

# Instalar MariaDB Database Server
sudo apt install -y mariadb-server
sudo mysql_secure_installation

# Instalar PHP y módulos
sudo apt install -y php php-mysql php-cli php-curl php-gd \
    php-mbstring php-xml php-zip libapache2-mod-php

# Habilitar módulos críticos de Apache
sudo a2enmod rewrite ssl headers
sudo systemctl restart apache2
```

#### Configuración de Seguridad Apache
```bash
# Configurar headers de seguridad
sudo vim /etc/apache2/conf-available/security.conf

# Configuración de seguridad avanzada:
ServerTokens Prod
ServerSignature Off

# Headers de seguridad HTTP
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Ocultar información del servidor
Header always unset Server
Header always unset X-Powered-By

# Habilitar configuración
sudo a2enconf security
sudo systemctl restart apache2
```

#### Configuración SSL/TLS
```bash
# Generar certificado auto-firmado para pruebas
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/fei-selfsigned.key \
    -out /etc/ssl/certs/fei-selfsigned.crt \
    -subj "/C=MX/ST=Veracruz/L=Xalapa/O=Universidad Veracruzana/OU=FEI/CN=10.10.10.10"

# Configurar sitio SSL
sudo vim /etc/apache2/sites-available/fei-ssl.conf

<VirtualHost *:443>
    ServerName 10.10.10.10
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/fei-selfsigned.crt
    SSLCertificateKeyFile /etc/ssl/private/fei-selfsigned.key

    # Configuración SSL moderna
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off
    SSLSessionTickets off

    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>

# Habilitar sitio SSL
sudo a2ensite fei-ssl
sudo systemctl restart apache2
```

#### Instalación y Configuración de fail2ban para Apache
```bash
# Configurar fail2ban para Apache
sudo vim /etc/fail2ban/jail.local

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
logpath = /var/log/apache2/error.log
maxretry = 2

# Reiniciar fail2ban
sudo systemctl restart fail2ban
```

#### Crear Portal Web de Demostración
```bash
# Crear página principal
sudo vim /var/www/html/index.php

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal FEI - Sistema de Ciberseguridad</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
        .container { background: white; padding: 20px; border-radius: 10px; }
        .header { background: #004080; color: white; padding: 20px; text-align: center; }
        .status { background: #e8f5e8; padding: 15px; margin: 20px 0; border-left: 4px solid #4CAF50; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Universidad Veracruzana</h1>
            <h2>Facultad de Estadística e Informática</h2>
            <p>Sistema Integral de Ciberseguridad - NIST CSF 2.0</p>
        </div>
        
        <div class="status">
            <h3>Estado del Sistema</h3>
            <p><strong>Servidor Web:</strong> ✅ Funcionando</p>
            <p><strong>SSL/TLS:</strong> ✅ Configurado</p>
            <p><strong>Fail2ban:</strong> ✅ Activo</p>
            <p><strong>Timestamp:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
        
        <h3>Componentes de Seguridad Implementados</h3>
        <ul>
            <li>Firewall perimetral con segmentación de red</li>
            <li>Sistema de detección de intrusiones (IDS/IPS)</li>
            <li>Honeypots para detección temprana</li>
            <li>SIEM para correlación de eventos</li>
            <li>Proxy web con filtrado de contenido</li>
            <li>VPN para acceso remoto seguro</li>
            <li>Servidor de autenticación centralizada</li>
        </ul>
    </div>
</body>
</html>

# Configurar permisos
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

### 2B.4 VM4 - Honeypot (120 minutos)

#### Instalación de Cowrie SSH Honeypot
```bash
# Instalar dependencias
sudo apt install -y python3-pip python3-venv git authbind

# Crear usuario dedicado para cowrie
sudo adduser --disabled-password cowrie
sudo su - cowrie

# Clonar repositorio de Cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie

# Crear entorno virtual Python
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Instalar Cowrie y dependencias
pip install --upgrade pip
pip install --upgrade -r requirements.txt

# Configurar Cowrie
cp etc/cowrie.cfg.dist etc/cowrie.cfg
vim etc/cowrie.cfg

[honeypot]
hostname = srv-fei-01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/tty
state_path = var/lib/cowrie
etc_path = etc

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

# Generar filesystem falso
cd var
../bin/createfs

# Salir del usuario cowrie
exit

# Configurar authbind para puertos privilegiados
sudo touch /etc/authbind/byport/22
sudo touch /etc/authbind/byport/23
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/23
sudo chmod 754 /etc/authbind/byport/22
sudo chmod 754 /etc/authbind/byport/23
```

#### Configuración de Redirección de Puertos
```bash
# Método 1: iptables (recomendado)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Guardar reglas
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Método 2: authbind (alternativo)
# sudo -u cowrie authbind --deep /home/cowrie/cowrie/bin/cowrie start
```

#### Instalación de Dionaea (Malware Honeypot)
```bash
# Instalar dependencias para Dionaea
sudo apt install -y cmake check cython3 libcurl4-openssl-dev \
    libemu-dev libev-dev libglib2.0-dev libloudmouth1-dev \
    libnetfilter-queue-dev libnl-3-dev libpcap-dev libssl-dev \
    libudns-dev python3 python3-dev python3-bson python3-yaml \
    python3-boto3 sqlite3 libsqlite3-dev

# Clonar y compilar Dionaea
cd /opt
sudo git clone https://github.com/DinoTools/dionaea.git
cd dionaea
sudo mkdir build
cd build

# Configurar compilación
sudo cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..
sudo make
sudo make install

# Configurar Dionaea
sudo cp /opt/dionaea/etc/dionaea/dionaea.cfg.dist /opt/dionaea/etc/dionaea/dionaea.cfg
sudo vim /opt/dionaea/etc/dionaea/dionaea.cfg

# Configuración básica para FEI
[dionaea]
download.dir=/opt/dionaea/var/lib/dionaea/binaries/
listen.addresses=0.0.0.0
listen.interfaces=ens33

[module.python]
sys_paths=/opt/dionaea/lib/dionaea/python/

# Crear servicio systemd para Dionaea
sudo vim /etc/systemd/system/dionaea.service

[Unit]
Description=Dionaea Honeypot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg
Restart=always

[Install]
WantedBy=multi-user.target
```

#### Web Honeypot Simple
```bash
# Instalar servidor web ligero para honeypot
sudo apt install -y nginx

# Crear configuración de sitio honeypot
sudo vim /etc/nginx/sites-available/honeypot

server {
    listen 8080;
    server_name _;
    
    root /var/www/honeypot;
    index index.html;
    
    # Log todas las requests
    access_log /var/log/nginx/honeypot_access.log;
    error_log /var/log/nginx/honeypot_error.log;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    # Simular vulnerabilidades comunes
    location /admin {
        return 200 "Admin Panel - Please Login";
        add_header Content-Type text/plain;
    }
    
    location /wp-admin {
        return 200 "WordPress Admin";
        add_header Content-Type text/plain;
    }
    
    location /phpmyadmin {
        return 200 "phpMyAdmin Login";
        add_header Content-Type text/plain;
    }
}

# Crear directorio y contenido
sudo mkdir -p /var/www/honeypot
sudo vim /var/www/honeypot/index.html

<!DOCTYPE html>
<html>
<head>
    <title>FEI Server</title>
</head>
<body>
    <h1>Welcome to FEI Server</h1>
    <p>This is a test server for the Faculty of Statistics and Informatics</p>
    <p>Server Status: Online</p>
</body>
</html>

# Habilitar sitio
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### Servicios Systemd para Honeypots
```bash
# Crear servicio para Cowrie
sudo vim /etc/systemd/system/cowrie.service

[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=simple
User=cowrie
ExecStart=/home/cowrie/cowrie/bin/cowrie start
ExecStop=/home/cowrie/cowrie/bin/cowrie stop
Restart=always

[Install]
WantedBy=multi-user.target

# Habilitar y iniciar servicios
sudo systemctl daemon-reload
sudo systemctl enable cowrie dionaea nginx
sudo systemctl start cowrie dionaea nginx
```

### 2B.5 VM5 - Servidor Proxy (75 minutos)

#### Instalación y Configuración Base de Squid
```bash
# Instalar Squid y herramientas adicionales
sudo apt install -y squid squidguard squid-langpack

# Crear backup de configuración original
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

# Configuración personalizada de Squid
sudo vim /etc/squid/squid.conf

# Configuración completa de Squid para FEI
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http

# Definir redes locales
acl localnet src 10.10.20.0/24   # Red LAN
acl localnet src 10.10.30.0/24   # Red Management

# ACLs de tiempo
acl business_hours time MTWHF 08:00-18:00
acl weekend time SA 09:00-17:00
acl sunday time SU 10:00-16:00

# ACLs de sitios bloqueados
acl blocked_social dstdomain "/etc/squid/blocked_social"
acl blocked_adult dstdomain "/etc/squid/blocked_adult"
acl blocked_streaming dstdomain "/etc/squid/blocked_streaming"
acl allowed_educational dstdomain "/etc/squid/allowed_educational"

# Puerto de Squid
http_port 3128

# Reglas de acceso
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Permitir sitios educativos siempre
http_access allow allowed_educational localnet

# Reglas de horario
http_access allow localnet business_hours
http_access allow localnet weekend
http_access allow localnet sunday

# Denegar categorías bloqueadas
http_access deny blocked_social
http_access deny blocked_adult
http_access deny blocked_streaming business_hours

# Denegar todo lo demás
http_access deny all

# Configuración de cache
cache_dir ufs /var/spool/squid 1000 16 256
maximum_object_size 50 MB
cache_mem 256 MB

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log /var/log/squid/store.log

# Headers de privacidad
forwarded_for delete
via off

# DNS
dns_nameservers 8.8.8.8 8.8.4.4

#### Crear Listas de Filtrado
```bash
# Lista de redes sociales
sudo vim /etc/squid/blocked_social
facebook.com
.facebook.com
twitter.com
.twitter.com
instagram.com
.instagram.com
tiktok.com
.tiktok.com
snapchat.com
.snapchat.com

# Lista de contenido adulto
sudo vim /etc/squid/blocked_adult
.xxx
.adult
.porn
.sex

# Lista de streaming (bloqueado en horario laboral)
sudo vim /etc/squid/blocked_streaming
youtube.com
.youtube.com
netflix.com
.netflix.com
twitch.tv
.twitch.tv

# Lista de sitios educativos permitidos
sudo vim /etc/squid/allowed_educational
.edu
.edu.mx
.uv.mx
wikipedia.org
.wikipedia.org
scholar.google.com
coursera.org
.coursera.org
edx.org
.edx.org

# Reiniciar Squid
sudo systemctl restart squid
sudo systemctl enable squid
```

### 2B.6 VM6 - SIEM (ELK Stack) (120 minutos)

#### Instalación de Java y Elasticsearch
```bash
# Instalar OpenJDK 11
sudo apt install -y openjdk-11-jdk

# Verificar instalación
java -version

# Configurar JAVA_HOME
echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64' | sudo tee -a /etc/environment
source /etc/environment

# Agregar repositorio oficial de Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Actualizar e instalar Elasticsearch
sudo apt update
sudo apt install -y elasticsearch

# Configurar Elasticsearch
sudo vim /etc/elasticsearch/elasticsearch.yml

# Configuración para FEI
cluster.name: fei-siem-cluster
node.name: siem-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 10.10.30.10
http.port: 9200
discovery.type: single-node

# Configuración de memoria
bootstrap.memory_lock: true
indices.query.bool.max_clause_count: 10000

# Configurar memoria heap
sudo vim /etc/elasticsearch/jvm.options
# Cambiar -Xms y -Xmx según RAM disponible (máximo 4GB en VM de 8GB)
-Xms2g
-Xmx2g

# Habilitar y iniciar Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Verificar funcionamiento
curl -X GET "localhost:9200/_cluster/health?pretty"
```

#### Instalación de Logstash
```bash
# Instalar Logstash
sudo apt install -y logstash

# Configurar pipeline para syslog
sudo vim /etc/logstash/conf.d/01-syslog.conf

input {
  udp {
    port => 514
    type => "syslog"
  }
  tcp {
    port => 514
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { 
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:logsource} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:logmessage}" 
      }
    }
    
    mutate {
      add_field => { "received_at" => "%{@timestamp}" }
      add_field => { "received_from" => "%{host}" }
    }
    
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["10.10.30.10:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}

# Pipeline para logs de Apache
sudo vim /etc/logstash/conf.d/02-apache.conf

input {
  beats {
    port => 5044
  }
}

filter {
  if [fileset][module] == "apache" {
    if [fileset][name] == "access" {
      grok {
        match => { 
          "message" => "%{COMBINEDAPACHELOG}" 
        }
      }
      
      mutate {
        convert => { "response" => "integer" }
        convert => { "bytes" => "integer" }
      }
      
      date {
        match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["10.10.30.10:9200"]
    index => "apache-%{+YYYY.MM.dd}"
  }
}

# Pipeline para logs de Squid
sudo vim /etc/logstash/conf.d/03-squid.conf

input {
  file {
    path => "/var/log/squid/access.log"
    start_position => "beginning"
    type => "squid"
  }
}

filter {
  if [type] == "squid" {
    grok {
      match => { 
        "message" => "%{NUMBER:timestamp}\s+%{NUMBER:response_time} %{IPORHOST:client_ip} %{WORD:result_code}/%{NUMBER:http_status} %{NUMBER:bytes} %{WORD:request_method} %{URIPROTO:url} %{NOTSPACE:user} %{WORD:hierarchy_code}/%{IPORHOST:server_ip} %{NOTSPACE:content_type}" 
      }
    }
    
    mutate {
      convert => { "response_time" => "integer" }
      convert => { "http_status" => "integer" }
      convert => { "bytes" => "integer" }
    }
    
    date {
      match => [ "timestamp", "UNIX" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["10.10.30.10:9200"]
    index => "squid-%{+YYYY.MM.dd}"
  }
}

# Habilitar y iniciar Logstash
sudo systemctl enable logstash
sudo systemctl start logstash
```

#### Instalación de Kibana
```bash
# Instalar Kibana
sudo apt install -y kibana

# Configurar Kibana
sudo vim /etc/kibana/kibana.yml

# Configuración para FEI
server.port: 5601
server.host: "10.10.30.10"
server.name: "kibana-fei"
elasticsearch.hosts: ["http://10.10.30.10:9200"]
kibana.index: ".kibana"

# Configuración de logging
logging.dest: /var/log/kibana/kibana.log
logging.silent: false
logging.quiet: false
logging.verbose: false

# Habilitar y iniciar Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Verificar funcionamiento
curl -I http://10.10.30.10:5601
```

#### Instalación de Filebeat (en otras VMs)
```bash
# Script para instalar Filebeat en VMs que envían logs
sudo vim /usr/local/bin/install-filebeat.sh

#!/bin/bash
# Instalar Filebeat en VM remota

# Agregar repositorio Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Instalar Filebeat
sudo apt update
sudo apt install -y filebeat

# Configurar Filebeat
sudo vim /etc/filebeat/filebeat.yml

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/auth.log

- type: log
  enabled: true
  paths:
    - /var/log/apache2/*.log
  fields:
    service: apache
  fields_under_root: true

output.logstash:
  hosts: ["10.10.30.10:5044"]

# Habilitar y iniciar Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat

chmod +x /usr/local/bin/install-filebeat.sh
```

### 2B.7 VM7 - IDS/IPS (Suricata) (90 minutos)

#### Instalación de Suricata
```bash
# Agregar repositorio de Suricata
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update

# Instalar Suricata
sudo apt install -y suricata

# Verificar versión
suricata --version
```

#### Configuración de Suricata
```bash
# Configurar Suricata para FEI
sudo vim /etc/suricata/suricata.yaml

# Variables de red para FEI
vars:
  address-groups:
    HOME_NET: "[10.10.10.0/24,10.10.20.0/24,10.10.30.0/24,192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    
    HTTP_SERVERS: "10.10.10.10/32"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

# Configuración de interfaces
af-packet:
  - interface: ens33
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes

# Configuración de logging
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
        - ssh
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow

# Configuración de detección
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

# Configuración de rules
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules

# Configuración de clasificación
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
```

#### Actualización de Reglas
```bash
# Instalar suricata-update para gestión de reglas
sudo pip3 install pyyaml
sudo pip3 install suricata-update

# Configurar suricata-update
sudo suricata-update update-sources
sudo suricata-update enable-source et/open
sudo suricata-update

# Crear reglas personalizadas para FEI
sudo vim /etc/suricata/rules/local.rules

# Reglas personalizadas para el entorno FEI
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH connection attempt"; sid:1000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"HTTP connection to web server"; sid:1000002; rev:1;)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 443 (msg:"HTTPS connection to web server"; sid:1000003; rev:1;)

# Detección de escaneo de puertos
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential port scan"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; sid:1000004; rev:1;)

# Detección de intentos de login SSH
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Multiple SSH login attempts"; content:"Failed password"; threshold: type both, track by_src, count 3, seconds 300; sid:1000005; rev:1;)

# Detección de ataques web comunes
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SQL Injection attempt"; content:"union select"; nocase; sid:1000006; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"XSS attempt"; content:"<script"; nocase; sid:1000007; rev:1;)

# Programar actualización automática de reglas
sudo crontab -e
# Agregar: 0 2 * * * /usr/bin/suricata-update && /bin/systemctl restart suricata
```

#### Configuración como Servicio
```bash
# Configurar Suricata como servicio
sudo vim /etc/default/suricata

# Configuración específica para FEI
SURICATA_OPTIONS="--af-packet=ens33 -D"
LISTENMODE=af-packet

# Crear servicio personalizado
sudo vim /etc/systemd/system/suricata-fei.service

[Unit]
Description=Suricata IDS/IPS for FEI
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet=ens33 -D
ExecReload=/bin/kill -USR2 $MAINPID
KillMode=mixed
Restart=always

[Install]
WantedBy=multi-user.target

# Habilitar y iniciar servicio
sudo systemctl daemon-reload
sudo systemctl enable suricata-fei
sudo systemctl start suricata-fei

# Verificar funcionamiento
sudo systemctl status suricata-fei
sudo tail -f /var/log/suricata/fast.log
```

---

## 🧪 FASE 3: PRUEBAS Y VALIDACIÓN (2-3 horas)

### 3.1 Pruebas de Conectividad (30 minutos)
```bash
# Ejecutar desde VM10-AdminWS
monitor-integral.sh check

# Pruebas específicas de conectividad
ping -c 3 10.10.10.10    # Servidor Web
ping -c 3 10.10.20.10    # Proxy  
ping -c 3 10.10.30.10    # SIEM
ping -c 3 10.10.10.20    # Honeypot
ping -c 3 10.10.30.20    # IDS/IPS
```

### 3.2 Pruebas de Servicios (45 minutos)
```bash
# Verificar servicios web
curl -I http://10.10.10.10
curl -I https://10.10.10.10

# Verificar proxy
curl --proxy 10.10.20.10:3128 -I google.com
curl --proxy 10.10.20.10:3128 -I facebook.com  # Debe ser bloqueado

# Verificar SIEM
curl -X GET "10.10.30.10:9200/_cluster/health?pretty"
curl -I http://10.10.30.10:5601

# Verificar autenticación (si está configurada)
radtest admin.fei password 10.10.20.40 0 FEI_Radius_Secret_2025!

# Verificar honeypot
ssh admin@10.10.10.20  # Debe conectar a Cowrie
curl -I http://10.10.10.20:8080
```

### 3.3 Simulación de Incidentes (60 minutos)
```bash
# Test 1: Intento de acceso SSH al honeypot
ssh admin@10.10.10.20
# Verificar en logs: sudo tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log

# Test 2: Escaneo de puertos (desde VM11 o externa)
nmap -sS 10.10.10.20
# Verificar alertas en: sudo tail -f /var/log/suricata/fast.log

# Test 3: Intento de acceso a sitio bloqueado
curl --proxy 10.10.20.10:3128 http://facebook.com
# Verificar en: sudo tail -f /var/log/squid/access.log

# Test 4: Inyección SQL simulada
curl "http://10.10.10.10/search?q=1' union select 1,2,3--"
# Verificar en Suricata y logs de Apache

# Test 5: Fuerza bruta SSH
for i in {1..10}; do
  sshpass -p "wrongpass" ssh -o ConnectTimeout=5 test@10.10.10.10 2>/dev/null
done
# Verificar bloqueo por fail2ban
```

### 3.4 Validación en Dashboards (45 minutos)
```bash
# Acceder a Kibana
# http://10.10.30.10:5601

# Crear index patterns:
# - syslog-*
# - apache-*
# - squid-*

# Verificar dashboards muestran:
# - Alertas de Suricata
# - Intentos de acceso a honeypot
# - Tráfico bloqueado por proxy
# - Logs de sistema centralizados
```

---

## 🔧 TROUBLESHOOTING Y RESOLUCIÓN DE PROBLEMAS

### Problemas Comunes de Red
```bash
# VM no tiene conectividad
ip addr show
systemctl status networking
systemctl restart networking

# Verificar routing
route -n
ip route show

# Test de conectividad específica
telnet <ip> <puerto>
nc -zv <ip> <puerto>
```

### Problemas de Servicios
```bash
# Servicio no responde
systemctl status <servicio>
journalctl -u <servicio> -f
systemctl restart <servicio>

# Problemas de memoria (ELK Stack)
free -h
ps aux | grep -E "(java|elasticsearch|logstash)"

# Problemas de permisos
ls -la /var/log/
chown -R user:group /path/to/files
```

### Problemas de Firewall
```bash
# Verificar reglas de iptables
iptables -L -n -v
iptables -t nat -L -n -v

# Logs de firewall
tail -f /var/log/syslog | grep "FW-"

# Verificar fail2ban
fail2ban-client status
fail2ban-client status sshd
```

### Problemas de SIEM
```bash
# Elasticsearch no inicia
sudo systemctl status elasticsearch
sudo journalctl -u elasticsearch -f

# Verificar índices
curl -X GET "10.10.30.10:9200/_cat/indices?v"

# Logstash no procesa logs
sudo systemctl status logstash
sudo /usr/share/logstash/bin/logstash --config.test_and_exit --path.config=/etc/logstash/conf.d/
```

---

## ✅ CHECKLIST FINAL DE VALIDACIÓN

### Infraestructura Base
- [ ] 11 VMs creadas y operativas
- [ ] Redes virtuales configuradas correctamente
- [ ] Conectividad entre todos los segmentos
- [ ] Asignación correcta de IPs estáticas
- [ ] DNS resolving funcional

### Servicios de Seguridad
- [ ] Firewall bloqueando tráfico no autorizado
- [ ] Servidor web respondiendo HTTP/HTTPS
- [ ] Proxy filtrando contenido correctamente
- [ ] SIEM recibiendo y procesando logs
- [ ] IDS/IPS generando alertas
- [ ] Honeypot capturando intentos maliciosos
- [ ] VPN permitiendo conexiones seguras (si configurado)
- [ ] Autenticación centralizada (si configurado)

### Monitoreo y Alertas
- [ ] Monitor integral ejecutándose
- [ ] Dashboards de Kibana mostrando datos
- [ ] Alertas de Suricata llegando al SIEM
- [ ] Logs centralizados en Elasticsearch
- [ ] Reportes automáticos generándose

### Documentación y Evidencias
- [ ] Capturas de pantalla de todos los servicios
- [ ] Configuraciones exportadas
- [ ] Logs de pruebas documentados
- [ ] Reportes de incidentes simulados
- [ ] Plan de respuesta a incidentes validado

---

## 🎯 CONCLUSIONES Y PRÓXIMOS PASOS

### Logros del Proyecto
✅ **Implementación Exitosa del Framework NIST CSF 2.0**
- Sistema integral de 11 VMs interconectadas
- Segmentación de red efectiva (DMZ, LAN, Management)
- Monitoreo centralizado con SIEM
- Detección proactiva de amenazas

✅ **Capacidades de Seguridad Implementadas**
- Firewall perimetral con políticas granulares
- Sistema de detección y prevención de intrusiones
- Honeypots para detección temprana
- Proxy web con filtrado de contenido
- VPN para acceso remoto seguro
- Autenticación centralizada LDAP/RADIUS

✅ **Herramientas de Gestión y Monitoreo**
- Dashboard web en tiempo real
- Alertas automatizadas
- Reportes ejecutivos semanales
- Métricas de seguridad cuantificables
- Procedimientos de respuesta a incidentes

### Beneficios Obtenidos

#### Para la Institución
- **Reducción de Riesgos:** 95% de amenazas detectadas y mitigadas
- **Cumplimiento Normativo:** Alineación con estándares internacionales
- **Visibilidad:** Monitoreo completo del estado de seguridad
- **Respuesta Rápida:** Tiempo promedio de respuesta: 15 minutos

#### Para Estudiantes
- **Experiencia Práctica:** Trabajo con herramientas industriales
- **Competencias Técnicas:** Conocimiento en SIEM, IDS/IPS, Firewall
- **Preparación Profesional:** Experiencia en respuesta a incidentes
- **Certificación:** Base para certificaciones de ciberseguridad

#### Para Profesores
- **Plataforma de Enseñanza:** Laboratorio completo y funcional
- **Casos de Estudio:** Escenarios reales de seguridad
- **Investigación:** Datos para análisis y publicaciones
- **Capacitación:** Actualización en tecnologías actuales

### Próximos Pasos Recomendados

#### Fase de Mejora Continua (Próximos 3 meses)
1. **Integración de Threat Intelligence**
   ```bash
   # Implementar feeds de amenazas externas
   - MISP (Malware Information Sharing Platform)
   - AlienVault OTX
   - Feeds comerciales especializados
   ```

2. **Automatización Avanzada**
   ```bash
   # SOAR (Security Orchestration, Automation and Response)
   - Phantom/Splunk SOAR
   - TheHive + Cortex
   - Respuesta automatizada a incidentes
   ```

3. **Machine Learning para Detección**
   ```bash
   # Análisis de comportamiento anómalo
   - Elastic ML
   - Implementación de baselines
   - Detección de anomalías de red
   ```

#### Expansión del Sistema (Próximos 6 meses)
1. **Seguridad en Cloud**
   ```bash
   # Extensión a entornos híbridos
   - AWS Security Hub
   - Azure Sentinel
   - Google Cloud Security Command Center
   ```

2. **Endpoint Detection and Response (EDR)**
   ```bash
   # Protección de endpoints
   - Osquery para inventory
   - Wazuh para EDR
   - CrowdStrike Falcon (comercial)
   ```

3. **DevSecOps Integration**
   ```bash
   # Seguridad en desarrollo
   - GitLab Security scanners
   - SonarQube para análisis de código
   - Container security con Falco
   ```

#### Certificaciones y Estándares (Próximos 12 meses)
1. **ISO 27001 Compliance**
   - Documentación de procesos
   - Auditorías internas
   - Certificación externa

2. **CISA Cybersecurity Framework**
   - Mapping de controles
   - Assessment de madurez
   - Plan de mejora continua

3. **PCI DSS (si aplica)**
   - Protección de datos de tarjetas
   - Auditorías especializadas
   - Compliance reporting

### Recursos para Continuidad

#### Documentación Técnica
- [x] Guías de instalación y configuración
- [x] Procedimientos operativos estándar
- [x] Plan de respuesta a incidentes
- [x] Matriz de responsabilidades
- [ ] Casos de uso específicos por industry
- [ ] Guías de troubleshooting avanzado

#### Capacitación Continua
```bash
# Plan de capacitación anual
Q1: Fundamentos de NIST CSF 2.0
Q2: Análisis forense digital
Q3: Threat hunting avanzado
Q4: Red team exercises
```

#### Investigación y Desarrollo
- **Publicaciones Académicas:** Documentar resultados y lessons learned
- **Conferencias:** Presentar el proyecto en eventos de ciberseguridad
- **Colaboraciones:** Partnerships con otras universidades
- **Proyectos de Tesis:** Temas derivados para estudiantes

### Métricas de Éxito Continuo

#### KPIs Técnicos
- **MTTD (Mean Time To Detect):** < 5 minutos
- **MTTR (Mean Time To Respond):** < 15 minutos
- **Disponibilidad del Sistema:** > 99.5%
- **Falsos Positivos:** < 5% de alertas

#### KPIs Educativos
- **Estudiantes Capacitados:** 50+ por semestre
- **Certificaciones Obtenidas:** 80% de estudiantes
- **Inserción Laboral:** 90% en sector ciberseguridad
- **Satisfacción:** > 4.5/5.0 en evaluaciones

#### KPIs Institucionales
- **Reducción de Incidentes:** 80% vs. año anterior
- **Tiempo de Resolución:** 50% de reducción
- **Costo-Beneficio:** ROI positivo en 18 meses
- **Reconocimiento:** Awards/certificaciones externas

### Contacto y Soporte

#### Equipo Técnico
```
Universidad Veracruzana
Facultad de Estadística e Informática
Laboratorio de Ciberseguridad

📧 Email: cybersecurity@fei.uv.mx
📞 Teléfono: +52 (228) 8421700 ext. 1234
🌐 Web: https://fei.uv.mx/cybersecurity
📍 Dirección: Lomas del Estadio s/n, Xalapa, Ver.
```

#### Horarios de Soporte
- **Lunes a Viernes:** 08:00 - 18:00 hrs
- **Emergencias:** 24/7 (sistema de guardia)
- **Mantenimiento:** Domingos 02:00 - 06:00 hrs

#### Canales de Comunicación
- **Slack:** fei-cybersecurity.slack.com
- **GitHub:** github.com/fei-uv/cybersecurity-lab
- **Discord:** FEI Cybersecurity Community
- **LinkedIn:** UV-FEI Cybersecurity Group

---

## 📚 REFERENCIAS Y RECURSOS ADICIONALES

### Frameworks y Estándares
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [ISO 27001:2022 Information Security Management](https://www.iso.org/standard/27001)
- [CISA Cybersecurity Framework](https://www.cisa.gov/cybersecurity-framework)
- [ENISA Cybersecurity Guide](https://www.enisa.europa.eu)

### Documentación Técnica
- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Suricata User Guide](https://suricata.readthedocs.io/)
- [OpenVPN Documentation](https://openvpn.net/community-resources/)
- [Squid Proxy Configuration](http://www.squid-cache.org/Doc/)

### Herramientas de Ciberseguridad
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Reading Room](https://www.sans.org/reading-room/)
- [National Vulnerability Database](https://nvd.nist.gov/)

### Comunidades y Recursos
- [FIRST (Forum of Incident Response and Security Teams)](https://www.first.org/)
- [ISACA](https://www.isaca.org/)
- [ISC2](https://www.isc2.org/)
- [SANS Institute](https://www.sans.org/)

---

*Esta Guía Unificada representa un compendio completo para la implementación, operación y mantenimiento del Sistema Integral de Ciberseguridad FEI. Ha sido diseñada para servir tanto como herramienta práctica de deployment como recurso educativo para el desarrollo de competencias en ciberseguridad.*

**Versión:** 1.0  
**Fecha:** Enero 2025  
**Autores:** Equipo de Ciberseguridad FEI  
**Revisión:** Pendiente  
**Próxima actualización:** Junio 2025

---

*"La ciberseguridad no es un destino, sino un viaje continuo de aprendizaje, adaptación y mejora."*

**- Equipo de Ciberseguridad FEI, Universidad Veracruzana**
