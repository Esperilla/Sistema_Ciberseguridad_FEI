#!/bin/bash

##############################################################################
# Script de Configuración Honeypot - Sistema Ciberseguridad FEI
# 
# Descripción: Instalación y configuración de Cowrie y Dionaea como honeypots
#              para detección temprana de ataques
# 
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Versión: 1.0
# Sistema: Debian 12 (VM4 - 10.10.10.20)
##############################################################################

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuración
COWRIE_USER="cowrie"
COWRIE_HOME="/home/cowrie"
COWRIE_DIR="$COWRIE_HOME/cowrie"
DIONAEA_DIR="/opt/dionaea"
HONEYPOT_IP="10.10.10.20"
SSH_HONEYPOT_PORT="2222"
TELNET_HONEYPOT_PORT="2323"
HTTP_HONEYPOT_PORT="8080"

# Función para logging
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/honeypot-install.log
}

error_message() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/honeypot-install.log
}

warning_message() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/honeypot-install.log
}

# Verificar privilegios de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_message "Este script debe ejecutarse como root"
        exit 1
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
        git \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-setuptools \
        build-essential \
        libssl-dev \
        libffi-dev \
        libmysqlclient-dev \
        libsqlite3-dev \
        libevent-dev \
        libglib2.0-dev \
        libsqlite3-0 \
        sqlite3 \
        pkg-config \
        autotools-dev \
        automake \
        autoconf \
        libtool \
        cython3 \
        libev-dev \
        libgeoip-dev \
        libudns-dev \
        libcap-dev \
        libcurl4-openssl-dev \
        libemu-dev \
        libpcap-dev \
        liblcfg-dev \
        libgcrypt20-dev \
        libreadline-dev \
        libnl-3-dev \
        curl \
        wget \
        unzip \
        rsyslog \
        logrotate \
        iptables \
        net-tools \
        tcpdump
        
    if [ $? -eq 0 ]; then
        log_message "Dependencias instaladas correctamente"
    else
        error_message "Error al instalar dependencias"
        exit 1
    fi
}

# Crear usuario para Cowrie
create_cowrie_user() {
    log_message "Creando usuario para Cowrie..."
    
    if ! id "$COWRIE_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$COWRIE_USER"
        log_message "Usuario $COWRIE_USER creado"
    else
        log_message "Usuario $COWRIE_USER ya existe"
    fi
}

# Instalar y configurar Cowrie SSH/Telnet Honeypot
install_cowrie() {
    log_message "Instalando Cowrie SSH/Telnet Honeypot..."
    
    # Cambiar al usuario cowrie
    sudo -u "$COWRIE_USER" bash << 'EOF'
cd /home/cowrie

# Clonar repositorio de Cowrie
git clone https://github.com/cowrie/cowrie.git

cd cowrie

# Crear entorno virtual
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Actualizar pip
pip install --upgrade pip

# Instalar dependencias de Cowrie
pip install -r requirements.txt

# Instalar dependencias adicionales
pip install mysql-connector-python
pip install geoip2
pip install requests
EOF

    if [ $? -eq 0 ]; then
        log_message "Cowrie instalado correctamente"
    else
        error_message "Error al instalar Cowrie"
        exit 1
    fi
}

# Configurar Cowrie
configure_cowrie() {
    log_message "Configurando Cowrie..."
    
    # Crear configuración personalizada
    sudo -u "$COWRIE_USER" bash << EOF
cd $COWRIE_DIR

# Copiar configuración de ejemplo
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Crear configuración personalizada
cat > etc/cowrie.cfg << 'COWRIE_CFG'
# Configuración Cowrie Honeypot - Sistema Ciberseguridad FEI

[honeypot]
# Hostname del honeypot
hostname = servidor-fei
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
share_path = share/cowrie
state_path = var/lib/cowrie
etc_path = honeyfs
contents_path = honeyfs
txtcmds_path = txtcmds
ttylog_path = var/lib/cowrie/tty
download_limit_size = 10485760

[ssh]
# Puerto SSH (cambiar por redirección)
listen_endpoints = tcp:$SSH_HONEYPOT_PORT:interface=0.0.0.0

# Versión SSH falsa
version = SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1

# Configuración de autenticación
auth_class = HoneyPotAuth
auth_class_parameters = etc/userdb.txt

# Banner SSH
ssh_banner = Servidor Academico FEI - Acceso Autorizado Solamente

[telnet]
# Puerto Telnet
listen_endpoints = tcp:$TELNET_HONEYPOT_PORT:interface=0.0.0.0
reported_procs = 

[shell]
# Configuración del shell falso
filesystem = share/cowrie/fs.pickle
processes = share/cowrie/cmdoutput.json

# Comandos del sistema
arch = linux-x86_64-lsb

[output_elasticsearch]
# Integración con Elasticsearch
enabled = false

[output_graylog]
# Integración con Graylog
enabled = false

[output_splunk]
# Integración con Splunk
enabled = false

[output_json]
# Salida JSON para SIEM
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_mysql]
# Base de datos MySQL
enabled = false

[output_sqlite3]
# Base de datos SQLite
enabled = true
db_file = var/lib/cowrie/cowrie.db

[output_textlog]
# Logs de texto
enabled = true
logfile = var/log/cowrie/cowrie.log

[output_syslog]
# Syslog para integración
enabled = true
facility = daemon
format = Cowrie [%(session)s]: %(message)s

[output_localsyslog]
# Syslog local
enabled = true
facility = daemon

[backend_pool]
# Pool de backends
pool_only = false
pool_max_vms = 5
pool_vm_unused_timeout = 600

[proxy]
# Configuración de proxy
enabled = false

[backend_proxy]
# Backend proxy
enabled = false

COWRIE_CFG

# Crear base de datos de usuarios falsos
cat > etc/userdb.txt << 'USERDB'
# Base de usuarios falsos para Cowrie - FEI
# formato: usuario:contraseña:uid:gid
root:123456:0:0
admin:admin:0:0
administrador:password:0:0
fei:fei123:1000:1000
usuario:123456:1001:1001
test:test:1002:1002
guest:guest:1003:1003
mysql:mysql:1004:1004
postgres:postgres:1005:1005
apache:apache:1006:1006
www-data:www123:1007:1007
student:student:1008:1008
profesor:profesor:1009:1009
oracle:oracle:1010:1010
samba:samba:1011:1011
USERDB

EOF

    # Crear directorios necesarios
    sudo -u "$COWRIE_USER" mkdir -p "$COWRIE_DIR/var/log/cowrie"
    sudo -u "$COWRIE_USER" mkdir -p "$COWRIE_DIR/var/lib/cowrie"
    sudo -u "$COWRIE_USER" mkdir -p "$COWRIE_DIR/var/lib/cowrie/downloads"
    sudo -u "$COWRIE_USER" mkdir -p "$COWRIE_DIR/var/lib/cowrie/tty"
    
    log_message "Cowrie configurado correctamente"
}

# Instalar Dionaea (Multi-protocol Honeypot)
install_dionaea() {
    log_message "Instalando Dionaea Multi-protocol Honeypot..."
    
    # Clonar y compilar Dionaea
    cd /tmp
    git clone https://github.com/DinoTools/dionaea.git
    cd dionaea
    
    # Crear directorio de instalación
    mkdir -p "$DIONAEA_DIR"
    
    # Configurar y compilar
    autoreconf -fi
    ./configure --prefix="$DIONAEA_DIR" \
                --disable-werror \
                --enable-ev \
                --enable-nl \
                --enable-python
    
    make && make install
    
    if [ $? -eq 0 ]; then
        log_message "Dionaea compilado e instalado correctamente"
    else
        warning_message "Error al compilar Dionaea, continuando sin él"
        return 1
    fi
}

# Configurar Dionaea
configure_dionaea() {
    log_message "Configurando Dionaea..."
    
    if [ ! -d "$DIONAEA_DIR" ]; then
        warning_message "Dionaea no está instalado, omitiendo configuración"
        return 1
    fi
    
    # Crear configuración personalizada
    mkdir -p "$DIONAEA_DIR/etc/dionaea"
    
    cat > "$DIONAEA_DIR/etc/dionaea/dionaea.cfg" << 'EOF'
[dionaea]
download.dir = /opt/dionaea/var/lib/dionaea/binaries/
modules.dir = /opt/dionaea/lib/dionaea/
processors.dir = /opt/dionaea/lib/dionaea/processors/
services.dir = /opt/dionaea/lib/dionaea/services/
ssl.default.c = MX
ssl.default.cn = servidor-fei.uv.mx
ssl.default.o = Universidad Veracruzana
ssl.default.ou = FEI

[logging]
default.filename = /opt/dionaea/var/log/dionaea/dionaea.log
default.levels = all
default.domains = *

[processors]
file_logger = 
text_logger = 
json_logger = 

[ihandlers]
store = 
uniquedownload = 
submitamavis = 
submitclamav = 
submitjoesandbox = 
submitvirtustotal = 
logxmpp = 
logsql = 
logdownloadurl = 
logjson = 
logpgsql = 

[services]
serve-http = yes
serve-https = yes
serve-ftp = yes
serve-tftp = yes
serve-smb = yes
serve-mysql = yes
serve-mssql = yes
EOF

    # Crear usuario dionaea
    useradd -r -s /bin/false dionaea
    chown -R dionaea:dionaea "$DIONAEA_DIR"
    
    log_message "Dionaea configurado correctamente"
}

# Configurar servicios systemd
configure_services() {
    log_message "Configurando servicios systemd..."
    
    # Servicio para Cowrie
    cat > "/etc/systemd/system/cowrie.service" << EOF
[Unit]
Description=Cowrie SSH/Telnet Honeypot FEI
After=network.target

[Service]
Type=forking
User=$COWRIE_USER
Group=$COWRIE_USER
WorkingDirectory=$COWRIE_DIR
ExecStart=$COWRIE_DIR/bin/cowrie start
ExecStop=$COWRIE_DIR/bin/cowrie stop
PIDFile=$COWRIE_DIR/var/run/cowrie.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Servicio para Dionaea (si está instalado)
    if [ -d "$DIONAEA_DIR" ]; then
        cat > "/etc/systemd/system/dionaea.service" << EOF
[Unit]
Description=Dionaea Multi-protocol Honeypot FEI
After=network.target

[Service]
Type=simple
User=dionaea
Group=dionaea
WorkingDirectory=$DIONAEA_DIR
ExecStart=$DIONAEA_DIR/bin/dionaea -u dionaea -g dionaea -c $DIONAEA_DIR/etc/dionaea/dionaea.cfg
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        systemctl enable dionaea
    fi
    
    # Habilitar servicios
    systemctl daemon-reload
    systemctl enable cowrie
    
    log_message "Servicios systemd configurados"
}

# Configurar redirección de puertos
configure_port_redirection() {
    log_message "Configurando redirección de puertos..."
    
    # Redirigir tráfico SSH del puerto 22 al 2222 (Cowrie)
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port $SSH_HONEYPOT_PORT
    
    # Redirigir tráfico Telnet del puerto 23 al 2323 (Cowrie)
    iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port $TELNET_HONEYPOT_PORT
    
    # Permitir tráfico a los puertos de honeypot
    iptables -A INPUT -p tcp --dport $SSH_HONEYPOT_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $TELNET_HONEYPOT_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $HTTP_HONEYPOT_PORT -j ACCEPT
    
    # Guardar reglas
    iptables-save > /etc/iptables/rules.v4
    
    log_message "Redirección de puertos configurada"
}

# Configurar logging avanzado
configure_logging() {
    log_message "Configurando sistema de logging..."
    
    # Configurar rsyslog para honeypots
    cat > "/etc/rsyslog.d/49-honeypot.conf" << 'EOF'
# Configuración rsyslog para Honeypots - FEI

# Cowrie logs
if $programname == 'cowrie' then {
    /var/log/honeypot/cowrie.log
    @@10.10.30.10:514
    stop
}

# Dionaea logs
if $programname == 'dionaea' then {
    /var/log/honeypot/dionaea.log
    @@10.10.30.10:514
    stop
}

# Honeypot general
:programname,isequal,"honeypot" /var/log/honeypot/general.log
EOF

    # Crear directorio de logs
    mkdir -p /var/log/honeypot
    chown syslog:adm /var/log/honeypot
    
    # Reiniciar rsyslog
    systemctl restart rsyslog
    
    log_message "Sistema de logging configurado"
}

# Configurar logrotate
configure_logrotate() {
    log_message "Configurando rotación de logs..."
    
    cat > "/etc/logrotate.d/honeypot-fei" << 'EOF'
/var/log/honeypot/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 syslog adm
    postrotate
        systemctl reload rsyslog
    endscript
}

/home/cowrie/cowrie/var/log/cowrie/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 cowrie cowrie
    postrotate
        systemctl restart cowrie
    endscript
}
EOF

    log_message "Rotación de logs configurada"
}

# Crear scripts de monitoreo
create_monitoring_scripts() {
    log_message "Creando scripts de monitoreo..."
    
    # Script de monitoreo en tiempo real
    cat > "/usr/local/bin/honeypot-monitor.sh" << 'EOF'
#!/bin/bash
# Monitor en tiempo real para Honeypots - FEI

echo "=== Monitor Honeypots - Sistema Ciberseguridad FEI ==="
echo "Presiona Ctrl+C para salir"
echo ""

while true; do
    clear
    echo "=== Estado de Servicios ==="
    echo "Cowrie SSH/Telnet Honeypot:"
    systemctl is-active cowrie && echo "  ✓ Activo" || echo "  ✗ Inactivo"
    
    if systemctl is-enabled dionaea >/dev/null 2>&1; then
        echo "Dionaea Multi-protocol Honeypot:"
        systemctl is-active dionaea && echo "  ✓ Activo" || echo "  ✗ Inactivo"
    fi
    
    echo ""
    echo "=== Conexiones en Tiempo Real ==="
    echo "Puerto SSH (22 -> 2222):"
    netstat -nt | grep ":2222 " | wc -l | xargs echo "  Conexiones activas:"
    
    echo "Puerto Telnet (23 -> 2323):"
    netstat -nt | grep ":2323 " | wc -l | xargs echo "  Conexiones activas:"
    
    echo ""
    echo "=== Últimos Intentos de Acceso ==="
    if [ -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log ]; then
        echo "Cowrie (últimos 5):"
        tail -5 /home/cowrie/cowrie/var/log/cowrie/cowrie.log | grep "login attempt" | cut -d' ' -f1-3,6-
    else
        echo "No hay logs de Cowrie disponibles"
    fi
    
    echo ""
    echo "=== Estadísticas de Red ==="
    echo "Tráfico en interfaces:"
    ip -s link show | grep -E "(eth0|ens|enp)" -A1 | grep -E "RX:|TX:" | head -2
    
    echo ""
    echo "Actualizado: $(date)"
    sleep 10
done
EOF

    chmod +x /usr/local/bin/honeypot-monitor.sh
    
    # Script de análisis de ataques
    cat > "/usr/local/bin/honeypot-analysis.sh" << 'EOF'
#!/bin/bash
# Análisis de ataques detectados por Honeypots

LOG_DIR="/home/cowrie/cowrie/var/log/cowrie"
REPORT_FILE="/tmp/honeypot-report-$(date +%Y%m%d_%H%M%S).txt"

echo "=== Reporte de Análisis Honeypots - FEI ===" > $REPORT_FILE
echo "Generado: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== Resumen de Intentos de Login ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/cowrie.log" ]; then
    grep "login attempt" "$LOG_DIR/cowrie.log" | awk '{print $6}' | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE
else
    echo "No hay datos de login disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Top 10 IPs Atacantes ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/cowrie.log" ]; then
    grep "login attempt" "$LOG_DIR/cowrie.log" | awk '{print $4}' | cut -d',' -f1 | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE
else
    echo "No hay datos de IPs disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Credenciales Más Intentadas ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/cowrie.log" ]; then
    grep "login attempt" "$LOG_DIR/cowrie.log" | grep -o "u'[^']*'" | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE
else
    echo "No hay datos de credenciales disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Comandos Ejecutados ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/cowrie.log" ]; then
    grep "CMD:" "$LOG_DIR/cowrie.log" | awk -F'CMD: ' '{print $2}' | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE
else
    echo "No hay datos de comandos disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Archivos Descargados ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/cowrie.log" ]; then
    grep "download" "$LOG_DIR/cowrie.log" | grep -o "http[s]*://[^']*" | sort | uniq >> $REPORT_FILE
else
    echo "No hay datos de descargas disponibles" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== Actividad por Horas ===" >> $REPORT_FILE
if [ -f "$LOG_DIR/cowrie.log" ]; then
    grep "$(date '+%Y-%m-%d')" "$LOG_DIR/cowrie.log" | awk '{print $2}' | cut -d':' -f1 | sort | uniq -c >> $REPORT_FILE
else
    echo "No hay datos de actividad por horas" >> $REPORT_FILE
fi

echo "Reporte generado en: $REPORT_FILE"
cat $REPORT_FILE
EOF

    chmod +x /usr/local/bin/honeypot-analysis.sh
    
    # Script de limpieza de logs
    cat > "/usr/local/bin/honeypot-cleanup.sh" << 'EOF'
#!/bin/bash
# Limpieza de logs antiguos de honeypots

# Limpiar logs de Cowrie más antiguos de 30 días
find /home/cowrie/cowrie/var/log/cowrie/ -name "*.log" -mtime +30 -delete

# Limpiar descargas más antiguas de 7 días
find /home/cowrie/cowrie/var/lib/cowrie/downloads/ -type f -mtime +7 -delete

# Limpiar TTY logs más antiguos de 15 días
find /home/cowrie/cowrie/var/lib/cowrie/tty/ -name "*.log" -mtime +15 -delete

echo "Limpieza de honeypots completada: $(date)"
EOF

    chmod +x /usr/local/bin/honeypot-cleanup.sh
    
    # Agregar tarea cron para limpieza automática
    cat > "/etc/cron.d/honeypot-cleanup" << 'EOF'
# Limpieza automática de logs de honeypots - FEI
0 2 * * * root /usr/local/bin/honeypot-cleanup.sh >/dev/null 2>&1
EOF

    log_message "Scripts de monitoreo creados"
}

# Crear honeypot web simple
create_web_honeypot() {
    log_message "Creando honeypot web simple..."
    
    # Instalar y configurar nginx como honeypot web
    apt install -y nginx php-fpm
    
    # Crear sitio honeypot
    cat > "/var/www/html/index.php" << 'EOF'
<?php
// Honeypot Web Simple - FEI
$ip = $_SERVER['REMOTE_ADDR'];
$timestamp = date('Y-m-d H:i:s');
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$request_uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

// Log del acceso
$log_entry = "$timestamp - IP: $ip - Method: $method - URI: $request_uri - UA: $user_agent\n";
file_put_contents('/var/log/honeypot/web.log', $log_entry, FILE_APPEND | LOCK_EX);

// Simular login administrativo
if (isset($_POST['username']) && isset($_POST['password'])) {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    $log_entry = "$timestamp - IP: $ip - LOGIN ATTEMPT - User: $user - Pass: $pass\n";
    file_put_contents('/var/log/honeypot/web-login.log', $log_entry, FILE_APPEND | LOCK_EX);
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Panel Administrativo - Sistema FEI</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .login-form { max-width: 400px; margin: 0 auto; border: 1px solid #ccc; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>Sistema Administrativo FEI</h2>
        <p>Acceso restringido a personal autorizado</p>
        <form method="post">
            <input type="text" name="username" placeholder="Usuario" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Ingresar</button>
        </form>
        <?php if(isset($_POST['username'])): ?>
        <p style="color: red;">Credenciales incorrectas. Intento registrado.</p>
        <?php endif; ?>
    </div>
</body>
</html>
EOF

    # Configurar nginx para honeypot
    cat > "/etc/nginx/sites-available/honeypot" << EOF
server {
    listen $HTTP_HONEYPOT_PORT;
    server_name _;
    root /var/www/html;
    index index.php index.html;
    
    access_log /var/log/honeypot/nginx-access.log;
    error_log /var/log/honeypot/nginx-error.log;
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }
    
    # Páginas de honeypot adicionales
    location /admin { try_files \$uri /index.php; }
    location /login { try_files \$uri /index.php; }
    location /panel { try_files \$uri /index.php; }
    location /phpmyadmin { try_files \$uri /index.php; }
}
EOF

    ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    systemctl restart nginx
    systemctl restart php8.2-fpm
    
    log_message "Honeypot web configurado en puerto $HTTP_HONEYPOT_PORT"
}

# Función de verificación final
verify_installation() {
    log_message "Verificando instalación..."
    
    # Verificar Cowrie
    if systemctl is-active --quiet cowrie; then
        log_message "✓ Cowrie SSH/Telnet Honeypot activo"
    else
        error_message "✗ Cowrie no está activo"
    fi
    
    # Verificar puertos
    if netstat -tlnp | grep -q ":$SSH_HONEYPOT_PORT "; then
        log_message "✓ Puerto SSH honeypot ($SSH_HONEYPOT_PORT) en escucha"
    else
        warning_message "✗ Puerto SSH honeypot no disponible"
    fi
    
    if netstat -tlnp | grep -q ":$TELNET_HONEYPOT_PORT "; then
        log_message "✓ Puerto Telnet honeypot ($TELNET_HONEYPOT_PORT) en escucha"
    else
        warning_message "✗ Puerto Telnet honeypot no disponible"
    fi
    
    if netstat -tlnp | grep -q ":$HTTP_HONEYPOT_PORT "; then
        log_message "✓ Puerto HTTP honeypot ($HTTP_HONEYPOT_PORT) en escucha"
    else
        warning_message "✗ Puerto HTTP honeypot no disponible"
    fi
    
    # Verificar logs
    if [ -d "/var/log/honeypot" ]; then
        log_message "✓ Directorio de logs creado"
    else
        error_message "✗ Directorio de logs no encontrado"
    fi
    
    # Verificar redirección de puertos
    if iptables -t nat -L PREROUTING | grep -q "tcp dpt:22.*redir ports $SSH_HONEYPOT_PORT"; then
        log_message "✓ Redirección SSH configurada"
    else
        warning_message "✗ Redirección SSH no configurada"
    fi
    
    # Mostrar resumen
    echo ""
    echo -e "${BLUE}=== RESUMEN DE INSTALACIÓN ===${NC}"
    echo "Honeypots configurados:"
    echo "  - Cowrie SSH/Telnet: Puerto $SSH_HONEYPOT_PORT (SSH), $TELNET_HONEYPOT_PORT (Telnet)"
    echo "  - Web Honeypot: Puerto $HTTP_HONEYPOT_PORT"
    if [ -d "$DIONAEA_DIR" ]; then
        echo "  - Dionaea Multi-protocol: Múltiples puertos"
    fi
    echo ""
    echo "Direcciones de honeypot:"
    echo "  SSH: $HONEYPOT_IP:22 -> :$SSH_HONEYPOT_PORT"
    echo "  Telnet: $HONEYPOT_IP:23 -> :$TELNET_HONEYPOT_PORT"
    echo "  Web: http://$HONEYPOT_IP:$HTTP_HONEYPOT_PORT"
    echo ""
    echo -e "${GREEN}Comandos útiles:${NC}"
    echo "  Monitor en tiempo real: /usr/local/bin/honeypot-monitor.sh"
    echo "  Análisis de ataques: /usr/local/bin/honeypot-analysis.sh"
    echo "  Estado servicios: systemctl status cowrie"
    echo "  Logs en tiempo real: tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log"
    echo "  Logs web: tail -f /var/log/honeypot/web-login.log"
}

# Función principal
main() {
    echo -e "${BLUE}"
    echo "############################################################################"
    echo "#                      Configuración Honeypots - FEI                      #"
    echo "#                     Sistema Integral de Ciberseguridad                  #"
    echo "############################################################################"
    echo -e "${NC}"
    
    # Verificaciones previas
    check_root
    
    # Proceso de instalación
    log_message "Iniciando configuración de honeypots..."
    
    update_system
    install_dependencies
    create_cowrie_user
    install_cowrie
    configure_cowrie
    install_dionaea
    configure_dionaea
    configure_services
    configure_port_redirection
    configure_logging
    configure_logrotate
    create_monitoring_scripts
    create_web_honeypot
    
    # Iniciar servicios
    log_message "Iniciando servicios..."
    systemctl restart cowrie
    if systemctl is-enabled dionaea >/dev/null 2>&1; then
        systemctl restart dionaea
    fi
    
    # Verificación final
    verify_installation
    
    echo ""
    echo -e "${GREEN}¡Configuración de honeypots completada exitosamente!${NC}"
    echo ""
    echo -e "${YELLOW}Próximos pasos:${NC}"
    echo "1. Monitorear actividad: /usr/local/bin/honeypot-monitor.sh"
    echo "2. Analizar ataques detectados: /usr/local/bin/honeypot-analysis.sh"
    echo "3. Verificar integración con SIEM"
    echo "4. Probar conectividad desde redes externas"
    echo ""
    echo -e "${YELLOW}IMPORTANTE:${NC}"
    echo "Los honeypots están capturando intentos de acceso maliciosos."
    echo "Revisa regularmente los logs para detectar nuevas amenazas."
    echo ""
    
    log_message "Configuración de honeypots completada"
}

# Ejecutar función principal
main "$@"
