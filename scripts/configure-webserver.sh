#!/bin/bash

# Script de configuración automatizada para Servidor Web FEI

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

# Función para logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARN $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO $(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Verificar si se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

log "Iniciando configuración del Servidor Web FEI..."

# Variables de configuración
DOMAIN_NAME="fei.local"
ADMIN_EMAIL="admin@fei.loDOMAINcal"
WEB_ROOT="/var/www/html"
ROOT_PASS=$(openssl rand -base64 32)
DB_NAME="fei_db"
DB_USER="fei_user"
DB_PASS=$(openssl rand -base64 32)

# Actualizar sistema
log "Actualizando sistema..."
apt update && apt upgrade -y

# Instalar LAMP Stack y herramientas de seguridad
log "Instalando LAMP Stack y herramientas de seguridad..."
apt install -y apache2 mariadb-server php php-mysql php-cli php-curl \
    php-gd php-mbstring php-xml php-zip libapache2-mod-php \
    fail2ban ufw certbot python3-certbot-apache \
    rkhunter chkrootkit \
    logwatch rsyslog unattended-upgrades

# Configurar red estática
log "Configurando interfaz de red..."
cat > /etc/network/interfaces << 'EOF'
# Configuración de red para Servidor Web FEI

auto lo
iface lo inet loopback

# Interfaz DMZ
auto ens36
iface ens36 inet static
    address 10.10.10.10
    netmask 255.255.255.0
    gateway 10.10.10.1
    dns-nameservers 8.8.8.8 8.8.4.4
EOF

# Configurar hostname
echo "web-fei" > /etc/hostname
echo "127.0.0.1 web-fei web-fei.fei.local" >> /etc/hosts

# Configurar MariaDB
log "Configurando MariaDB..."
systemctl start mariadb
systemctl enable mariadb

# Configuración segura de MySQL
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$ROOT_PASS'; FLUSH PRIVILEGES;"
mysql -u root -p$ROOT_PASS -e "DROP DATABASE IF EXISTS test"
mysql -u root -p$ROOT_PASS -e "DELETE FROM mysql.user WHERE User=''"
mysql -u root -p$ROOT_PASS -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -u root -p$ROOT_PASS -e "FLUSH PRIVILEGES"

# Crear base de datos y usuario para la aplicación
mysql -u root -p$ROOT_PASS -e "CREATE DATABASE $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
mysql -u root -p$ROOT_PASS -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS'"
mysql -u root -p$ROOT_PASS -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost'"
mysql -u root -p$ROOT_PASS -e "FLUSH PRIVILEGES"

# Guardar credenciales de BD
cat > /root/.db_credentials << EOF
RootPassword: $ROOT_PASS
Database: $DB_NAME
Username: $DB_USER
Password: $DB_PASS
EOF
chmod 600 /root/.db_credentials

# Configurar Apache - Hardening de seguridad
log "Configurando Apache con medidas de seguridad..."

# Configuración principal de seguridad
cat > /etc/apache2/conf-available/security-fei.conf << 'EOF'
# Configuración de seguridad para Apache FEI

# Ocultar información del servidor
ServerTokens Prod
ServerSignature Off

# Headers de seguridad
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Ocultar archivos sensibles
<FilesMatch "\.(htaccess|htpasswd|ini|log|sh|inc|bak)$">
    Require all denied
</FilesMatch>

# Prevenir acceso a directorios
<Directory />
    Options -Indexes
    AllowOverride None
</Directory>

# Prevenir ejecución de PHP en uploads
<Directory "/var/www/html/uploads">
    php_flag engine off
    Options -ExecCGI
    AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
</Directory>

# Limitar tamaño de request
LimitRequestBody 10485760

# Timeout de conexión
Timeout 60
KeepAliveTimeout 5

# Prevenir ataques de slowloris
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
EOF

# Habilitar configuración de seguridad y módulos necesarios
a2enmod headers
a2enmod rewrite
a2enmod ssl
a2enconf security-fei

# Crear sitio web principal
log "Creando sitio web principal..."
cat > /etc/apache2/sites-available/fei-web.conf << EOF
<VirtualHost *:80>
    ServerName $DOMAIN_NAME
    ServerAlias www.$DOMAIN_NAME
    DocumentRoot $WEB_ROOT
    ErrorLog \${APACHE_LOG_DIR}/fei_error.log
    CustomLog \${APACHE_LOG_DIR}/fei_access.log combined
    
    # Redireccionar a HTTPS
    Redirect permanent / https://$DOMAIN_NAME/
</VirtualHost>

<VirtualHost *:443>
    ServerName $DOMAIN_NAME
    ServerAlias www.$DOMAIN_NAME
    DocumentRoot $WEB_ROOT
    
    # SSL Configuration (se configurará con certbot)
    #SSLEngine on
    
    # Logging
    ErrorLog \${APACHE_LOG_DIR}/fei_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/fei_ssl_access.log combined
    
    # PHP Security
    php_admin_value open_basedir "$WEB_ROOT:/tmp:/var/tmp"
    php_admin_flag allow_url_fopen off
    php_admin_flag allow_url_include off
    
    <Directory "$WEB_ROOT">
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Deshabilitar sitio por defecto y habilitar nuestro sitio
a2dissite 000-default
a2ensite fei-web

# Crear página web de prueba
log "Creando página web de demostración..."
mkdir -p $WEB_ROOT/uploads $WEB_ROOT/admin $WEB_ROOT/assets/css $WEB_ROOT/assets/js

cat > $WEB_ROOT/index.php << 'EOF'
<?php
// Portal Web FEI - Página Principal
session_start();

// Configuración de seguridad para headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

$page_title = "Portal FEI - Facultad de Estadística e Informática";
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <header>
        <nav class="navbar">
            <div class="nav-container">
                <h1>Portal FEI</h1>
                <ul class="nav-menu">
                    <li><a href="#home">Inicio</a></li>
                    <li><a href="#servicios">Servicios</a></li>
                    <li><a href="#contacto">Contacto</a></li>
                    <li><a href="admin/">Admin</a></li>
                </ul>
            </div>
        </nav>
    </header>

    <main>
        <section id="home" class="hero">
            <h2>Bienvenido al Portal de la Facultad de Estadística e Informática</h2>
            <p>Sistema de información académica y servicios estudiantiles</p>
            <div class="stats">
                <div class="stat-item">
                    <h3>Servidor Web</h3>
                    <p>Estado: <span class="status-active">Activo</span></p>
                    <p>IP: <?php echo $_SERVER['SERVER_ADDR']; ?></p>
                    <p>Fecha: <?php echo date('Y-m-d H:i:s'); ?></p>
                </div>
            </div>
        </section>

        <section id="servicios" class="services">
            <h2>Servicios Disponibles</h2>
            <div class="service-grid">
                <div class="service-card">
                    <h3>Sistema Académico</h3>
                    <p>Consulta de calificaciones, horarios y expediente</p>
                </div>
                <div class="service-card">
                    <h3>Biblioteca Digital</h3>
                    <p>Recursos académicos y material de estudio</p>
                </div>
                <div class="service-card">
                    <h3>Portal de Estudiantes</h3>
                    <p>Servicios exclusivos para la comunidad estudiantil</p>
                </div>
            </div>
        </section>
    </main>

    <footer>
        <p>&copy; 2025 Facultad de Estadística e Informática - Universidad Veracruzana</p>
        <p>Sistema protegido por medidas de ciberseguridad</p>
    </footer>

    <script src="assets/js/main.js"></script>
</body>
</html>
EOF

# Crear archivo CSS
cat > $WEB_ROOT/assets/css/style.css << 'EOF'
/* Estilos para Portal FEI */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Arial', sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f4f4f4;
}

.navbar {
    background: #2c3e50;
    color: white;
    padding: 1rem 0;
    position: fixed;
    width: 100%;
    top: 0;
    z-index: 1000;
}

.nav-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-menu {
    display: flex;
    list-style: none;
}

.nav-menu li {
    margin-left: 2rem;
}

.nav-menu a {
    color: white;
    text-decoration: none;
    transition: color 0.3s;
}

.nav-menu a:hover {
    color: #3498db;
}

main {
    margin-top: 80px;
    padding: 2rem 0;
}

.hero {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    text-align: center;
    padding: 4rem 2rem;
}

.hero h2 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
}

.stats {
    display: flex;
    justify-content: center;
    margin-top: 2rem;
}

.stat-item {
    background: rgba(255,255,255,0.1);
    padding: 1.5rem;
    border-radius: 10px;
    margin: 0 1rem;
}

.status-active {
    color: #2ecc71;
    font-weight: bold;
}

.services {
    max-width: 1200px;
    margin: 4rem auto;
    padding: 0 2rem;
    text-align: center;
}

.service-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin-top: 2rem;
}

.service-card {
    background: white;
    padding: 2rem;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    transition: transform 0.3s;
}

.service-card:hover {
    transform: translateY(-5px);
}

footer {
    background: #2c3e50;
    color: white;
    text-align: center;
    padding: 2rem;
    margin-top: 4rem;
}
EOF

# Crear archivo JavaScript
cat > $WEB_ROOT/assets/js/main.js << 'EOF'
// JavaScript para Portal FEI
document.addEventListener('DOMContentLoaded', function() {
    // Función para mostrar la hora actual
    function updateTime() {
        const now = new Date();
        const timeString = now.toLocaleString('es-MX', {
            timeZone: 'America/Mexico_City'
        });
        
        const timeElements = document.querySelectorAll('.current-time');
        timeElements.forEach(element => {
            element.textContent = timeString;
        });
    }

    // Actualizar tiempo cada segundo
    setInterval(updateTime, 1000);
    updateTime();

    // Smooth scrolling para enlaces internos
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Log de acceso (para demostración)
    console.log('Portal FEI cargado correctamente');
    console.log('Timestamp:', new Date().toISOString());
});
EOF

# Crear página de administración básica
cat > $WEB_ROOT/admin/index.php << 'EOF'
<?php
// Página de administración básica
session_start();

// Headers de seguridad
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Función básica de autenticación (para demostración)
if (!isset($_SESSION['authenticated'])) {
    if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin123') {
        $_SESSION['authenticated'] = true;
    } else if ($_POST) {
        $error = "Credenciales incorrectas";
    }
}

if (!isset($_SESSION['authenticated'])) {
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login - Admin FEI</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .login-container { width: 300px; margin: 100px auto; background: white; padding: 20px; border-radius: 5px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #2c3e50; color: white; border: none; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Acceso Administrativo</h2>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="POST">
            <input type="text" name="username" placeholder="Usuario" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Ingresar</button>
        </form>
        <p><small>Demo: admin/admin123</small></p>
    </div>
</body>
</html>
<?php
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Panel Admin - FEI</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f4f4f4; }
        .header { background: #2c3e50; color: white; padding: 15px; }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .card { background: white; padding: 20px; margin: 15px 0; border-radius: 5px; }
        .status-ok { color: green; } .status-warn { color: orange; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Panel de Administración FEI</h1>
        <a href="?logout=1" style="color: white; float: right;">Cerrar Sesión</a>
    </div>

    <div class="container">
        <div class="card">
            <h2>Estado del Servidor</h2>
            <table>
                <tr><td>Servidor Web</td><td class="status-ok">Activo</td></tr>
                <tr><td>Base de Datos</td><td class="status-ok">Conectada</td></tr>
                <tr><td>Espacio en Disco</td><td><?php echo disk_free_space('/') / 1024 / 1024 / 1024; ?> GB libres</td></tr>
                <tr><td>Memoria RAM</td><td><?php echo round(memory_get_usage() / 1024 / 1024, 2); ?> MB en uso</td></tr>
                <tr><td>Uptime</td><td><?php echo shell_exec('uptime'); ?></td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Información del Sistema</h2>
            <table>
                <tr><td>IP del Servidor</td><td><?php echo $_SERVER['SERVER_ADDR']; ?></td></tr>
                <tr><td>Versión PHP</td><td><?php echo PHP_VERSION; ?></td></tr>
                <tr><td>Sistema Operativo</td><td><?php echo php_uname(); ?></td></tr>
                <tr><td>Timestamp</td><td><?php echo date('Y-m-d H:i:s'); ?></td></tr>
            </table>
        </div>
    </div>
</body>
</html>

<?php
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}
?>
EOF

# Configurar permisos
chown -R www-data:www-data $WEB_ROOT
chmod -R 755 $WEB_ROOT
chmod -R 644 $WEB_ROOT/*.php
chmod 755 $WEB_ROOT/uploads

# Configurar fail2ban para Apache
log "Configurando fail2ban para Apache..."
cat > /etc/fail2ban/jail.d/apache-fei.conf << 'EOF'
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error*.log
maxretry = 3
bantime = 3600

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/*access*.log
maxretry = 1
bantime = 86400

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache2/*access*.log
maxretry = 2
bantime = 3600

[apache-overflows]
enabled = true
port = http,https
filter = apache-overflows
logpath = /var/log/apache2/*access*.log
maxretry = 2
bantime = 3600
EOF

# Configurar logrotate para Apache
cat > /etc/logrotate.d/apache-fei << 'EOF'
/var/log/apache2/*fei*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 644 www-data adm
    postrotate
        systemctl reload apache2 > /dev/null 2>&1 || true
    endscript
}
EOF

# Configurar actualizaciones automáticas de seguridad
log "Configurando actualizaciones automáticas..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

# Crear script de monitoreo
log "Creando script de monitoreo..."
cat > /usr/local/bin/web-monitor.sh << 'EOF'
#!/bin/bash
# Script de monitoreo para servidor web FEI

LOG_FILE="/var/log/web-monitor.log"
ALERT_FILE="/var/log/web-alerts.log"

# Función para logging
log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> $LOG_FILE
}

# Función para alertas
send_alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ALERT - $message" >> $ALERT_FILE
    logger "WEB-ALERT: $message"
}

# Verificar servicios
check_services() {
    services=("apache2" "mariadb" "fail2ban")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            send_alert "Servicio $service no está activo"
        fi
    done
}

# Verificar conectividad
check_connectivity() {
    if ! curl -s http://localhost > /dev/null; then
        send_alert "Servidor web no responde en puerto 80"
    fi
}

# Verificar espacio en disco
check_disk_space() {
    usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ $usage -gt 90 ]; then
        send_alert "Uso de disco crítico: ${usage}%"
    fi
}

# Verificar procesos sospechosos
check_processes() {
    suspicious_processes=$(ps aux | grep -E "(nc|netcat|nmap|sqlmap)" | grep -v grep | wc -l)
    if [ $suspicious_processes -gt 0 ]; then
        send_alert "Procesos sospechosos detectados"
    fi
}

# Ejecutar verificaciones
check_services
check_connectivity
check_disk_space
check_processes

log_event "Monitoreo completado"
EOF

chmod +x /usr/local/bin/web-monitor.sh

# Agregar monitoreo al crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/web-monitor.sh") | crontab -

# Configurar UFW (firewall local)
log "Configurando firewall local..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.10.30.0/24 to any port 22
ufw allow 80
ufw allow 443

# Reiniciar servicios
log "Reiniciando servicios..."
systemctl restart apache2
systemctl restart mariadb
systemctl restart fail2ban
systemctl restart networking

# Mostrar información de configuración
log "¡Configuración completada exitosamente!"
echo
info "=== INFORMACIÓN DEL SERVIDOR WEB ==="
info "URL: http://10.10.10.10 (se redirige a HTTPS)"
info "Panel Admin: http://10.10.10.10/admin/ (admin/admin123)"
info "Documentos: $WEB_ROOT"
info "Logs Apache: /var/log/apache2/"
info "Logs Monitoreo: /var/log/web-monitor.log"
echo
info "=== CREDENCIALES DE BASE DE DATOS ==="
info "Base de datos: $DB_NAME"
info "Usuario: $DB_USER"
info "Contraseña: (guardada en /root/.db_credentials)"
echo
warn "=== TAREAS PENDIENTES ==="
warn "1. Configurar certificado SSL con certbot"
warn "2. Personalizar contenido web según necesidades"
warn "3. Configurar backup automático de base de datos"
warn "4. Revisar logs de seguridad regularmente"
echo
log "El servidor web está configurado y funcionando correctamente."
