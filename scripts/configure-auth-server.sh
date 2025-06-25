#!/bin/bash

##############################################################################
# Script de Configuración Servidor de Autenticación - Sistema Ciberseguridad FEI
# 
# Descripción: Instalación y configuración de OpenLDAP con integración
#              de autenticación centralizada para el entorno FEI
# 
# Autor: Proyecto Ciberseguridad FEI
# Fecha: 2025
# Versión: 1.0
# Sistema: Debian 12 (VM9 - 10.10.20.40)
##############################################################################

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuración
LDAP_DOMAIN="fei.uv.mx"
LDAP_BASE_DN="dc=fei,dc=uv,dc=mx"
LDAP_ADMIN_DN="cn=admin,$LDAP_BASE_DN"
LDAP_ADMIN_PASSWORD="FEI_Admin_2025!"
LDAP_SERVER_IP="10.10.20.40"
ORGANIZATION="Universidad Veracruzana - FEI"
RADIUS_SECRET="FEI_Radius_Secret_2025!"

# Función para logging
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/auth-server-install.log
}

error_message() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/auth-server-install.log
}

warning_message() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/auth-server-install.log
}

# Verificar privilegios de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_message "Este script debe ejecutarse como root"
        exit 1
    fi
}

# Backup de configuraciones existentes
backup_configs() {
    log_message "Creando backup de configuraciones existentes..."
    
    if [ -f "/etc/ldap/slapd.conf" ]; then
        cp "/etc/ldap/slapd.conf" "/etc/ldap/slapd.conf.backup.$(date +%Y%m%d_%H%M%S)"
        log_message "Backup de slapd.conf creado"
    fi
}

# Actualizar sistema
update_system() {
    log_message "Actualizando repositorios del sistema..."
    apt update -qq
    
    log_message "Actualizando paquetes del sistema..."
    apt upgrade -y -qq
}

# Configurar variables de entorno para instalación silenciosa
configure_debconf() {
    log_message "Configurando variables de instalación..."
    
    # Configurar debconf para instalación no interactiva
    echo "slapd slapd/internal/generated_adminpw password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/internal/adminpw password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/password2 password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/password1 password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/dump_database_destdir string /var/backups/slapd-VERSION" | debconf-set-selections
    echo "slapd slapd/domain string $LDAP_DOMAIN" | debconf-set-selections
    echo "slapd shared/organization string $ORGANIZATION" | debconf-set-selections
    echo "slapd slapd/backend string MDB" | debconf-set-selections
    echo "slapd slapd/purge_database boolean true" | debconf-set-selections
    echo "slapd slapd/move_old_database boolean true" | debconf-set-selections
    echo "slapd slapd/allow_ldap_v2 boolean false" | debconf-set-selections
    echo "slapd slapd/no_configuration boolean false" | debconf-set-selections
    echo "slapd slapd/dump_database boolean when needed" | debconf-set-selections
}

# Instalar dependencias
install_dependencies() {
    log_message "Instalando dependencias necesarias..."
    
    apt install -y \
        slapd \
        ldap-utils \
        phpldapadmin \
        apache2 \
        libapache2-mod-php \
        php \
        php-ldap \
        php-xml \
        freeradius \
        freeradius-ldap \
        freeradius-utils \
        ssl-cert \
        openssl \
        ca-certificates \
        rsyslog \
        logrotate \
        curl \
        wget \
        net-tools \
        ldapvi \
        python3-ldap \
        python3-pip
        
    if [ $? -eq 0 ]; then
        log_message "Dependencias instaladas correctamente"
    else
        error_message "Error al instalar dependencias"
        exit 1
    fi
}

# Configurar OpenLDAP
configure_openldap() {
    log_message "Configurando OpenLDAP..."
    
    # Reconfigurar slapd
    dpkg-reconfigure -f noninteractive slapd
    
    # Verificar configuración
    systemctl restart slapd
    systemctl enable slapd
    
    # Esperar a que el servicio esté listo
    sleep 5
    
    # Crear estructura organizacional base
    cat > "/tmp/base_structure.ldif" << EOF
# Estructura base para FEI
dn: $LDAP_BASE_DN
objectClass: top
objectClass: dcObject
objectClass: organization
o: $ORGANIZATION
dc: fei

# Unidad Organizacional para Personas
dn: ou=people,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: people

# Unidad Organizacional para Grupos
dn: ou=groups,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: groups

# Unidad Organizacional para Servicios
dn: ou=services,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: services

# Grupo de Administradores
dn: cn=administrators,ou=groups,$LDAP_BASE_DN
objectClass: groupOfNames
cn: administrators
description: Administradores del sistema FEI
member: $LDAP_ADMIN_DN

# Grupo de Profesores
dn: cn=profesores,ou=groups,$LDAP_BASE_DN
objectClass: groupOfNames
cn: profesores
description: Profesores de la FEI
member: $LDAP_ADMIN_DN

# Grupo de Estudiantes
dn: cn=estudiantes,ou=groups,$LDAP_BASE_DN
objectClass: groupOfNames
cn: estudiantes
description: Estudiantes de la FEI
member: $LDAP_ADMIN_DN

# Grupo de Personal Administrativo
dn: cn=administrativo,ou=groups,$LDAP_BASE_DN
objectClass: groupOfNames
cn: administrativo
description: Personal administrativo de la FEI
member: $LDAP_ADMIN_DN
EOF

    # Aplicar estructura base
    ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f /tmp/base_structure.ldif
    
    if [ $? -eq 0 ]; then
        log_message "Estructura organizacional LDAP creada"
    else
        error_message "Error al crear estructura LDAP"
    fi
    
    # Crear usuarios de ejemplo
    create_sample_users
    
    log_message "OpenLDAP configurado correctamente"
}

# Crear usuarios de ejemplo
create_sample_users() {
    log_message "Creando usuarios de ejemplo..."
    
    cat > "/tmp/sample_users.ldif" << EOF
# Usuario Administrador
dn: uid=admin.fei,ou=people,$LDAP_BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: admin.fei
sn: Administrador
givenName: Sistema
cn: Administrador Sistema
displayName: Administrador Sistema FEI
mail: admin@fei.uv.mx
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/admin.fei
loginShell: /bin/bash
userPassword: {SSHA}$(slappasswd -s "Admin123!")

# Profesor de ejemplo
dn: uid=profesor.ejemplo,ou=people,$LDAP_BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: profesor.ejemplo
sn: Ejemplo
givenName: Profesor
cn: Profesor Ejemplo
displayName: Profesor Ejemplo
mail: profesor.ejemplo@fei.uv.mx
uidNumber: 10002
gidNumber: 10002
homeDirectory: /home/profesor.ejemplo
loginShell: /bin/bash
userPassword: {SSHA}$(slappasswd -s "Profesor123!")

# Estudiante de ejemplo
dn: uid=estudiante.ejemplo,ou=people,$LDAP_BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: estudiante.ejemplo
sn: Ejemplo
givenName: Estudiante
cn: Estudiante Ejemplo
displayName: Estudiante Ejemplo
mail: estudiante.ejemplo@fei.uv.mx
uidNumber: 10003
gidNumber: 10003
homeDirectory: /home/estudiante.ejemplo
loginShell: /bin/bash
userPassword: {SSHA}$(slappasswd -s "Estudiante123!")

# Usuario de servicio VPN
dn: uid=vpn.service,ou=services,$LDAP_BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: vpn.service
sn: Service
givenName: VPN
cn: VPN Service
displayName: Servicio VPN
mail: vpn@fei.uv.mx
uidNumber: 10004
gidNumber: 10004
homeDirectory: /dev/null
loginShell: /sbin/nologin
userPassword: {SSHA}$(slappasswd -s "VPN_Service_2025!")

# Usuario de servicio Web
dn: uid=web.service,ou=services,$LDAP_BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: web.service
sn: Service
givenName: Web
cn: Web Service
displayName: Servicio Web
mail: web@fei.uv.mx
uidNumber: 10005
gidNumber: 10005
homeDirectory: /dev/null
loginShell: /sbin/nologin
userPassword: {SSHA}$(slappasswd -s "Web_Service_2025!")
EOF

    # Aplicar usuarios de ejemplo
    ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f /tmp/sample_users.ldif
    
    if [ $? -eq 0 ]; then
        log_message "Usuarios de ejemplo creados"
    else
        warning_message "Error al crear algunos usuarios de ejemplo"
    fi
}

# Configurar phpLDAPadmin
configure_phpldapadmin() {
    log_message "Configurando phpLDAPadmin..."
    
    # Configurar Apache para phpLDAPadmin
    cat > "/etc/apache2/conf-available/phpldapadmin.conf" << EOF
# Configuración phpLDAPadmin - FEI
Alias /phpldapadmin /usr/share/phpldapadmin/htdocs

<Directory /usr/share/phpldapadmin/htdocs>
    DirectoryIndex index.php
    Options +FollowSymLinks
    AllowOverride None
    
    # Restricción de acceso por IP
    <RequireAll>
        Require ip 10.10.20.0/24
        Require ip 10.10.30.0/24
        Require ip 127.0.0.1
        Require ip ::1
    </RequireAll>
    
    <IfModule mod_php.c>
        php_flag magic_quotes_gpc Off
        php_flag track_vars On
    </IfModule>
</Directory>
EOF

    # Habilitar configuración
    a2enconf phpldapadmin
    
    # Configurar phpLDAPadmin
    cp /etc/phpldapadmin/config.php /etc/phpldapadmin/config.php.backup
    
    cat > "/etc/phpldapadmin/config.php" << EOF
<?php
// Configuración phpLDAPadmin - Sistema Ciberseguridad FEI

\$config->custom->appearance['friendly_attrs'] = array(
    'facsimileTelephoneNumber' => 'Fax',
    'gid'                      => 'Group',
    'mail'                     => 'Email',
    'telephoneNumber'          => 'Telephone',
    'uid'                      => 'User Name',
    'userPassword'             => 'Password'
);

\$servers = new Datastore();

\$servers->newServer('ldap_pla');
\$servers->setValue('server','name','Servidor LDAP FEI');
\$servers->setValue('server','host','127.0.0.1');
\$servers->setValue('server','port',389);
\$servers->setValue('server','base',array('$LDAP_BASE_DN'));
\$servers->setValue('login','auth_type','cookie');
\$servers->setValue('login','bind_id','$LDAP_ADMIN_DN');
\$servers->setValue('login','bind_pass','');
\$servers->setValue('server','tls',false);

\$servers->setValue('appearance','password_hash_custom','ssha');
\$servers->setValue('login','attr','dn');
\$servers->setValue('auto_number','min',array('uidNumber'=>10000,'gidNumber'=>10000));

// Configuración de seguridad
\$config->custom->session['blowfish'] = 'FEI_LDAP_Secret_Key_2025';
\$config->custom->password['no_random_crypt_salt'] = true;
\$config->custom->appearance['hide_template_warning'] = true;

// Configuración de logging
\$config->custom->debug['level'] = 0;
\$config->custom->debug['syslog'] = true;
\$config->custom->debug['file'] = '/var/log/phpldapadmin.log';

?>
EOF

    # Reiniciar Apache
    systemctl restart apache2
    systemctl enable apache2
    
    log_message "phpLDAPadmin configurado correctamente"
}

# Configurar FreeRADIUS con LDAP
configure_freeradius() {
    log_message "Configurando FreeRADIUS con integración LDAP..."
    
    # Backup de configuraciones originales
    cp /etc/freeradius/3.0/radiusd.conf /etc/freeradius/3.0/radiusd.conf.backup
    cp /etc/freeradius/3.0/clients.conf /etc/freeradius/3.0/clients.conf.backup
    
    # Configurar módulo LDAP
    cat > "/etc/freeradius/3.0/mods-available/ldap" << EOF
# Configuración módulo LDAP para FreeRADIUS - FEI
ldap {
    server = '$LDAP_SERVER_IP'
    port = 389
    identity = '$LDAP_ADMIN_DN'
    password = '$LDAP_ADMIN_PASSWORD'
    base_dn = '$LDAP_BASE_DN'
    
    # Configuración de búsqueda de usuarios
    user {
        base_dn = "ou=people,$LDAP_BASE_DN"
        filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
        scope = 'sub'
        
        # Mapeo de atributos
        access_attribute = 'uid'
    }
    
    # Configuración de búsqueda de grupos
    group {
        base_dn = "ou=groups,$LDAP_BASE_DN"
        filter = '(objectClass=groupOfNames)'
        scope = 'sub'
        name_attribute = cn
        membership_filter = "(|(member=%{control:Ldap-UserDn})(memberUid=%{%{Stripped-User-Name}:-%{User-Name}}))"
        membership_attribute = 'member'
    }
    
    # Pool de conexiones
    pool {
        start = 5
        min = 4
        max = 32
        spare = 3
        uses = 0
        retry_delay = 30
        lifetime = 0
        idle_timeout = 60
    }
    
    # Configuración de TLS (deshabilitado para entorno interno)
    tls {
        start_tls = no
    }
    
    # Opciones adicionales
    chase_referrals = yes
    rebind = yes
    
    # Configuración de timeout
    net_timeout = 10
    timeout = 4
    timelimit = 3
    
    # Configuración de reconexión
    reconnect = yes
}
EOF

    # Habilitar módulo LDAP
    ln -sf /etc/freeradius/3.0/mods-available/ldap /etc/freeradius/3.0/mods-enabled/
    
    # Configurar clientes RADIUS
    cat > "/etc/freeradius/3.0/clients.conf" << EOF
# Configuración de clientes RADIUS - Sistema FEI

# Cliente localhost
client localhost {
    ipaddr = 127.0.0.1
    secret = $RADIUS_SECRET
    require_message_authenticator = no
    nas_type = other
    shortname = localhost
}

# Cliente VPN Server
client vpn-server {
    ipaddr = 10.10.20.30
    secret = $RADIUS_SECRET
    require_message_authenticator = yes
    nas_type = other
    shortname = vpn-fei
}

# Cliente Firewall
client firewall {
    ipaddr = 10.10.20.1
    secret = $RADIUS_SECRET
    require_message_authenticator = yes
    nas_type = other
    shortname = firewall-fei
}

# Red de gestión completa
client management-network {
    ipaddr = 10.10.30.0/24
    secret = $RADIUS_SECRET
    require_message_authenticator = yes
    nas_type = other
    shortname = mgmt-net
}

# Red LAN completa
client lan-network {
    ipaddr = 10.10.20.0/24
    secret = $RADIUS_SECRET
    require_message_authenticator = no
    nas_type = other
    shortname = lan-net
}
EOF

    # Configurar sitio por defecto
    cat > "/etc/freeradius/3.0/sites-available/default" << EOF
# Sitio por defecto FreeRADIUS - FEI
server default {
    listen {
        type = auth
        ipaddr = *
        port = 0
        limit {
            max_connections = 16
            lifetime = 0
            idle_timeout = 30
        }
    }
    
    listen {
        ipaddr = *
        port = 0
        type = acct
        limit {
        }
    }
    
    authorize {
        filter_username
        preprocess
        chap
        mschap
        digest
        suffix
        eap {
            ok = return
        }
        files
        ldap
        expiration
        logintime
        pap
    }
    
    authenticate {
        Auth-Type PAP {
            pap
        }
        Auth-Type CHAP {
            chap
        }
        Auth-Type MS-CHAP {
            mschap
        }
        Auth-Type LDAP {
            ldap
        }
        digest
        eap
    }
    
    preacct {
        preprocess
        acct_unique
        suffix
        files
    }
    
    accounting {
        detail
        unix
        radutmp
        exec
        attr_filter.accounting_response
    }
    
    session {
        radutmp
    }
    
    post-auth {
        update {
            &reply: += &session-state:
        }
        exec
        remove_reply_message_if_eap
        Post-Auth-Type REJECT {
            attr_filter.access_reject
            eap
            remove_reply_message_if_eap
        }
    }
    
    pre-proxy {
    }
    
    post-proxy {
        eap
    }
}
EOF

    # Configurar usuarios locales adicionales
    cat > "/etc/freeradius/3.0/users" << EOF
# Usuarios locales FreeRADIUS - FEI

# Usuario de emergencia
emergency Cleartext-Password := "Emergency_FEI_2025!"
    Reply-Message := "Usuario de emergencia FEI"

# Usuario de prueba
test Cleartext-Password := "test123"
    Reply-Message := "Usuario de prueba FEI"

# Grupo por defecto para usuarios LDAP
DEFAULT Ldap-Group == "administrators"
    Reply-Message := "Acceso administrativo autorizado"

DEFAULT Ldap-Group == "profesores"
    Reply-Message := "Acceso profesor autorizado"

DEFAULT Ldap-Group == "estudiantes"
    Reply-Message := "Acceso estudiante autorizado"

DEFAULT Ldap-Group == "administrativo"
    Reply-Message := "Acceso administrativo autorizado"
EOF

    # Configurar logging
    sed -i 's/auth = no/auth = yes/' /etc/freeradius/3.0/radiusd.conf
    sed -i 's/auth_badpass = no/auth_badpass = yes/' /etc/freeradius/3.0/radiusd.conf
    sed -i 's/auth_goodpass = no/auth_goodpass = yes/' /etc/freeradius/3.0/radiusd.conf
    
    # Configurar permisos
    chown -R freerad:freerad /etc/freeradius/3.0/
    
    # Reiniciar y habilitar FreeRADIUS
    systemctl restart freeradius
    systemctl enable freeradius
    
    log_message "FreeRADIUS configurado con integración LDAP"
}

# Configurar SSL/TLS
configure_ssl() {
    log_message "Configurando SSL/TLS..."
    
    # Generar certificado autofirmado para LDAPS
    mkdir -p /etc/ldap/certs
    
    openssl req -new -x509 -nodes -out /etc/ldap/certs/ldap-server.crt \
        -keyout /etc/ldap/certs/ldap-server.key -days 365 \
        -subj "/C=MX/ST=Veracruz/L=Xalapa/O=Universidad Veracruzana/OU=FEI/CN=ldap.fei.uv.mx"
    
    # Configurar permisos
    chown openldap:openldap /etc/ldap/certs/*
    chmod 600 /etc/ldap/certs/ldap-server.key
    chmod 644 /etc/ldap/certs/ldap-server.crt
    
    # Habilitar SSL en Apache para phpLDAPadmin
    a2enmod ssl
    a2ensite default-ssl
    
    log_message "SSL/TLS configurado"
}

# Configurar firewall
configure_firewall() {
    log_message "Configurando firewall para servicios de autenticación..."
    
    # LDAP (389) y LDAPS (636)
    iptables -A INPUT -p tcp --dport 389 -s 10.10.0.0/16 -j ACCEPT
    iptables -A INPUT -p tcp --dport 636 -s 10.10.0.0/16 -j ACCEPT
    
    # RADIUS (1812, 1813)
    iptables -A INPUT -p udp --dport 1812 -s 10.10.0.0/16 -j ACCEPT
    iptables -A INPUT -p udp --dport 1813 -s 10.10.0.0/16 -j ACCEPT
    
    # Apache para phpLDAPadmin (80, 443)
    iptables -A INPUT -p tcp --dport 80 -s 10.10.0.0/16 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -s 10.10.0.0/16 -j ACCEPT
    
    # Guardar reglas
    iptables-save > /etc/iptables/rules.v4
    
    log_message "Firewall configurado para servicios de autenticación"
}

# Configurar logging y monitoreo
configure_logging() {
    log_message "Configurando logging y monitoreo..."
    
    # Configurar rsyslog para LDAP y RADIUS
    cat > "/etc/rsyslog.d/50-auth-services.conf" << 'EOF'
# Configuración rsyslog para servicios de autenticación - FEI

# OpenLDAP logs
if $programname == 'slapd' then {
    /var/log/auth-services/openldap.log
    @@10.10.30.10:514
    stop
}

# FreeRADIUS logs
if $programname == 'freeradius' then {
    /var/log/auth-services/freeradius.log
    @@10.10.30.10:514
    stop
}

# Autenticación general
if $programname == 'auth' then {
    /var/log/auth-services/auth.log
    @@10.10.30.10:514
    stop
}
EOF

    # Crear directorio de logs
    mkdir -p /var/log/auth-services
    chown syslog:adm /var/log/auth-services
    
    # Reiniciar rsyslog
    systemctl restart rsyslog
    
    log_message "Logging configurado"
}

# Configurar logrotate
configure_logrotate() {
    log_message "Configurando rotación de logs..."
    
    cat > "/etc/logrotate.d/auth-services-fei" << 'EOF'
/var/log/auth-services/*.log {
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

/var/log/freeradius/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 freerad freerad
    postrotate
        systemctl reload freeradius
    endscript
}
EOF

    log_message "Rotación de logs configurada"
}

# Crear herramientas de administración
create_admin_tools() {
    log_message "Creando herramientas de administración..."
    
    # Script de gestión de usuarios LDAP
    cat > "/usr/local/bin/ldap-user-manager.sh" << 'EOF'
#!/bin/bash
# Gestor de usuarios LDAP - FEI

LDAP_BASE_DN="dc=fei,dc=uv,dc=mx"
LDAP_ADMIN_DN="cn=admin,$LDAP_BASE_DN"
LDAP_ADMIN_PASSWORD="FEI_Admin_2025!"

show_help() {
    echo "Uso: $0 [OPCIÓN] [PARÁMETROS]"
    echo ""
    echo "Opciones:"
    echo "  add-user <uid> <nombre> <apellido> <email> <grupo>    Agregar usuario"
    echo "  del-user <uid>                                        Eliminar usuario"
    echo "  list-users                                           Listar usuarios"
    echo "  list-groups                                          Listar grupos"
    echo "  change-password <uid>                                Cambiar contraseña"
    echo "  add-to-group <uid> <grupo>                           Agregar a grupo"
    echo "  help                                                 Mostrar ayuda"
    echo ""
    echo "Grupos disponibles: administrators, profesores, estudiantes, administrativo"
}

add_user() {
    local uid=$1
    local first_name=$2
    local last_name=$3
    local email=$4
    local group=$5
    
    if [ -z "$uid" ] || [ -z "$first_name" ] || [ -z "$last_name" ] || [ -z "$email" ] || [ -z "$group" ]; then
        echo "Error: Todos los parámetros son requeridos"
        echo "Uso: add-user <uid> <nombre> <apellido> <email> <grupo>"
        exit 1
    fi
    
    # Generar UID number único
    local uid_number=$(ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=people,$LDAP_BASE_DN" "(objectClass=posixAccount)" uidNumber | grep "uidNumber:" | awk '{print $2}' | sort -n | tail -1)
    uid_number=$((uid_number + 1))
    
    cat > "/tmp/new_user.ldif" << EOF
dn: uid=$uid,ou=people,$LDAP_BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: $uid
sn: $last_name
givenName: $first_name
cn: $first_name $last_name
displayName: $first_name $last_name
mail: $email
uidNumber: $uid_number
gidNumber: $uid_number
homeDirectory: /home/$uid
loginShell: /bin/bash
userPassword: {SSHA}$(slappasswd -s "TempPass123!")
EOF

    ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f /tmp/new_user.ldif
    
    if [ $? -eq 0 ]; then
        echo "Usuario $uid creado exitosamente"
        echo "Contraseña temporal: TempPass123!"
        add_to_group "$uid" "$group"
        rm -f /tmp/new_user.ldif
    else
        echo "Error al crear usuario $uid"
        rm -f /tmp/new_user.ldif
    fi
}

del_user() {
    local uid=$1
    
    if [ -z "$uid" ]; then
        echo "Error: UID requerido"
        exit 1
    fi
    
    ldapdelete -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" "uid=$uid,ou=people,$LDAP_BASE_DN"
    
    if [ $? -eq 0 ]; then
        echo "Usuario $uid eliminado exitosamente"
    else
        echo "Error al eliminar usuario $uid"
    fi
}

list_users() {
    echo "=== Usuarios LDAP ==="
    ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=people,$LDAP_BASE_DN" "(objectClass=inetOrgPerson)" uid cn mail | grep -E "^(uid|cn|mail):" | awk '{print $2}' | paste - - -
}

list_groups() {
    echo "=== Grupos LDAP ==="
    ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=groups,$LDAP_BASE_DN" "(objectClass=groupOfNames)" cn description | grep -E "^(cn|description):" | awk '{print $2}' | paste - -
}

change_password() {
    local uid=$1
    
    if [ -z "$uid" ]; then
        echo "Error: UID requerido"
        exit 1
    fi
    
    echo -n "Nueva contraseña para $uid: "
    read -s password
    echo
    
    ldappasswd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -s "$password" "uid=$uid,ou=people,$LDAP_BASE_DN"
    
    if [ $? -eq 0 ]; then
        echo "Contraseña cambiada exitosamente para $uid"
    else
        echo "Error al cambiar contraseña para $uid"
    fi
}

add_to_group() {
    local uid=$1
    local group=$2
    
    if [ -z "$uid" ] || [ -z "$group" ]; then
        echo "Error: UID y grupo requeridos"
        exit 1
    fi
    
    cat > "/tmp/add_to_group.ldif" << EOF
dn: cn=$group,ou=groups,$LDAP_BASE_DN
changetype: modify
add: member
member: uid=$uid,ou=people,$LDAP_BASE_DN
EOF

    ldapmodify -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f /tmp/add_to_group.ldif
    
    if [ $? -eq 0 ]; then
        echo "Usuario $uid agregado al grupo $group"
        rm -f /tmp/add_to_group.ldif
    else
        echo "Error al agregar usuario $uid al grupo $group"
        rm -f /tmp/add_to_group.ldif
    fi
}

case "$1" in
    add-user)
        add_user "$2" "$3" "$4" "$5" "$6"
        ;;
    del-user)
        del_user "$2"
        ;;
    list-users)
        list_users
        ;;
    list-groups)
        list_groups
        ;;
    change-password)
        change_password "$2"
        ;;
    add-to-group)
        add_to_group "$2" "$3"
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
EOF

    chmod +x /usr/local/bin/ldap-user-manager.sh
    
    # Script de monitoreo de servicios de autenticación
    cat > "/usr/local/bin/auth-monitor.sh" << 'EOF'
#!/bin/bash
# Monitor de servicios de autenticación - FEI

echo "=== Monitor Servicios de Autenticación - FEI ==="
echo "Presiona Ctrl+C para salir"
echo ""

while true; do
    clear
    echo "=== Estado de Servicios ==="
    echo "OpenLDAP:"
    systemctl is-active slapd && echo "  ✓ Activo" || echo "  ✗ Inactivo"
    
    echo "FreeRADIUS:"
    systemctl is-active freeradius && echo "  ✓ Activo" || echo "  ✗ Inactivo"
    
    echo "Apache (phpLDAPadmin):"
    systemctl is-active apache2 && echo "  ✓ Activo" || echo "  ✗ Inactivo"
    
    echo ""
    echo "=== Conexiones LDAP ==="
    netstat -an | grep ":389 " | wc -l | xargs echo "  Conexiones activas:"
    
    echo ""
    echo "=== Estadísticas RADIUS ==="
    if [ -f /var/log/freeradius/radius.log ]; then
        echo "  Autenticaciones hoy: $(grep "$(date '+%Y-%m-%d')" /var/log/freeradius/radius.log | grep "Access-Accept" | wc -l)"
        echo "  Rechazos hoy: $(grep "$(date '+%Y-%m-%d')" /var/log/freeradius/radius.log | grep "Access-Reject" | wc -l)"
    else
        echo "  No hay estadísticas disponibles"
    fi
    
    echo ""
    echo "=== Últimos Logs LDAP ==="
    if [ -f /var/log/auth-services/openldap.log ]; then
        tail -3 /var/log/auth-services/openldap.log
    else
        echo "  No hay logs disponibles"
    fi
    
    echo ""
    echo "Actualizado: $(date)"
    sleep 10
done
EOF

    chmod +x /usr/local/bin/auth-monitor.sh
    
    log_message "Herramientas de administración creadas"
}

# Función de verificación final
verify_installation() {
    log_message "Verificando instalación..."
    
    # Verificar OpenLDAP
    if systemctl is-active --quiet slapd; then
        log_message "✓ OpenLDAP activo"
    else
        error_message "✗ OpenLDAP no está activo"
    fi
    
    # Verificar FreeRADIUS
    if systemctl is-active --quiet freeradius; then
        log_message "✓ FreeRADIUS activo"
    else
        error_message "✗ FreeRADIUS no está activo"
    fi
    
    # Verificar Apache
    if systemctl is-active --quiet apache2; then
        log_message "✓ Apache (phpLDAPadmin) activo"
    else
        warning_message "✗ Apache no está activo"
    fi
    
    # Verificar puertos
    if netstat -tlnp | grep -q ":389 "; then
        log_message "✓ Puerto LDAP (389) en escucha"
    else
        error_message "✗ Puerto LDAP no disponible"
    fi
    
    if netstat -ulnp | grep -q ":1812 "; then
        log_message "✓ Puerto RADIUS (1812) en escucha"
    else
        error_message "✗ Puerto RADIUS no disponible"
    fi
    
    # Verificar conectividad LDAP
    if ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "$LDAP_BASE_DN" "(objectClass=*)" >/dev/null 2>&1; then
        log_message "✓ Conectividad LDAP funcional"
    else
        error_message "✗ Error en conectividad LDAP"
    fi
    
    # Contar usuarios
    user_count=$(ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=people,$LDAP_BASE_DN" "(objectClass=inetOrgPerson)" | grep -c "^dn:")
    log_message "✓ Usuarios LDAP configurados: $user_count"
    
    # Mostrar resumen
    echo ""
    echo -e "${BLUE}=== RESUMEN DE INSTALACIÓN ===${NC}"
    echo "Servicios configurados:"
    echo "  - OpenLDAP: Puerto 389 (LDAP)"
    echo "  - FreeRADIUS: Puerto 1812 (Auth), 1813 (Acct)"
    echo "  - phpLDAPadmin: Puerto 80 (HTTP), 443 (HTTPS)"
    echo ""
    echo "Configuración LDAP:"
    echo "  - Base DN: $LDAP_BASE_DN"
    echo "  - Admin DN: $LDAP_ADMIN_DN"
    echo "  - Dominio: $LDAP_DOMAIN"
    echo "  - Usuarios creados: $user_count"
    echo ""
    echo "Acceso web:"
    echo "  - phpLDAPadmin: http://$LDAP_SERVER_IP/phpldapadmin"
    echo ""
    echo -e "${GREEN}Comandos útiles:${NC}"
    echo "  Gestión usuarios: /usr/local/bin/ldap-user-manager.sh"
    echo "  Monitor servicios: /usr/local/bin/auth-monitor.sh"
    echo "  Test RADIUS: radtest <usuario> <password> localhost 0 $RADIUS_SECRET"
    echo "  Búsqueda LDAP: ldapsearch -x -D '$LDAP_ADMIN_DN' -w '$LDAP_ADMIN_PASSWORD' -b '$LDAP_BASE_DN'"
}

# Función principal
main() {
    echo -e "${BLUE}"
    echo "############################################################################"
    echo "#                 Configuración Servidor Autenticación - FEI              #"
    echo "#                     Sistema Integral de Ciberseguridad                  #"
    echo "############################################################################"
    echo -e "${NC}"
    
    # Verificaciones previas
    check_root
    
    # Proceso de instalación
    log_message "Iniciando configuración del servidor de autenticación..."
    
    backup_configs
    update_system
    configure_debconf
    install_dependencies
    configure_openldap
    configure_phpldapadmin
    configure_freeradius
    configure_ssl
    configure_firewall
    configure_logging
    configure_logrotate
    create_admin_tools
    
    # Reiniciar servicios
    log_message "Reiniciando servicios..."
    systemctl restart slapd
    systemctl restart freeradius
    systemctl restart apache2
    
    # Verificación final
    verify_installation
    
    echo ""
    echo -e "${GREEN}¡Configuración del servidor de autenticación completada exitosamente!${NC}"
    echo ""
    echo -e "${YELLOW}Próximos pasos:${NC}"
    echo "1. Acceder a phpLDAPadmin: http://$LDAP_SERVER_IP/phpldapadmin"
    echo "2. Crear usuarios adicionales con /usr/local/bin/ldap-user-manager.sh"
    echo "3. Probar autenticación RADIUS: radtest test test123 localhost 0 $RADIUS_SECRET"
    echo "4. Integrar con otros servicios (VPN, etc.)"
    echo ""
    echo -e "${YELLOW}Credenciales importantes:${NC}"
    echo "LDAP Admin: $LDAP_ADMIN_DN"
    echo "LDAP Password: $LDAP_ADMIN_PASSWORD"
    echo "RADIUS Secret: $RADIUS_SECRET"
    echo ""
    
    log_message "Configuración del servidor de autenticación completada"
}

# Ejecutar función principal
main "$@"
