# Plan de Respuesta a Incidentes de Seguridad - FEI

## 1. Información General

### 1.1 Propósito
Este plan establece los procedimientos para detectar, responder y recuperarse de incidentes de seguridad de la información en la Facultad de Estadística e Informática (FEI), basado en las mejores prácticas del NIST SP 800-61r2.

### 1.2 Alcance
Aplica a todos los sistemas, redes, datos y personal de la FEI, incluyendo:
- Infraestructura tecnológica
- Sistemas de información académica
- Datos de estudiantes y personal
- Servicios en línea
- Equipos de laboratorio

### 1.3 Objetivos
- Minimizar el impacto de incidentes de seguridad
- Restaurar servicios normales lo más rápido posible
- Preservar evidencia para análisis forense
- Implementar mejoras para prevenir incidentes similares
- Cumplir con requisitos legales y regulatorios

## 2. Equipo de Respuesta a Incidentes (CSIRT-FEI)

### 2.1 Estructura del Equipo

#### 2.1.1 Líder de Incidentes
- **Responsable**: Coordinador de TI FEI
- **Contacto**: ti@fei.edu / (228) 842-1700 ext. 2502
- **Responsabilidades**:
  - Coordinar la respuesta general
  - Tomar decisiones críticas
  - Comunicar con la dirección
  - Activar el equipo de respuesta

#### 2.1.2 Analista Técnico Senior
- **Responsable**: Administrador de Sistemas
- **Contacto**: admin@fei.edu / (228) 842-1700 ext. 2503
- **Responsabilidades**:
  - Análisis técnico del incidente
  - Implementar medidas de contención
  - Coordinar la erradicación
  - Supervisar la recuperación

#### 2.1.3 Especialista en Seguridad
- **Responsable**: Jefe de Seguridad de la Información
- **Contacto**: seguridad@fei.edu / (228) 842-1700 ext. 2504
- **Responsabilidades**:
  - Evaluación de riesgos
  - Análisis forense
  - Coordinación con autoridades
  - Desarrollo de contramedidas

#### 2.1.4 Coordinador de Comunicaciones
- **Responsable**: Asistente de Dirección
- **Contacto**: comunicacion@fei.edu / (228) 842-1700 ext. 2505
- **Responsabilidades**:
  - Comunicación interna y externa
  - Documentación del incidente
  - Coordinar con medios (si aplica)
  - Mantener logs de comunicación

#### 2.1.5 Enlace Legal/Compliance
- **Responsable**: Secretario Académico
- **Contacto**: legal@fei.edu / (228) 842-1700 ext. 2506
- **Responsabilidades**:
  - Evaluación de implicaciones legales
  - Coordinación con autoridades regulatorias
  - Revisión de contratos y seguros
  - Documentación legal

### 2.2 Contactos de Emergencia

#### 2.2.1 Internos
| Rol | Nombre | Teléfono | Email | Disponibilidad |
|-----|--------|----------|-------|----------------|
| Director FEI | Dr. [Nombre] | (228) 842-1700 ext. 2501 | director@fei.edu | 24/7 |
| Coordinador TI | Ing. [Nombre] | (228) 842-1700 ext. 2502 | ti@fei.edu | 24/7 |
| Jefe Seguridad | M.C. [Nombre] | (228) 842-1700 ext. 2504 | seguridad@fei.edu | 24/7 |

#### 2.2.2 Externos
| Organización | Contacto | Teléfono | Email | Propósito |
|--------------|----------|----------|-------|-----------|
| CERT-MX | Mesa de Ayuda | 01-800-CERT-MX | incidentes@cert.org.mx | Coordinación nacional |
| Policía Cibernética | Denuncia | 088 | cibernetica@ssc.cdmx.gob.mx | Delitos informáticos |
| Universidad Veracruzana | DGTI | (228) 842-1745 | dgti@uv.mx | Soporte institucional |
| Proveedor ISP | Soporte | (228) 815-7000 | soporte@telmex.com | Conectividad |

## 3. Clasificación de Incidentes

### 3.1 Categorías de Incidentes

#### 3.1.1 Incidentes de Malware
- **Descripción**: Virus, trojanos, ransomware, spyware
- **Ejemplos**: Infección por ransomware, troyano bancario
- **Tiempo de respuesta**: 1 hora (crítico), 4 horas (alto)

#### 3.1.2 Acceso no Autorizado
- **Descripción**: Intrusión a sistemas, escalamiento de privilegios
- **Ejemplos**: Hack a servidor web, acceso a base de datos
- **Tiempo de respuesta**: 30 minutos (crítico), 2 horas (alto)

#### 3.1.3 Ataques de Denegación de Servicio (DoS/DDoS)
- **Descripción**: Ataques para interrumpir servicios
- **Ejemplos**: DDoS al sitio web, flood a servidores
- **Tiempo de respuesta**: 15 minutos (crítico), 1 hora (alto)

#### 3.1.4 Fuga de Datos
- **Descripción**: Exposición o robo de información sensible
- **Ejemplos**: Leak de base de datos, robo de expedientes
- **Tiempo de respuesta**: 15 minutos (crítico), 1 hora (alto)

#### 3.1.5 Phishing y Ingeniería Social
- **Descripción**: Engaños para obtener credenciales o información
- **Ejemplos**: Email de phishing, llamada fraudulenta
- **Tiempo de respuesta**: 2 horas (alto), 8 horas (medio)

#### 3.1.6 Comprometimiento de Sitio Web
- **Descripción**: Defacement, inyección de contenido malicioso
- **Ejemplos**: Alteración del sitio web, inyección SQL
- **Tiempo de respuesta**: 1 hora (crítico), 4 horas (alto)

### 3.2 Niveles de Severidad

| Nivel | Criterios | Ejemplos | Tiempo Respuesta | Escalamiento |
|-------|-----------|----------|------------------|--------------|
| **Crítico** | • Sistemas críticos comprometidos<br>• Fuga masiva de datos<br>• Ransomware activo<br>• Servicios académicos interrumpidos | • Encriptación de servidores<br>• Robo de base de datos completa<br>• Caída total de red | 15 minutos | Director + Rector |
| **Alto** | • Sistemas importantes afectados<br>• Acceso no autorizado confirmado<br>• Malware detectado<br>• Servicios parcialmente afectados | • Servidor web comprometido<br>• Acceso no autorizado a sistema<br>• Virus en múltiples equipos | 1 hora | Director + DGTI UV |
| **Medio** | • Intentos de intrusión<br>• Vulnerabilidades críticas<br>• Incidentes aislados<br>• Servicios degradados | • Escaneo de puertos<br>• Vulnerabilidad 0-day<br>• Phishing dirigido | 4 horas | Coordinador TI |
| **Bajo** | • Actividad sospechosa<br>• Vulnerabilidades menores<br>• Intentos fallidos<br>• Servicios normales | • Logs anómalos<br>• Intentos de login fallidos<br>• Spam masivo | 24 horas | Administrador |

## 4. Procedimiento de Respuesta a Incidentes

### 4.1 Fase 1: Preparación (Continua)

#### 4.1.1 Actividades Preventivas
- Mantener inventario de activos actualizado
- Implementar herramientas de monitoreo (SIEM, IDS/IPS)
- Realizar respaldos regulares y verificar integridad
- Capacitar al personal en detección de incidentes
- Mantener contactos actualizados
- Revisar y actualizar el plan trimestralmente

#### 4.1.2 Herramientas y Recursos
- **Forenses**: Kali Linux, Autopsy, Volatility
- **Análisis de red**: Wireshark, nmap, netstat
- **Análisis de malware**: VirusTotal, Hybrid Analysis
- **Comunicación**: Sistema de tickets, WhatsApp corporativo
- **Documentación**: Templates de reportes, formularios

#### 4.1.3 Kit de Respuesta a Incidentes
- Laptops aisladas para análisis forense
- Discos duros externos para respaldos de emergencia
- Dispositivos USB booteable con herramientas forenses
- Cables de red para segmentación de emergencia
- Celulares de emergencia para comunicación

### 4.2 Fase 2: Detección y Análisis (0-2 horas)

#### 4.2.1 Fuentes de Detección
- **Automáticas**:
  - Alertas del SIEM (Kibana)
  - IDS/IPS (Suricata)
  - Antivirus empresarial
  - Monitoreo de red
  - Logs de firewall

- **Manuales**:
  - Reportes de usuarios
  - Observación directa
  - Auditorías de seguridad
  - Análisis de logs

#### 4.2.2 Procedimiento de Detección

```
1. RECEPCIÓN DE ALERTA (0-15 min)
   ├─ Alerta automática → Verificar en SIEM
   ├─ Reporte de usuario → Validar información
   └─ Observación directa → Documentar hallazgos

2. CLASIFICACIÓN INICIAL (15-30 min)
   ├─ Determinar tipo de incidente
   ├─ Evaluar severidad inicial
   ├─ Asignar número de caso (INC-YYYY-NNNN)
   └─ Activar equipo correspondiente

3. ANÁLISIS PRELIMINAR (30-60 min)
   ├─ Recopilar evidencia inicial
   ├─ Determinar alcance
   ├─ Identificar sistemas afectados
   └─ Evaluar impacto potencial

4. ESCALAMIENTO (60-120 min)
   ├─ Notificar según nivel de severidad
   ├─ Convocar equipo de respuesta
   ├─ Establecer sala de crisis (si aplica)
   └─ Iniciar documentación formal
```

#### 4.2.3 Plantilla de Análisis Inicial

```
REPORTE INICIAL DE INCIDENTE
============================
Número de caso: INC-2025-____
Fecha/Hora detección: _______________
Reportado por: ____________________
Tipo de incidente: ________________
Severidad inicial: ________________

DESCRIPCIÓN:
_____________________________________

SISTEMAS AFECTADOS:
- Servidor: _______________________
- Aplicación: ____________________
- Red: ___________________________
- Usuarios: ______________________

EVIDENCIA INICIAL:
- Logs: __________________________
- Capturas: ______________________
- Archivos: ______________________

ACCIONES INMEDIATAS:
- Contención: ____________________
- Notificaciones: _________________
- Próximos pasos: _________________

Analista: ________________________
Supervisor: ______________________
```

### 4.3 Fase 3: Contención, Erradicación y Recuperación (2-72 horas)

#### 4.3.1 Estrategias de Contención

##### Contención Inmediata (Short-term)
- **Aislamiento de red**: Desconectar sistemas comprometidos
- **Desactivación de cuentas**: Suspender usuarios afectados
- **Bloqueo de IPs**: Actualizar reglas de firewall
- **Cierre de puertos**: Desactivar servicios vulnerables
- **Preservación de evidencia**: Crear imágenes forenses

##### Contención Temporal (Intermediate)
- **Segmentación de red**: Crear VLANs de cuarentena
- **Redirección de tráfico**: Usar proxy o WAF
- **Servicios alternativos**: Activar sistemas de respaldo
- **Monitoreo intensivo**: Aumentar logging y alertas

#### 4.3.2 Procedimientos por Tipo de Incidente

##### Malware/Ransomware
```
CONTENCIÓN:
1. Aislar sistemas infectados inmediatamente
2. Identificar variante de malware
3. Determinar método de propagación
4. Crear imágenes forenses antes de limpieza

ERRADICACIÓN:
5. Ejecutar antimalware en modo seguro
6. Eliminar archivos maliciosos
7. Cerrar vulnerabilidades explotadas
8. Aplicar parches de seguridad

RECUPERACIÓN:
9. Restaurar desde respaldos limpios
10. Verificar integridad de datos
11. Fortalecer controles de seguridad
12. Monitorear por reinfección
```

##### Acceso no Autorizado
```
CONTENCIÓN:
1. Cambiar credenciales comprometidas
2. Cerrar sesiones activas del atacante
3. Aislar sistemas accedidos
4. Revisar logs de acceso

ERRADICACIÓN:
5. Eliminar cuentas creadas por atacante
6. Cerrar puertas traseras (backdoors)
7. Corregir vulnerabilidades explotadas
8. Revisar y fortalecer controles de acceso

RECUPERACIÓN:
9. Restaurar configuraciones seguras
10. Implementar monitoreo adicional
11. Validar integridad de datos
12. Reactivar servicios gradualmente
```

##### Fuga de Datos
```
CONTENCIÓN:
1. Identificar origen y alcance de la fuga
2. Cerrar canal de exfiltración
3. Preservar evidencia forense
4. Notificar a autoridades (si aplica)

ERRADICACIÓN:
5. Eliminar datos expuestos de sitios públicos
6. Cerrar vulnerabilidades que causaron la fuga
7. Fortalecer controles de acceso a datos
8. Implementar DLP si no existe

RECUPERACIÓN:
9. Evaluar impacto en personas afectadas
10. Implementar medidas de mitigación
11. Comunicar a stakeholders
12. Monitorear uso indebido de datos
```

### 4.4 Fase 4: Post-Incidente (1-2 semanas)

#### 4.4.1 Documentación Final

##### Reporte Ejecutivo
```
RESUMEN EJECUTIVO DE INCIDENTE
==============================
Caso: INC-2025-____
Fecha: ___________

RESUMEN:
- Tipo: ________________________
- Duración: ____________________
- Sistemas afectados: ___________
- Impacto: ____________________

CRONOLOGÍA:
- Detección: __________________
- Contención: _________________
- Erradicación: _______________
- Recuperación: _______________

CAUSA RAÍZ:
____________________________

LECCIONES APRENDIDAS:
____________________________

RECOMENDACIONES:
____________________________

COSTO ESTIMADO:
- Tiempo personal: ____________
- Pérdida productividad: _______
- Costos técnicos: ___________
- Total: ____________________
```

#### 4.4.2 Sesión de Lecciones Aprendidas

##### Agenda Estándar
1. **Revisión cronológica** (30 min)
   - ¿Qué pasó y cuándo?
   - ¿Cómo se detectó?
   - ¿Qué funcionó bien?

2. **Análisis de causa raíz** (45 min)
   - ¿Por qué ocurrió?
   - ¿Qué fallas permitieron el incidente?
   - ¿Se pudo prevenir?

3. **Evaluación de respuesta** (30 min)
   - ¿Fue efectiva la respuesta?
   - ¿Qué se puede mejorar?
   - ¿Los procedimientos funcionaron?

4. **Plan de mejoras** (30 min)
   - Acciones correctivas
   - Actualizaciones de políticas
   - Inversiones requeridas
   - Responsables y fechas

## 5. Comunicación Durante Incidentes

### 5.1 Matriz de Comunicación

| Severidad | Audiencia | Método | Tiempo | Contenido |
|-----------|-----------|--------|--------|-----------|
| **Crítico** | Director, Rector | Llamada + Email | 15 min | Resumen ejecutivo, impacto, acciones |
| **Alto** | Coordinadores | Email + WhatsApp | 1 hora | Detalles técnicos, timeline |
| **Medio** | Equipo TI | Email | 4 horas | Información técnica, procedimientos |
| **Bajo** | Responsable área | Email | 24 horas | Notificación simple |

### 5.2 Templates de Comunicación

#### 5.2.1 Notificación Inicial (Crítico/Alto)
```
ASUNTO: [URGENTE] Incidente de Seguridad - INC-2025-NNNN

Estimado/a [Destinatario],

Se ha detectado un incidente de seguridad que requiere atención inmediata:

DETALLES:
- Tipo: [Tipo de incidente]
- Hora detección: [HH:MM]
- Sistemas afectados: [Lista]
- Impacto estimado: [Descripción]
- Estado actual: [En investigación/Contenido/Resuelto]

ACCIONES TOMADAS:
- [Acción 1]
- [Acción 2]

PRÓXIMOS PASOS:
- [Paso 1]
- [Paso 2]

Contacto: [Líder de incidentes]
Próxima actualización: [Tiempo]
```

#### 5.2.2 Actualización de Progreso
```
ASUNTO: [ACTUALIZACIÓN] INC-2025-NNNN - [Estado]

PROGRESO DEL INCIDENTE:
- Estado: [En progreso/Contenido/Resuelto]
- Última actualización: [HH:MM]
- Tiempo estimado resolución: [HH:MM]

ACTIVIDADES COMPLETADAS:
- [Lista de actividades]

ACTIVIDADES EN CURSO:
- [Lista de actividades]

PRÓXIMAS ACTIVIDADES:
- [Lista de actividades]

IMPACTO ACTUAL:
- Servicios afectados: [Lista]
- Usuarios impactados: [Número]
- Tiempo de inactividad: [Duración]
```

### 5.3 Comunicación Externa

#### 5.3.1 Criterios para Notificación Externa
- **Inmediata**: Fuga de datos personales, ataques que afecten servicios públicos
- **24 horas**: Compromiso de sistemas críticos, incidentes con repercusión mediática
- **72 horas**: Incidentes menores con posible impacto regulatorio

#### 5.3.2 Autoridades a Notificar
- **INAI**: Violaciones a datos personales
- **CERT-MX**: Incidentes de seguridad cibernética
- **Policía Cibernética**: Delitos informáticos
- **Universidad Veracruzana**: Incidentes que afecten imagen institucional

## 6. Herramientas y Recursos Técnicos

### 6.1 Herramientas de Análisis Forense

#### 6.1.1 Análisis de Memoria
```bash
# Volatility - Análisis de memoria RAM
volatility -f memory.dump --profile=LinuxDebian12x64 linux_psaux
volatility -f memory.dump --profile=LinuxDebian12x64 linux_netstat

# Captura de memoria con LiME
insmod lime.ko "path=/tmp/memory.dump format=raw"
```

#### 6.1.2 Análisis de Disco
```bash
# Crear imagen forense
dd if=/dev/sda of=/tmp/evidence.img bs=4096 conv=noerror,sync

# Análisis con Autopsy
autopsy &

# Búsqueda de archivos eliminados
photorec /tmp/evidence.img
```

#### 6.1.3 Análisis de Red
```bash
# Captura de tráfico
tcpdump -i ens33 -w /tmp/capture.pcap

# Análisis con Wireshark
wireshark /tmp/capture.pcap

# Análisis de logs de conexión
netstat -tulpn | grep ESTABLISHED
ss -tulpn | grep :80
```

### 6.2 Scripts de Respuesta Automatizada

#### 6.2.1 Script de Contención de Emergencia
```bash
#!/bin/bash
# emergency-containment.sh

INCIDENT_ID=$1
AFFECTED_IP=$2

if [ -z "$INCIDENT_ID" ] || [ -z "$AFFECTED_IP" ]; then
    echo "Uso: $0 <incident_id> <affected_ip>"
    exit 1
fi

echo "Iniciando contención de emergencia para $INCIDENT_ID"

# Bloquear IP en firewall
iptables -A INPUT -s $AFFECTED_IP -j DROP
iptables -A OUTPUT -d $AFFECTED_IP -j DROP

# Cerrar conexiones activas
ss -K dst $AFFECTED_IP

# Crear snapshot de evidencia
mkdir -p /evidence/$INCIDENT_ID
netstat -tulpn > /evidence/$INCIDENT_ID/netstat.txt
ps aux > /evidence/$INCIDENT_ID/processes.txt
lsof > /evidence/$INCIDENT_ID/openfiles.txt

echo "Contención completada. Evidencia en /evidence/$INCIDENT_ID"
```

#### 6.2.2 Script de Análisis Rápido
```bash
#!/bin/bash
# quick-analysis.sh

INCIDENT_ID=$1

echo "=== ANÁLISIS RÁPIDO DE SISTEMA ==="
echo "Incident ID: $INCIDENT_ID"
echo "Timestamp: $(date)"
echo

echo "=== CONEXIONES ACTIVAS ==="
netstat -tulpn | grep ESTABLISHED

echo -e "\n=== PROCESOS SOSPECHOSOS ==="
ps aux | grep -E "(nc|netcat|nmap|sqlmap|metasploit)"

echo -e "\n=== USUARIOS CONECTADOS ==="
who

echo -e "\n=== ÚLTIMOS LOGINS ==="
last -n 10

echo -e "\n=== ARCHIVOS MODIFICADOS RECIENTEMENTE ==="
find /var/log -type f -mmin -60 -ls

echo -e "\n=== USO DE DISCO ==="
df -h

echo -e "\n=== CARGA DEL SISTEMA ==="
uptime
free -h
```

### 6.3 Checklist de Verificación Post-Incidente

#### 6.3.1 Checklist Técnico
```
□ Sistemas restaurados y funcionando normalmente
□ Parches de seguridad aplicados
□ Contraseñas cambiadas
□ Logs de seguridad revisados
□ Configuraciones de firewall actualizadas
□ Antimalware ejecutado y actualizado
□ Respaldos verificados y funcionales
□ Monitoreo adicional implementado
□ Vulnerabilidades cerradas
□ Accesos no autorizados eliminados
```

#### 6.3.2 Checklist Administrativo
```
□ Documentación del incidente completada
□ Reporte ejecutivo entregado
□ Autoridades notificadas (si aplica)
□ Usuarios afectados comunicados
□ Costos del incidente calculados
□ Lecciones aprendidas documentadas
□ Plan de mejoras desarrollado
□ Políticas actualizadas
□ Personal capacitado en nuevos procedimientos
□ Seguimiento programado
```

## 7. Métricas y KPIs de Respuesta

### 7.1 Indicadores de Tiempo

| Métrica | Objetivo | Crítico | Alto | Medio | Bajo |
|---------|----------|---------|------|-------|------|
| **Tiempo de detección** | - | <15 min | <1 hora | <4 horas | <24 horas |
| **Tiempo de respuesta** | - | <15 min | <1 hora | <4 horas | <24 horas |
| **Tiempo de contención** | - | <1 hora | <4 horas | <8 horas | <48 horas |
| **Tiempo de recuperación** | - | <4 horas | <24 horas | <72 horas | <1 semana |
| **Tiempo total de resolución** | - | <8 horas | <48 horas | <1 semana | <2 semanas |

### 7.2 Indicadores de Calidad

| Métrica | Objetivo | Fórmula |
|---------|----------|---------|
| **Tasa de detección automática** | >80% | (Incidentes detectados automáticamente / Total incidentes) × 100 |
| **Precisión de clasificación** | >90% | (Incidentes clasificados correctamente / Total incidentes) × 100 |
| **Efectividad de contención** | >95% | (Incidentes contenidos exitosamente / Total incidentes) × 100 |
| **Tasa de reincidencia** | <5% | (Incidentes recurrentes / Total incidentes) × 100 |

### 7.3 Reporte Mensual de Métricas

```
REPORTE MENSUAL DE INCIDENTES - [MES/AÑO]
========================================

RESUMEN EJECUTIVO:
- Total de incidentes: ___
- Críticos: __ | Altos: __ | Medios: __ | Bajos: __
- Tiempo promedio de resolución: __ horas
- Costo total estimado: $____

TIPOS DE INCIDENTES:
- Malware: ____ (___%)
- Acceso no autorizado: ____ (___%)
- DoS/DDoS: ____ (___%)
- Fuga de datos: ____ (___%)
- Otros: ____ (___%)

MÉTRICAS DE RENDIMIENTO:
- Tiempo promedio de detección: __ minutos
- Tiempo promedio de respuesta: __ minutos
- Tiempo promedio de contención: __ horas
- Tiempo promedio de recuperación: __ horas

MEJORAS IMPLEMENTADAS:
- [Lista de mejoras]

RECOMENDACIONES:
- [Lista de recomendaciones]
```

## 8. Procedimientos Específicos por Escenario

### 8.1 Escenario: Ransomware en Sistema Crítico

#### Respuesta Inmediata (0-30 min)
1. **Aislamiento inmediato**
   ```bash
   # Desconectar de red
   ip link set ens33 down
   
   # Crear imagen de memoria
   dd if=/dev/mem of=/tmp/memory_$(date +%Y%m%d_%H%M).img
   ```

2. **Evaluación rápida**
   - Identificar variante de ransomware
   - Determinar sistemas afectados
   - Verificar estado de respaldos

3. **Notificación de emergencia**
   - Director FEI (inmediato)
   - CERT-MX (30 min)
   - Policía Cibernética (si hay demanda de rescate)

#### Contención (30 min - 2 horas)
1. **Análisis forense preliminar**
2. **Aislamiento de sistemas relacionados**
3. **Verificación de respaldos**
4. **Preparación para recuperación**

#### Recuperación (2-24 horas)
1. **Limpieza de sistemas**
2. **Restauración desde respaldos**
3. **Aplicación de parches**
4. **Verificación de integridad**

### 8.2 Escenario: Fuga de Base de Datos de Estudiantes

#### Respuesta Inmediata (0-15 min)
1. **Contener la fuga**
   - Cerrar acceso a la base de datos
   - Revisar logs de acceso
   - Identificar datos expuestos

2. **Preservar evidencia**
   - Capturar logs completos
   - Documentar hallazgos
   - Crear imágenes forenses

3. **Notificación urgente**
   - Director FEI
   - INAI (datos personales)
   - Asesor legal

#### Evaluación de Impacto (15 min - 2 horas)
1. **Determinar alcance**
   - Número de registros afectados
   - Tipo de información expuesta
   - Método de exfiltración

2. **Análisis legal**
   - Obligaciones de notificación
   - Posibles sanciones
   - Medidas de mitigación

#### Comunicación y Remediación (2 horas - 72 horas)
1. **Notificar a afectados**
2. **Implementar medidas de protección**
3. **Coordinar con autoridades**
4. **Monitorear uso indebido**

### 8.3 Escenario: Compromiso de Sitio Web Institucional

#### Detección y Contención (0-1 hora)
1. **Verificar compromiso**
   ```bash
   # Revisar integridad de archivos
   find /var/www/html -type f -name "*.php" -exec grep -l "eval\|base64_decode\|shell_exec" {} \;
   
   # Verificar procesos sospechosos
   ps aux | grep -E "(www-data|apache)" | grep -v grep
   ```

2. **Aislar sitio web**
   ```bash
   # Desactivar sitio
   a2dissite fei-web
   systemctl reload apache2
   
   # Mostrar página de mantenimiento
   cp /var/www/maintenance.html /var/www/html/index.html
   ```

3. **Preservar evidencia**
   ```bash
   # Crear backup forense
   tar -czf /evidence/web_compromise_$(date +%Y%m%d_%H%M).tar.gz /var/www/html/
   
   # Copiar logs
   cp /var/log/apache2/* /evidence/
   ```

#### Análisis y Limpieza (1-8 horas)
1. **Análisis de vulnerabilidad**
2. **Limpieza de contenido malicioso**
3. **Aplicación de parches**
4. **Fortalecimiento de seguridad**

#### Restauración (8-24 horas)
1. **Restaurar desde respaldo limpio**
2. **Verificar funcionalidad**
3. **Implementar monitoreo adicional**
4. **Reactivar sitio web**

## 9. Documentos de Apoyo

### 9.1 Formularios y Templates

#### 9.1.1 Formulario de Reporte de Incidente
```
REPORTE INICIAL DE INCIDENTE DE SEGURIDAD
==========================================

INFORMACIÓN BÁSICA:
- Número de caso: INC-2025-____
- Fecha/Hora: _______________
- Reportado por: ____________
- Método de detección: ______

CLASIFICACIÓN:
- Tipo de incidente: [ ] Malware [ ] Acceso no autorizado [ ] DoS/DDoS
                     [ ] Fuga de datos [ ] Phishing [ ] Web compromise [ ] Otro
- Severidad: [ ] Crítico [ ] Alto [ ] Medio [ ] Bajo
- Estado: [ ] Nuevo [ ] En investigación [ ] Contenido [ ] Resuelto

DESCRIPCIÓN DETALLADA:
_________________________________

SISTEMAS AFECTADOS:
- Servidores: __________________
- Aplicaciones: ________________
- Usuarios: ____________________
- Datos: _______________________

IMPACTO ESTIMADO:
- Confidencialidad: [ ] Alto [ ] Medio [ ] Bajo [ ] Ninguno
- Integridad: [ ] Alto [ ] Medio [ ] Bajo [ ] Ninguno  
- Disponibilidad: [ ] Alto [ ] Medio [ ] Bajo [ ] Ninguno

EVIDENCIA RECOLECTADA:
- Logs: ________________________
- Capturas de pantalla: ________
- Archivos: ____________________
- Otros: _______________________

ACCIONES TOMADAS:
_________________________________

RECOMENDACIONES:
_________________________________

ASIGNADO A: ____________________
PRÓXIMA REVISIÓN: _______________

Firmado: _______________________
Fecha: _________________________
```

### 9.2 Contactos de Emergencia (Tarjeta de Referencia)

```
┌─────────────────────────────────────────┐
│        CONTACTOS DE EMERGENCIA          │
│         INCIDENTES DE SEGURIDAD         │
├─────────────────────────────────────────┤
│ CSIRT-FEI: (228) 842-1700 ext. 2500    │
│ Email: csirt@fei.edu                    │
│                                         │
│ Director FEI: ext. 2501                 │
│ Coordinador TI: ext. 2502               │
│ Jefe Seguridad: ext. 2504               │
│                                         │
│ EXTERNOS:                               │
│ CERT-MX: 01-800-CERT-MX                │
│ Policía Cibernética: 088               │
│ INAI: 01-800-835-4324                  │
├─────────────────────────────────────────┤
│ PROCEDIMIENTO RÁPIDO:                   │
│ 1. Contener el incidente                │
│ 2. Preservar evidencia                  │
│ 3. Notificar según severidad            │
│ 4. Documentar todo                      │
└─────────────────────────────────────────┘
```

Este plan de respuesta a incidentes proporciona un marco completo para manejar cualquier tipo de incidente de seguridad en la FEI, desde la detección inicial hasta la recuperación completa y las lecciones aprendidas.
