# Políticas de Seguridad de la Información - FEI

## 1. Política General de Seguridad de la Información

### 1.1 Propósito
Establecer el marco normativo para proteger los activos de información de la Facultad de Estadística e Informática (FEI), asegurando la confidencialidad, integridad y disponibilidad de los datos y sistemas.

### 1.2 Alcance
Aplica a todos los estudiantes, académicos, personal administrativo, contratistas y visitantes que tengan acceso a los recursos tecnológicos de la FEI.

### 1.3 Objetivos
- Proteger la información crítica de la institución
- Cumplir con regulaciones nacionales e internacionales
- Minimizar riesgos de seguridad cibernética
- Asegurar la continuidad de servicios académicos

### 1.4 Responsabilidades

#### Director de la FEI
- Aprobar políticas de seguridad
- Asignar recursos para implementación
- Supervisar cumplimiento general

#### Coordinador de TI
- Implementar controles técnicos
- Gestionar incidentes de seguridad
- Reportar métricas de seguridad

#### Jefe de Seguridad de la Información
- Desarrollar políticas específicas
- Realizar evaluaciones de riesgo
- Coordinar auditorías de seguridad

#### Personal Académico y Administrativo
- Cumplir con políticas establecidas
- Reportar incidentes de seguridad
- Participar en capacitaciones

#### Estudiantes
- Seguir políticas de uso aceptable
- Proteger credenciales de acceso
- Reportar actividades sospechosas

## 2. Política de Control de Acceso

### 2.1 Principios Fundamentales
- **Menor privilegio**: Acceso mínimo necesario para funciones
- **Segregación de funciones**: Separación de responsabilidades críticas
- **Autenticación fuerte**: Verificación robusta de identidad
- **Autorización granular**: Permisos específicos por recurso

### 2.2 Gestión de Identidades

#### 2.2.1 Cuentas de Usuario
- **Nomenclatura**: apellido.nombre@estudiantes.fei.edu o apellido.nombre@fei.edu
- **Ciclo de vida**: Creación, modificación, suspensión, eliminación
- **Revisión**: Trimestral para personal, semestral para estudiantes

#### 2.2.2 Contraseñas
- **Longitud mínima**: 12 caracteres
- **Complejidad**: Mayúsculas, minúsculas, números, símbolos
- **Vigencia**: 90 días para personal, 180 días para estudiantes
- **Historial**: No reutilizar últimas 12 contraseñas
- **Bloqueo**: 5 intentos fallidos = bloqueo 30 minutos

#### 2.2.3 Autenticación Multifactor (MFA)
- **Obligatorio para**: Personal administrativo, profesores, sistemas críticos
- **Métodos aceptados**: SMS, aplicación móvil, token hardware
- **Excepción temporal**: Solo con autorización del Director

### 2.3 Autorización de Acceso

#### 2.3.1 Clasificación de Recursos
| Nivel | Descripción | Ejemplos |
|-------|-------------|----------|
| **Público** | Información de dominio público | Sitio web institucional |
| **Interno** | Información de uso interno | Políticas, procedimientos |
| **Confidencial** | Información sensible | Expedientes estudiantiles |
| **Restringido** | Información altamente sensible | Datos financieros, investigación |

#### 2.3.2 Roles y Permisos
| Rol | Nivel de Acceso | Recursos Autorizados |
|-----|----------------|---------------------|
| **Estudiante** | Básico | Sistema académico (consulta), biblioteca digital |
| **Profesor** | Intermedio | Sistema académico (edición), plataforma virtual |
| **Coordinador** | Avanzado | Sistemas administrativos, reportes |
| **Administrador TI** | Completo | Infraestructura, configuraciones |
| **Director** | Ejecutivo | Todos los sistemas, datos estratégicos |

### 2.4 Procedimientos de Acceso

#### 2.4.1 Solicitud de Acceso
1. Llenar formulario FEI-ACC-001
2. Aprobación del supervisor directo
3. Validación por Coordinador de TI
4. Implementación en 24-48 horas

#### 2.4.2 Modificación de Acceso
1. Solicitud justificada por escrito
2. Aprobación según matriz de autorización
3. Implementación y notificación

#### 2.4.3 Revocación de Acceso
1. **Inmediata**: Separación del personal, incidente de seguridad
2. **Programada**: Fin de contrato, cambio de rol
3. **Verificación**: Confirmación de revocación completa

## 3. Política de Uso Aceptable

### 3.1 Uso Autorizado
Los recursos tecnológicos de la FEI deben utilizarse exclusivamente para:
- Actividades académicas y de investigación
- Funciones administrativas autorizadas
- Comunicación institucional apropiada

### 3.2 Uso Prohibido
Está estrictamente prohibido:
- Acceso no autorizado a sistemas o datos
- Instalación de software no aprobado
- Uso de recursos para actividades comerciales personales
- Descarga de contenido ilegal o inapropiado
- Actividades que puedan dañar la reputación institucional

### 3.3 Monitoreo y Auditoría
- La FEI se reserva el derecho de monitorear el uso de recursos
- Los logs de actividad se conservan por 12 meses
- Las auditorías se realizan trimestralmente
- Violaciones pueden resultar en medidas disciplinarias

### 3.4 Sanciones
| Tipo de Violación | Primera Vez | Reincidencia | Grave |
|-------------------|-------------|--------------|-------|
| **Menor** (uso inadecuado) | Advertencia verbal | Advertencia escrita | Suspensión 3 días |
| **Moderada** (software no autorizado) | Advertencia escrita | Suspensión 5 días | Suspensión 15 días |
| **Grave** (acceso no autorizado) | Suspensión 15 días | Separación temporal | Separación definitiva |

## 4. Política de Seguridad Perimetral

### 4.1 Arquitectura de Red
- **DMZ**: Servicios públicos aislados
- **Red Interna**: Recursos institucionales protegidos
- **Red de Gestión**: Administración y monitoreo
- **Segmentación**: VLANs por función y criticidad

### 4.2 Firewall Institucional

#### 4.2.1 Reglas Generales
- **Denegación por defecto**: Todo tráfico bloqueado inicialmente
- **Menor privilegio**: Solo puertos necesarios abiertos
- **Logging obligatorio**: Todas las conexiones registradas
- **Revisión mensual**: Evaluación de reglas activas

#### 4.2.2 Puertos Autorizados
| Puerto | Protocolo | Servicio | Origen | Destino |
|--------|-----------|----------|---------|---------|
| 80/443 | TCP | HTTP/HTTPS | Internet | DMZ Web |
| 22 | TCP | SSH | Red Gestión | Servidores |
| 25/587 | TCP | SMTP | Servidores | Internet |
| 53 | UDP/TCP | DNS | Red Interna | DNS Externos |
| 389/636 | TCP | LDAP/LDAPS | Red Interna | Servidor Auth |

### 4.3 Proxy Web
- **Filtrado de contenido**: Categorías bloqueadas (adult, malware, gambling)
- **Autenticación requerida**: Usuarios identificados
- **Límites de ancho de banda**: Por usuario y categoria
- **Logging completo**: URLs visitadas, tiempo, usuario

### 4.4 VPN Institucional
- **Cifrado mínimo**: AES-256
- **Protocolos permitidos**: OpenVPN, IPSec
- **Autenticación**: Usuario + certificado digital
- **Logs de conexión**: Fecha, hora, usuario, IP origen

## 5. Política de Respaldo y Recuperación

### 5.1 Estrategia de Respaldo
- **Regla 3-2-1**: 3 copias, 2 medios diferentes, 1 ubicación externa
- **Frecuencia**: Diaria para datos críticos, semanal para datos normales
- **Retención**: 30 días online, 12 meses offline, 7 años archivo
- **Cifrado**: AES-256 para todos los respaldos

### 5.2 Clasificación de Datos

#### 5.2.1 Datos Críticos (RPO: 1 hora, RTO: 4 horas)
- Base de datos de estudiantes
- Sistema de gestión académica
- Expedientes digitales
- Datos financieros

#### 5.2.2 Datos Importantes (RPO: 8 horas, RTO: 24 horas)
- Correo electrónico institucional
- Documentos administrativos
- Recursos de biblioteca digital
- Proyectos de investigación

#### 5.2.3 Datos Normales (RPO: 24 horas, RTO: 72 horas)
- Archivos de usuario
- Logs de sistema
- Documentos de trabajo
- Recursos multimedia

### 5.3 Procedimientos de Recuperación
1. **Declaración de desastre**: Autorización del Director
2. **Activación del equipo**: Notificación en 30 minutos
3. **Evaluación de daños**: Determinación de alcance
4. **Recuperación por prioridades**: Sistemas críticos primero
5. **Validación de integridad**: Verificación de datos restaurados
6. **Retorno a operación normal**: Procedimiento documentado

## 6. Política de Gestión de Incidentes

### 6.1 Definiciones
- **Incidente**: Evento que compromete o amenaza la seguridad
- **Violación**: Acceso no autorizado confirmado a datos
- **Compromiso**: Sistema bajo control de atacante
- **Interrupción**: Indisponibilidad no planificada de servicios

### 6.2 Clasificación de Incidentes

| Nivel | Descripción | Tiempo de Respuesta | Escalamiento |
|-------|-------------|-------------------|--------------|
| **Crítico** | Sistemas críticos comprometidos | 15 minutos | Director + Autoridades |
| **Alto** | Datos sensibles expuestos | 1 hora | Coordinador TI |
| **Medio** | Servicios parcialmente afectados | 4 horas | Administrador |
| **Bajo** | Actividad sospechosa detectada | 24 horas | Técnico |

### 6.3 Equipo de Respuesta a Incidentes (CSIRT-FEI)

#### 6.3.1 Roles
- **Líder de Incidentes**: Coordinación general
- **Analista Técnico**: Investigación y contención
- **Especialista Forense**: Preservación de evidencia
- **Coordinador de Comunicaciones**: Notificaciones
- **Enlace Legal**: Aspectos regulatorios

#### 6.3.2 Contactos de Emergencia
- **CSIRT-FEI**: csirt@fei.edu / (228) 842-1700 ext. 2500
- **Director FEI**: director@fei.edu / (228) 842-1700 ext. 2501
- **Coordinador TI**: ti@fei.edu / (228) 842-1700 ext. 2502

### 6.4 Procedimiento de Respuesta
1. **Detección y Reporte** (0-15 min)
2. **Clasificación inicial** (15-30 min)
3. **Contención inmediata** (30 min-2 horas)
4. **Investigación y análisis** (2-8 horas)
5. **Erradicación** (8-24 horas)
6. **Recuperación** (24-72 horas)
7. **Lecciones aprendidas** (1 semana)

## 7. Política de Capacitación y Concienciación

### 7.1 Programa de Capacitación

#### 7.1.1 Personal Nuevo
- **Inducción obligatoria**: Primera semana de trabajo
- **Temas**: Políticas básicas, uso aceptable, contraseñas
- **Duración**: 4 horas
- **Evaluación**: Examen con 80% mínimo aprobatorio

#### 7.1.2 Personal Existente
- **Capacitación anual**: Actualización de conocimientos
- **Temas especializados**: Según rol y responsabilidades
- **Modalidad**: Presencial y virtual
- **Seguimiento**: Registro de participación

#### 7.1.3 Estudiantes
- **Orientación semestral**: Políticas de uso de laboratorios
- **Recursos online**: Portal de seguridad estudiantil
- **Campañas de concienciación**: Mensual via correo/redes

### 7.2 Contenidos de Capacitación
- Políticas de seguridad institucionales
- Reconocimiento de phishing y malware
- Uso seguro de contraseñas y MFA
- Manejo seguro de información confidencial
- Reporte de incidentes de seguridad
- Tendencias actuales de ciberseguridad

### 7.3 Métricas de Efectividad
- **Participación**: >95% personal, >80% estudiantes
- **Aprovechamiento**: >80% en evaluaciones
- **Incidentes por factor humano**: Reducción 50% anual
- **Reportes de usuarios**: Incremento 25% anual

## 8. Cumplimiento y Auditoría

### 8.1 Marco Regulatorio
- **NIST Cybersecurity Framework 2.0**
- **ISO/IEC 27001:2022**
- **Ley Federal de Protección de Datos Personales (México)**
- **Normativas de la Universidad Veracruzana**

### 8.2 Auditorías de Seguridad

#### 8.2.1 Auditorías Internas
- **Frecuencia**: Semestral
- **Alcance**: Cumplimiento de políticas
- **Responsable**: Jefe de Seguridad
- **Reporte**: Director y Coordinador TI

#### 8.2.2 Auditorías Externas
- **Frecuencia**: Anual
- **Alcance**: Evaluación integral
- **Proveedor**: Firma especializada certificada
- **Seguimiento**: Plan de remediación

### 8.3 Indicadores de Cumplimiento
| Indicador | Meta | Frecuencia | Responsable |
|-----------|------|------------|-------------|
| Políticas actualizadas | 100% | Anual | Jefe Seguridad |
| Personal capacitado | >95% | Trimestral | RRHH |
| Incidentes resueltos en tiempo | >90% | Mensual | CSIRT |
| Vulnerabilidades críticas | 0 >30 días | Semanal | Admin TI |
| Copias de seguridad exitosas | >99% | Diario | Admin Backup |

## 9. Vigencia y Actualizaciones

### 9.1 Período de Vigencia
- **Fecha de entrada**: 1 de agosto de 2025
- **Vigencia**: 2 años
- **Revisión**: Anual o cuando sea necesario

### 9.2 Proceso de Actualización
1. **Propuesta de cambio**: Cualquier miembro puede proponer
2. **Evaluación técnica**: Jefe de Seguridad analiza impacto
3. **Aprobación**: Director autoriza cambios mayores
4. **Comunicación**: Notificación a toda la comunidad
5. **Implementación**: Plazo definido según complejidad

### 9.3 Control de Versiones
- **Versión actual**: 1.0
- **Historial de cambios**: Documentado en anexo
- **Distribución**: Portal institucional y correo electrónico

---

**Documento aprobado por:**
- Dr. [Nombre], Director de la FEI
- M.C. [Nombre], Coordinador de TI  
- Ing. [Nombre], Jefe de Seguridad de la Información

**Fecha de aprobación:** [Fecha]  
**Próxima revisión:** [Fecha + 1 año]
