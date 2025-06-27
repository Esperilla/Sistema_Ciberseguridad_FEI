# Análisis de Riesgos - Facultad de Estadística e Informática

## 1. Identificación de Activos

### Activos Críticos de la FEI

| ID | Activo | Tipo | Descripción | Valor |
|----|--------|------|-------------|-------|
| A01 | Sistema de Gestión Académica | Software | Plataforma de inscripciones, calificaciones y expedientes | Alto |
| A02 | Base de Datos de Estudiantes | Datos | Información personal y académica de estudiantes | Alto |
| A03 | Servidores de Aplicaciones Web | Hardware | Infraestructura que aloja servicios críticos | Alto |
| A04 | Red de Datos Institucional | Infraestructura | Conectividad interna y externa | Alto |
| A05 | Sistema de Correo Electrónico | Software | Comunicación institucional | Medio |
| A06 | Plataforma de Educación Virtual | Software | Moodle o similar para clases en línea | Alto |
| A07 | Sistema de Biblioteca Digital | Software | Repositorio de recursos académicos | Medio |
| A08 | Equipos de Cómputo de Laboratorios | Hardware | Computadoras para prácticas estudiantiles | Medio |
| A09 | Sistema de Backup y Respaldos | Software/Hardware | Copias de seguridad de datos críticos | Alto |
| A10 | Sistema de Videoconferencias | Software | Plataformas para clases remotas | Medio |
| A11 | Documentos Administrativos | Datos | Políticas, procedimientos, reportes | Medio |
| A12 | Código Fuente de Proyectos | Datos | Desarrollos internos y proyectos estudiantiles | Bajo |

## 2. Identificación de Amenazas

### Amenazas Técnicas

| ID | Amenaza | Descripción | Fuente |
|----|---------|-------------|---------|
| T01 | Malware | Virus, ransomware, trojanos | Externa/Interna |
| T02 | Ataques de Phishing | Engaños para obtener credenciales | Externa |
| T03 | Ataques DDoS | Denegación de servicio distribuida | Externa |
| T04 | Inyección SQL | Explotación de vulnerabilidades web | Externa |
| T05 | Cross-Site Scripting (XSS) | Ataques a aplicaciones web | Externa |
| T06 | Acceso no autorizado | Intrusión a sistemas | Externa/Interna |
| T07 | Escalamiento de privilegios | Abuso de permisos del sistema | Interna |
| T08 | Fuga de datos | Exposición no autorizada de información | Interna/Externa |
| T09 | Man-in-the-Middle | Interceptación de comunicaciones | Externa |
| T10 | APT (Advanced Persistent Threat) | Ataques sofisticados y prolongados | Externa |

### Amenazas Físicas

| ID | Amenaza | Descripción |
|----|---------|-------------|
| F01 | Falla de energía eléctrica | Interrupción del suministro eléctrico |
| F02 | Incendio | Daño por fuego a infraestructura |
| F03 | Inundación | Daño por agua |
| F04 | Robo de equipos | Sustracción física de hardware |
| F05 | Acceso físico no autorizado | Intrusión a instalaciones |

### Amenazas Humanas

| ID | Amenaza | Descripción |
|----|---------|-------------|
| H01 | Usuario malintencionado interno | Empleado o estudiante con intenciones maliciosas |
| H02 | Error humano | Configuraciones incorrectas, eliminación accidental |
| H03 | Ingeniería social | Manipulación psicológica para obtener información |
| H04 | Falta de capacitación | Personal sin conocimientos de seguridad |

## 3. Identificación de Vulnerabilidades

### Vulnerabilidades Técnicas

| ID | Vulnerabilidad | Descripción | Referencia CVE |
|----|----------------|-------------|----------------|
| V01 | Sistemas desactualizados | Software sin parches de seguridad | CVE-2023-* |
| V02 | Contraseñas débiles | Políticas de passwords inadecuadas | CWE-521 |
| V03 | Configuraciones por defecto | Servicios con configuración insegura | CWE-1188 |
| V04 | Falta de cifrado | Datos transmitidos sin protección | CWE-319 |
| V05 | Logs insuficientes | Falta de auditoría y monitoreo | CWE-778 |
| V06 | Backup sin cifrar | Respaldos vulnerables | CWE-312 |
| V07 | Red sin segmentar | Falta de VLANs y controles de acceso | - |
| V08 | Puertos innecesarios abiertos | Servicios expuestos sin necesidad | CWE-1327 |

### Vulnerabilidades Organizacionales

| ID | Vulnerabilidad | Descripción |
|----|----------------|-------------|
| O01 | Falta de políticas de seguridad | Ausencia de normativas claras |
| O02 | Personal sin capacitar | Falta de conciencia en seguridad |
| O03 | Procesos no documentados | Procedimientos informales |
| O04 | Falta de control de acceso | Permisos mal gestionados |

## 4. Matriz de Riesgos

### Criterios de Evaluación

**Impacto:**
- Alto (3): Interrupción total de servicios críticos, pérdida masiva de datos
- Medio (2): Interrupción parcial, pérdida limitada de datos
- Bajo (1): Impacto mínimo en operaciones

**Probabilidad:**
- Alta (3): Muy probable que ocurra (>70%)
- Media (2): Moderadamente probable (30-70%)
- Baja (1): Poco probable (<30%)

**Nivel de Riesgo = Impacto × Probabilidad**

### Matriz de Análisis de Riesgos

| Activo | Amenaza | Vulnerabilidad | Impacto | Probabilidad | Riesgo | Prioridad |
|--------|---------|----------------|---------|--------------|---------|-----------|
| A01 - Sistema Gestión Académica | T01 - Malware | V01 - Sistemas desactualizados | 3 | 2 | 6 | Alto |
| A02 - BD Estudiantes | T08 - Fuga de datos | V04 - Falta de cifrado | 3 | 2 | 6 | Alto |
| A03 - Servidores Web | T03 - DDoS | V08 - Puertos abiertos | 2 | 3 | 6 | Alto |
| A01 - Sistema Gestión | T02 - Phishing | V02 - Contraseñas débiles | 3 | 2 | 6 | Alto |
| A04 - Red Institucional | T06 - Acceso no autorizado | V07 - Red sin segmentar | 2 | 2 | 4 | Medio |
| A06 - Plataforma Virtual | T04 - Inyección SQL | V03 - Config. por defecto | 2 | 2 | 4 | Medio |
| A09 - Sistema Backup | T08 - Fuga de datos | V06 - Backup sin cifrar | 3 | 1 | 3 | Medio |
| A05 - Correo Electrónico | T02 - Phishing | O02 - Personal sin capacitar | 2 | 2 | 4 | Medio |
| A08 - PCs Laboratorio | T01 - Malware | V01 - Sistemas desactualizados | 1 | 3 | 3 | Bajo |
| A07 - Biblioteca Digital | T05 - XSS | V03 - Config. por defecto | 1 | 2 | 2 | Bajo |

## 5. Tratamiento de Riesgos

### Controles Propuestos

#### Riesgos de Prioridad Alta

**R01: Sistema Gestión Académica vs Malware**
- **Control**: Implementar antimalware empresarial + EDR
- **Mapeo NIST**: PR.PT-1, DE.CM-4
- **Responsable**: Administrador de TI
- **Plazo**: 30 días

**R02: Base de Datos vs Fuga de Datos**
- **Control**: Cifrado de BD en reposo y tránsito (AES-256)
- **Mapeo NIST**: PR.DS-1, PR.DS-2
- **Responsable**: DBA
- **Plazo**: 45 días

**R03: Servidores Web vs DDoS**
- **Control**: Firewall con protección DDoS + CDN
- **Mapeo NIST**: PR.PT-4, DE.CM-1
- **Responsable**: Administrador de Red
- **Plazo**: 60 días

**R04: Sistema Gestión vs Phishing**
- **Control**: Autenticación multifactor (MFA)
- **Mapeo NIST**: PR.AC-1, PR.AC-7
- **Responsable**: Administrador de TI
- **Plazo**: 30 días

#### Riesgos de Prioridad Media

**R05: Red Institucional vs Acceso no autorizado**
- **Control**: Segmentación de red (VLANs) + NAC
- **Mapeo NIST**: PR.AC-4, PR.AC-5
- **Responsable**: Administrador de Red
- **Plazo**: 90 días

**R06: Plataforma Virtual vs Inyección SQL**
- **Control**: WAF + code review + input validation
- **Mapeo NIST**: PR.PT-1, DE.CM-1
- **Responsable**: Desarrollador/Admin
- **Plazo**: 60 días

## 6. Plan de Monitoreo y Revisión

### Indicadores de Riesgo (KRIs)

| Indicador | Métrica | Frecuencia | Responsable |
|-----------|---------|------------|-------------|
| Intentos de acceso fallidos | >100 por día | Diario | SOC/Admin |
| Parches pendientes | >30 días sin aplicar | Semanal | Admin TI |
| Usuarios sin MFA | >5% del total | Mensual | Admin Seguridad |
| Incidentes de malware | >1 por mes | Mensual | SOC |
| Vulnerabilidades críticas | >0 sin remediar | Quincenal | Equipo Seguridad |

### Cronograma de Revisión

- **Revisión operativa**: Semanal
- **Revisión táctica**: Mensual  
- **Revisión estratégica**: Trimestral
- **Evaluación anual**: Anual

## 7. Mapeo con NIST CSF 2.0

### Función IDENTIFICAR (ID)
- ID.AM: Gestión de activos - Inventario actualizado
- ID.RA: Evaluación de riesgos - Esta matriz de riesgos
- ID.RM: Estrategia de gestión de riesgos

### Función PROTEGER (PR)
- PR.AC: Control de acceso - MFA, segmentación
- PR.DS: Seguridad de datos - Cifrado, backup
- PR.PT: Tecnologías de protección - Firewall, antimalware

### Función DETECTAR (DE)
- DE.CM: Monitoreo continuo - SIEM, IDS
- DE.AE: Eventos de anomalías - Alertas automatizadas

### Función RESPONDER (RS)
- RS.RP: Planificación de respuesta - Procedimientos de incidentes
- RS.CO: Comunicaciones - Plan de comunicación

### Función RECUPERAR (RC)
- RC.RP: Planificación de recuperación - DRP/BCP
- RC.IM: Mejoras - Lecciones aprendidas

## 8. Conclusiones y Recomendaciones

### Hallazgos Principales
1. **6 riesgos de prioridad alta** requieren atención inmediata
2. **Falta de cifrado** es la vulnerabilidad más crítica
3. **Capacitación del personal** es fundamental
4. **Segmentación de red** mejorará significativamente la postura

### Recomendaciones Inmediatas
1. Implementar MFA en todos los sistemas críticos
2. Establecer programa de actualización de parches
3. Configurar monitoreo centralizado (SIEM)
4. Desarrollar programa de concienciación en seguridad

### Inversión Requerida
- **Tecnología**: Aproximadamente $1,000,000,000 MXN
- **Capacitación**: $200,000 MXN
- **Personal adicional**: 1 especialista en seguridad
- **Tiempo de implementación**: 6-12 meses
