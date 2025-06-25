# Proyecto Integrador Final – Ciberseguridad para la Facultad de Estadística e Informática

**Universidad Veracruzana / Facultad de Estadística e Informática**  
**Licenciatura en Redes y Servicios de Cómputo**  
**Experiencia Educativa Ciberseguridad**  
**Periodo febrero-julio 2025**

## Nombre del Proyecto

**Diseño e Implementación de un Sistema Integral de Ciberseguridad para la Facultad de Estadística e Informática (FEI) basado en el NIST Cybersecurity Framework 2.0**

## Objetivos Generales

1. Aplicar el NIST CSF 2.0 para definir políticas, procedimientos y controles técnicos alineados a los objetivos de seguridad institucionales.
2. Desarrollar la arquitectura de seguridad de la FEI basada en la gestión del riesgo.
3. Implementar y configurar controles técnicos de seguridad en un entorno simulado.
4. Documentar un SGSI institucional alineado al marco de NIST, con enfoque en la mejora continua.

## Componentes del Proyecto

### 1. Aplicación del NIST CSF 2.0

- **Identificar**: Contexto organizacional, activos críticos, perfiles de riesgo.
- **Proteger**: Políticas de seguridad, gestión de identidades, firewall, proxy, VPN.
- **Detectar**: Configuración de IDS/IPS, bitácoras y SIEM.
- **Responder**: Plan de respuesta a incidentes, procedimientos de escalamiento.
- **Recuperar**: Estrategias de respaldo, lecciones aprendidas, continuidad del negocio.

### 2. Definición de Políticas y Procedimientos

Incluye políticas de acceso, manejo de información, uso aceptable, seguridad perimetral, etc.

### 3. Desarrollo e Implementación de Controles

- Firewall
- Proxy
- IDS/IPS
- SIEM
- VPN
- Honeypot
- Bitácoras

### 4. Documentación y Evidencias

Debe incluir documentación, evidencias técnicas, scripts, configuraciones, capturas de pantalla.

## Metodología de Trabajo

1. Evaluación de riesgos
2. Diseño de arquitectura de seguridad
3. Implementación y configuración
4. Pruebas funcionales y simulación de incidentes
5. Documentación final y propuesta de mejora

## Entregables por Equipo

- Documento (.pdf o .odt)
- Evidencia de implementación (archivo tarball con código, configuraciones, bitácoras)
- Bitácora de trabajo del equipo

## Administración de Riesgos y Análisis de Amenazas

La gestión de riesgos es un componente fundamental del proyecto, alineado a estándares internacionales como ISO/IEC 27005, NIST SP 800-30 y el propio NIST CSF 2.0.

La administración de riesgos incluirá los siguientes elementos clave:

1. **Identificación de Activos**: Recursos tecnológicos, datos críticos y servicios institucionales de la FEI.
2. **Identificación de Amenazas**: Considerar amenazas físicas, técnicas y humanas (insider, malware, APT, errores de configuración).
3. **Identificación de Vulnerabilidades**: Basado en CVE, CWE, controles de configuración, obsolescencia.
4. **Evaluación de Impacto y Probabilidad**: Usando matrices de riesgo y criterios cuantitativos/cualitativos.
5. **Estimación del Nivel de Riesgo**: Clasificación de riesgos (alto, medio, bajo) con priorización.
6. **Tratamiento de Riesgos**: Selección de controles para mitigar, transferir, aceptar o evitar el riesgo.
7. **Seguimiento y revisión**: Mejora continua del tratamiento de riesgos.

## Plan de Respuesta a Incidentes de Seguridad de la Información

El plan de respuesta se basa en las recomendaciones del NIST SP 800-61r2 y está diseñado para abordar incidentes de manera efectiva y oportuna.

### Fases del Plan:

1. **Preparación**: Definición de roles, procedimientos, herramientas y comunicación.
2. **Detección y análisis**: Monitoreo de alertas, correlación de eventos, análisis de impacto.
3. **Contención, erradicación y recuperación**: Aislamiento del incidente, limpieza de sistemas, restauración segura.
4. **Post-mortem**: Documentación, lecciones aprendidas, ajuste de políticas y controles.

## Plan de Recuperación ante Desastres (DRP)

Este plan se basa en los lineamientos de ISO 22301 y NIST SP 800-34 para asegurar la continuidad operativa de la FEI ante eventos disruptivos.

### Componentes del DRP:

1. **Análisis de Impacto al Negocio (BIA)**: Identificar funciones críticas y tiempo máximo de recuperación (RTO/RPO).
2. **Estrategias de recuperación**: Respaldos, redundancia, infraestructura alternativa.
3. **Plan de comunicación**: Contactos clave, procedimientos internos y externos.
4. **Procedimientos de recuperación**: Pasos para restaurar operaciones técnicas y académicas.
5. **Pruebas y mantenimiento del DRP**: Simulacros regulares y actualizaciones del plan.

## Evaluación del Proyecto

La evaluación del proyecto se divide en tres bloques principales, cada uno con un peso específico en la calificación final. El objetivo es asegurar una valoración integral que incluya el análisis, desarrollo y presentación del trabajo.

| Bloque de Evaluación | Porcentaje |
|----------------------|------------|
| Planeación y análisis de riesgos | 30% |
| Desarrollo técnico e implementación de controles | 40% |
| Documentación, evidencias y presentación del proyecto | 30% |

### Entregables Considerados

- Documento del SGSI con políticas, planes y análisis de riesgos.
- Evidencias técnicas de implementación: scripts, configuraciones, capturas de pantalla.
- Bitácora detallada de actividades.
- Plan de respuesta a incidentes y plan de recuperación ante desastres.
- Presentación oral o escrita del proyecto final (opcional según docente).

## Anexos: Plantillas y Guías para el Desarrollo del Proyecto

### Plantilla de Análisis de Riesgos

Esta plantilla debe utilizarse para documentar los activos críticos, las amenazas y vulnerabilidades asociadas, el análisis de impacto y probabilidad, y las medidas de control propuestas.

**Campos obligatorios:**

- **Activo**: Nombre del recurso o servicio tecnológico.
- **Valor del Activo**: Relevancia del activo (Alto, Medio, Bajo).
- **Amenaza**: Evento potencial que puede causar daño (ej. malware, acceso no autorizado).
- **Vulnerabilidad**: Debilidad que podría ser explotada por la amenaza.
- **Impacto**: Consecuencia si se materializa el riesgo (Alto, Medio, Bajo).
- **Probabilidad**: Ocurrencia esperada del riesgo (Alta, Media, Baja).
- **Nivel de Riesgo**: Resultado del análisis (ej. fórmula Impacto x Probabilidad).
- **Control Propuesto**: Medida para mitigar o eliminar el riesgo.

### Plantilla de Plan de Respuesta a Incidentes

Esta plantilla debe seguirse para la creación de un plan que permita a la organización responder efectivamente a incidentes de seguridad.

**Campos:**

- **Tipo de Incidente**: Clasificación (Ej. DoS, Phishing, Intrusión).
- **Detectado por**: Sistema o usuario que detectó el incidente.
- **Fecha y Hora de Detección**: Registro preciso.
- **Impacto Estimado**: Sistemas o datos afectados.
- **Contención Inmediata**: Acciones rápidas tomadas.
- **Plan de Erradicación**: Eliminación de amenazas.
- **Plan de Recuperación**: Restauración de sistemas y servicios.
- **Responsable del Seguimiento**: Persona o equipo asignado.
- **Comunicación**: Plan para informar a partes interesadas.
- **Lecciones Aprendidas**: Mejora continua post incidente.

### Plantilla de Plan de Recuperación ante Desastres

Este documento debe emplearse para asegurar la continuidad de operaciones esenciales en caso de eventos disruptivos mayores.

**Elementos esenciales:**

- **Función Crítica**: Servicio o actividad clave para la operación.
- **Responsable del Proceso**: Encargado de la función.
- **Análisis de Impacto**: Consecuencias por pérdida del servicio.
- **Tiempo Máximo de Interrupción Permitido (RTO)**: Tiempo límite para recuperación.
- **Objetivo de Punto de Recuperación (RPO)**: Pérdida máxima de datos aceptable.
- **Estrategia de Recuperación**: Acciones para volver a operar (ej. respaldo, sitio alterno).
- **Recursos Necesarios**: Infraestructura, datos, personal.
- **Pruebas de Validación**: Periodicidad y responsables.
- **Actualización del Plan**: Responsable y frecuencia de revisión.

## Rúbrica de Evaluación del Proyecto Integrador

La siguiente rúbrica detalla los criterios con los que será evaluado el proyecto final. Cada aspecto se evalúa con base en su calidad, profundidad técnica, documentación, y evidencia entregada.

| Elemento Evaluado | Excelente (90-100) | Bueno (80-89) | Regular (70-79) | Insuficiente (<70) |
|-------------------|-------------------|---------------|-----------------|-------------------|
| **Planeación y análisis de riesgos** | Incluye identificación de activos, amenazas, vulnerabilidades, impactos y controles. Matriz bien documentada con estándares internacionales. | Incluye matriz con activos, amenazas y algunos controles. Buena estructura. | Matriz incompleta o con poca profundidad en el análisis. | Falta el análisis o contiene errores conceptuales graves. |
| **Definición de políticas de seguridad** | Políticas claras, completas, alineadas con NIST y adaptadas a la FEI. Incluyen responsables y sanciones. | Políticas adecuadas pero generales o con omisiones menores. | Políticas confusas o poco aplicables al contexto. | No hay políticas o son irrelevantes. |
| **Desarrollo técnico de controles (Firewall, Proxy, IDS/IPS, etc.)** | Controles bien implementados, funcionales, con evidencias, pruebas y documentación clara. | Controles implementados con funcionamiento parcial o sin pruebas detalladas. | Controles incompletos o con errores funcionales. | Controles no implementados o fallidos. |
| **Plan de respuesta a incidentes** | Incluye todos los elementos recomendados por NIST SP 800-61r2. Detallado, aplicable, probado. | Incluye elementos básicos del plan, bien estructurado. | Plan superficial o genérico, poco adaptado al contexto. | No se presenta un plan de respuesta válido. |
| **Plan de recuperación ante desastres (DRP)** | Contempla BIA, RTO, RPO, comunicación, pruebas y mantenimiento. Alineado con ISO 22301. | DRP básico con elementos principales descritos correctamente. | Plan incompleto o con poca aplicabilidad práctica. | No se entrega o no sigue ninguna metodología reconocida. |
| **Documentación y evidencias** | Documentación clara, profesional, bien estructurada. Evidencias completas (scripts, capturas, configuraciones). | Documentación adecuada con evidencias suficientes. | Documentación parcial o desorganizada. | Falta documentación o evidencias esenciales. |
| **Bitácora de trabajo** | Registro continuo de actividades, responsables, fechas y avances. Incluye lecciones aprendidas. | Registro funcional pero con algunos vacíos o sin seguimiento continuo. | Bitácora poco detallada o desactualizada. | No se entrega bitácora o no refleja el desarrollo real del proyecto. |

## Rúbrica Detallada: Desarrollo Técnico e Implementación de Controles

Esta rúbrica evalúa la calidad, funcionalidad y documentación de los controles técnicos implementados por los equipos como parte del proyecto. Cada control tiene su propio criterio de evaluación con énfasis en la correcta configuración, evidencia funcional y alineación con los objetivos del NIST CSF 2.0.

| Control de Seguridad | Excelente (90-100) | Bueno (80-89) | Regular (70-79) | Insuficiente (<70) |
|---------------------|-------------------|---------------|-----------------|-------------------|
| **Firewall** | Reglas configuradas correctamente con lógica clara. Evidencias de pruebas y documentación técnica completa. | Reglas configuradas y funcionales. Evidencias parciales. | Configuración básica o con errores. Falta documentación. | No se implementó o la configuración es incorrecta. |
| **Proxy** | Configurado correctamente. Aplica filtros de contenido, registro de accesos, y políticas de uso. | Implementado con configuración funcional básica. | Configuración parcial o sin evidencia funcional clara. | No implementado o inoperante. |
| **IDS/IPS** | Detecta y reporta actividad maliciosa. Firmas actualizadas y configuraciones optimizadas. | Detecta actividad básica. Configuración funcional. | Instalado pero sin pruebas o sin alertas registradas. | No instalado o no operativo. |
| **SIEM** | Recolecta, correlaciona y presenta alertas relevantes. Visualización clara y centralizada. | Recolecta logs y presenta eventos básicos. Visualización parcial. | SIEM básico, sin correlación ni visualización adecuada. | No se implementó o está inactivo. |
| **VPN** | Configuración segura. Acceso remoto probado. Buen manejo de certificados y cifrado. | Configurada y funcional, con pruebas mínimas. | Configuración parcial o sin validación de acceso. | No implementada o insegura. |
| **Honeypot** | Simulación creíble de servicios. Evidencias de intentos de intrusión capturados. | Honeypot funcional, con algunos eventos registrados. | Configuración básica sin eventos detectados. | No implementado o no funcional. |
| **Bitácoras** | Centralización y análisis de logs funcional. Evidencias completas de uso en todos los servicios. | Bitácoras habilitadas, con registros disponibles. | Registros parciales o sin análisis. | Sin bitácoras funcionales o no habilitadas. |

## Rúbrica Detallada: Planeación y Análisis de Riesgos

Esta rúbrica evalúa la calidad y exhaustividad de la planeación inicial del proyecto, especialmente en lo referente al análisis de riesgos, conforme a las metodologías del NIST SP 800-30, ISO/IEC 27005 y el marco NIST CSF 2.0.

| Elemento Evaluado | Excelente (90-100) | Bueno (80-89) | Regular (70-79) | Insuficiente (<70) |
|-------------------|-------------------|---------------|-----------------|-------------------|
| **Identificación de activos** | Listado detallado, clasificado por criticidad y contexto institucional. Bien documentado. | Activos identificados correctamente, pero sin clasificar o justificar. | Listado incompleto o sin justificación. | Sin identificar activos o mal elaborado. |
| **Identificación de amenazas y vulnerabilidades** | Amenazas y vulnerabilidades detalladas, específicas y contextualizadas. Uso de fuentes como CVE/CWE. | Listados generales pero adecuados para los activos. | Amenazas poco detalladas o sin conexión clara con los activos. | No se identifican amenazas reales o están mal formuladas. |
| **Matriz de riesgos (impacto, probabilidad, nivel de riesgo)** | Matriz clara, con criterios definidos. Riesgos priorizados correctamente. | Matriz adecuada pero sin priorización o con criterios implícitos. | Matriz confusa o con errores conceptuales. | Matriz ausente o inadecuada. |
| **Controles propuestos ante los riesgos** | Controles coherentes, realistas y alineados al nivel de riesgo. Mapeo con NIST CSF. | Controles adecuados pero con poca justificación. | Controles propuestos vagos o genéricos. | No se proponen controles o no corresponden a los riesgos. |
| **Documentación y presentación del análisis de riesgos** | Documento profesional, bien estructurado, con lenguaje técnico apropiado. | Documento adecuado, aunque con áreas de mejora en redacción o estructura. | Documento incompleto o desorganizado. | Presentación deficiente o ausente. |

## Rúbrica Detallada: Documentación, Evidencias y Presentación del Proyecto

Esta rúbrica evalúa la calidad de la documentación técnica, la completitud de las evidencias de implementación, y la claridad en la presentación final del proyecto. Se valora la organización, precisión, y profesionalismo de los entregables.

| Elemento Evaluado | Excelente (90-100) | Bueno (80-89) | Regular (70-79) | Insuficiente (<70) |
|-------------------|-------------------|---------------|-----------------|-------------------|
| **Guías de instalación y configuración** | Documentadas paso a paso, con comandos, capturas y explicaciones claras. | Guías funcionales pero sin detalle completo o sin capturas. | Guías básicas o con errores de estructura. | Falta documentación técnica o es incomprensible. |
| **Evidencias funcionales (capturas, logs, scripts)** | Capturas organizadas, scripts funcionales, logs completos y explicados. | Evidencias presentes pero no siempre explicadas o documentadas. | Evidencias dispersas o sin relación clara con el desarrollo. | No se presentan evidencias funcionales o están incompletas. |
| **Organización de archivos entregables** | Estructura clara, jerarquizada por control o componente. Nombres coherentes. | Organización básica con pocos errores. | Desorden parcial o faltan archivos clave. | Archivo general desorganizado o incompleto. |
| **Bitácora de trabajo** | Bitácora detallada con fechas, actividades, responsables y evidencias. | Bitácora funcional pero con algunas lagunas. | Bitácora parcial o poco descriptiva. | Falta bitácora o no aporta información útil. |
| **Presentación final del proyecto (oral o escrita)** | Presentación clara, técnica, con dominio del contenido y respuestas correctas. | Presentación adecuada con buena explicación general. | Presentación incompleta o con dificultades de comprensión. | Presentación confusa o sin preparación visible. |