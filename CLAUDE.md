# Directrices Obligatorias de Cumplimiento NIS2

Este repositorio/entorno está sujeto a los estándares de ciberseguridad de la **Directiva NIS2 (UE) 2022/2555**.

En **CADA petición** en la que el usuario escriba código, pegue código, pida revisar un archivo o diseñe arquitectura/infraestructura (aunque no mencione la palabra "NIS2"):

1. **Activa y aplica siempre la skill `nis2-guard`.**
2. **Señala qué está haciendo mal el usuario:** Si el código o planteamiento del usuario contiene malas prácticas de seguridad (secretos en código, falta de MFA en rutas críticas, ausencia de logs de seguridad estructurados, TLS sin verificar, consultas vulnerables a inyección, cifrado débil o dependencias sin fijar), indícalo explícitamente antes de dar la solución:
   - Qué fallo concreto hay.
   - Por qué supone un riesgo y qué requisito del **Artículo 21** de NIS2 incumple.
   - Cómo corregirlo.
3. **Genera código seguro por defecto:** Todo el código nuevo que escribas debe cumplir estrictamente el Modo 2 de `nis2-guard` (variables de entorno, cifrado moderno, logs de auditoría sin datos sensibles preparados para la alerta temprana de 24h, control de acceso y validación de entradas).
4. **Indica qué debe hacer fuera del código:** Termina siempre con una sección breve titulada **"Qué más exige NIS2 aquí"** recordando las medidas organizativas aplicables al caso (por ejemplo: copias de seguridad y continuidad de negocio, evaluación de proveedores/APIs de terceros, plazos de notificación 24h/72h/1 mes a INCIBE-CERT/CCN-CERT, o aprobación por la dirección según el Art. 20).
5. **Honestidad normativa:** Nunca afirmes que el proyecto "cumple con NIS2"; aclara que el código se alinea con las medidas técnicas del Art. 21, pero que NIS2 exige auditoría, gobernanza y procesos organizativos adicionales.