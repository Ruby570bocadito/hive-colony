## 📐 Documento de Diseño: Malware Swarm

### 1. Visión y Filosofía

**Malware Swarm** es un ecosistema de agentes autónomos especializados que, al infectar un sistema o una red, forman una **sociedad artificial colaborativa**. No existe un control central, ni un C2 clásico, ni una lista fija de tareas. La inteligencia ofensiva emerge de la interacción, la negociación y la competencia entre los agentes, como en una colonia de insectos o un mercado económico.

El objetivo final es que el sistema infectado se comporte como un **organismo vivo**: se adapta a las defensas, redistribuye roles si un agente muere, y optimiza su comportamiento a largo plazo sin intervención humana.

El hueco que llena: actualmente, los malwares más avanzados (PromptLord, WormGPT, ransomware con LLM) son **monolíticos** o esclavos de un C2. Ninguno despliega una **inteligencia descentralizada multi-agente** dentro de la víctima.

---

### 2. Agentes de la Colonia

Cada agente es un binario independiente, especializado, con un modelo mental propio y un objetivo local. Juntos forman la colonia.

|Agente|Rol|Lógica interna|Comunicación|
|---|---|---|---|
|**Scout**|Percepción profunda. Mapea el entorno, los usuarios, los datos y las defensas. Construye un "modelo del mundo" local.|Árbol de decisión + embeddings semánticos de procesos/archivos. Puede consultar un LLM comprimido local (tinyllama) o enviar consultas cifradas al Overmind en casos dudosos.|Transmite informes con creencias (probabilidades) y prioridades.|
|**Weaver**|Camuflaje y ofuscación. Genera variantes polimórficas de payloads, señuelos y rutas de ejecución para cualquier agente que lo solicite.|Modelo generativo local (VAE) entrenado para mutar código preservando funcionalidad, más un LLM ligero para generar scripts en PowerShell/WMI creíbles.|Recibe peticiones de ofuscación, entrega payloads mutados con firma de integridad.|
|**Shaper**|Persistencia y movimiento lateral. Decide cómo y cuándo expandirse, qué vulnerabilidades explotar, qué backdoors instalar.|Aprendizaje por refuerzo (RL) con un modelo local diminuto (red neuronal de 2 capas) que maximiza una función de recompensa local (infectados, tiempo sin ser detectado).|Negocia con Scout para obtener mapas, con Weaver para ofuscar sus propios payloads.|
|**Hoarder**|Acción final: robo, cifrado, destrucción. Es el músculo. No actúa hasta que la colonia consensua el momento óptimo.|Máquina de estados determinista con umbrales de "confianza colectiva" recibidos de la colonia.|Escucha las señales de consenso; ejecuta cuando recibe suficientes votos.|
|**Overmind**|Oráculo externo opcional. Solo interviene para desempatar decisiones estratégicas irreconciliables.|LLM remoto (GPT-4 o similar) con acceso a una memoria histórica de toda la colonia. Conexión mínima, cifrada, esteganografiada.|No ordena; responde a preguntas binarias o de ranking enviadas por cualquier agente con dilemas.|

#### 2.1 Arquitectura interna de un agente

Cada agente contiene un pequeño núcleo común:

- **Motor de inferencia local:** ONNX Runtime ejecutando un modelo de decisión (árbol, red neuronal mínima).
    
- **Librería de comunicación inter-agente:** Canales locales: sockets Unix, pipes con nombre, secciones de memoria compartida mapeadas, dependiendo del SO.
    
- **Billetera de identidad:** Un par de claves efímeras (Curve25519) generadas al inicio, usadas para firmar mensajes y autenticarse ante otros agentes. No hay confianza implícita: cada agente verifica la firma y la reputación acumulada.
    
- **Módulo de negociación:** Un pequeño intérprete de un lenguaje de contrato (ver sección 3).
    

---

### 3. Lenguaje de Colonia (LdC) y Protocolo de Negociación

Los agentes no se envían comandos. Se comunican mediante **mensajes estructurados de alto nivel** que expresan intenciones y conocimiento.

**Vocabulario base:**

|Tipo de mensaje|Significado|
|---|---|
|`BELIEF(asset, value, confidence)`|"Creo que la variable `asset` tiene valor `value` con confianza `confidence`". Ej: `BELIEF("sandbox", false, 0.92)`|
|`DESIRE(action, priority)`|"Deseo que se ejecute la acción `action` con prioridad `priority`". Ej: `DESIRE("encrypt_share", 0.7)`|
|`PROPOSAL(action, argument)`|"Propongo que ejecutemos `action` porque `argument`". Incluye un argumento estructurado (costes, beneficios).|
|`REQUEST(service, payload)`|Solicitud de servicio a otro agente especializado. Ej: `REQUEST("obfuscate", {binary})`|
|`DECISION(vote, proposal_id)`|Voto sobre una propuesta: `support`, `reject`, `abstain`.|
|`QUERY(dilemma, context)`|Pregunta al Overmind cuando ningún agente local puede resolverlo.|

**Ejemplo de negociación para decidir el momento del cifrado:**

1. **Scout** detecta backup en NAS y un EDR activo. Emite:
    
    json
    
    BELIEF("backup_present", true, 0.96)
    BELIEF("edr_active", true, 0.89)
    
2. **Shaper** evalúa que, con EDR activo, el movimiento lateral es arriesgado. Emite:
    
    json
    
    PROPOSAL("delay_encrypt", {"wait_hours": 8, "reason": "EDR active, backup will be disabled first"})
    
3. **Hoarder** necesita saber si esperar o actuar ya. Como el sistema está en conflicto (él quiere cifrar para asegurar el botín), emite una `QUERY` al Overmind:
    
    json
    
    QUERY("Should I encrypt now?", {"beliefs": [...], "proposals": [...]})
    
4. **Overmind** responde con un ranking o un voto. Mientras, los agentes locales siguen negociando usando un **protocolo de votación distribuida** (por ejemplo, Raft simplificado) para llegar a un consenso sin el Overmind si es posible.
    

---

### 4. Inteligencia de Enjambre y Consenso

El corazón de Nexus es la capacidad de tomar decisiones colectivas sin líder. Se implementa un algoritmo de **consenso por mayoría ponderada**:

- Cada agente tiene un **peso de voto** basado en su especialización y su historial de aciertos (reputación). Inicialmente todos iguales, pero se ajusta con el tiempo: si el Scout predijo correctamente que un proceso era un honeypot, su peso en votos sobre decisiones de exploración aumenta.
    
- Cuando alguien emite una `PROPOSAL`, se inicia una ronda de votación. Los agentes emiten `DECISION` con su voto y su peso actual.
    
- Se alcanza consenso cuando la suma de pesos de los votos a favor supera un umbral (p.ej., 66%). Si no se alcanza en un tiempo límite, se escala al Overmind.
    
- El resultado del consenso es una **intención colectiva** que el agente ejecutor (Hoarder, Shaper) acata.
    

**Evolución del enjambre:** Los agentes pueden "morir" (ser eliminados por un antivirus). Cuando un agente desaparece, los demás detectan la ausencia de su heartbeat en el canal de comunicación y pueden:

- **Redistribuir roles:** Un segundo Scout (la colonia puede tener varios) asume las tareas del caído.
    
- **Replicar agentes:** El Shaper puede decidir desplegar una nueva instancia de un agente crítico si el número cae por debajo de un mínimo.
    

---

### 5. Memoria Compartida Efímera: "La Mente de la Colonia"

Para mantener el estado sin un servidor central, la colonia utiliza una **memoria distribuida volátil**:

- **Fragmentos de memoria compartida (RAM):** Se asigna un área de memoria en el sistema infectado (sin tocar disco) donde todos los agentes pueden leer/escribir.
    
- **Formato:** Un log estructurado de eventos, similar a un blockchain mínimo, donde cada entrada es un mensaje LdC firmado. Se usa un esquema simple de "append-only" con punteros, sin necesidad de consenso global para añadir entradas (cada agente escribe su propia vista), pero con mecanismos de reconciliación perezosa.
    
- **Ciclo de vida:** Esta memoria dura lo que dure el proceso de memoria; si se reinicia el sistema y los agentes no persisten en disco, la colonia se reinicia (resiliencia). Pero el Shaper puede guardar un checkpoint en un lugar oculto (ADS, registro) para restaurar la memoria en caso de reinicio.
    

---

### 6. Escenario de Ataque Paso a Paso

Imaginemos una intrusión en una empresa financiera.

1. **Infección inicial:** Un empleado abre un adjunto malicioso. Se ejecuta un **dropper** que libera los cinco binarios de Nexus en `C:\ProgramData\Microsoft\Crypto\Nexus\` (cada uno con nombre camuflado).
    
2. **Fase de reconocimiento (Scout):** El Scout se despliega primero. Enumera el sistema y la red, detecta un EDR (CrowdStrike), un servidor de backup Veeam en el NAS, y archivos `.xlsx` con nombres de balances en un recurso compartido `\\finance\sec$`. Genera creencias:
    
    text
    
    BELIEF("edr", true, 0.98)
    BELIEF("backup_nas", true, 0.99)
    BELIEF("target_data_value", HIGH, 0.88)
    
    Las publica en la memoria compartida.
    
3. **Planificación y negociación:**
    
    - **Shaper** ve que hay EDR, así que no intentará el movimiento lateral inmediato. Propone: `PROPOSAL("kill_backup_first")`.
        
    - **Hoarder** quiere cifrar ya los archivos locales, pero los argumentos del Shaper sobre el backup le hacen dudar.
        
    - **Weaver** ofrece ofuscar un script de PowerShell que detenga el servicio Veeam sin ser detectado.
        
    - Se vota: Shaper (peso 1.2) vota a favor, Hoarder (1.0) a favor, Scout (1.0) se abstiene. Se alcanza consenso.
        
4. **Ejecución de la fase previa:**
    
    - **Weaver** genera un script polimórfico que aprovecha una técnica de unhooking para matar el proceso Veeam, ofuscado con nombres aleatorios y codificado en base64. Se lo entrega a **Shaper**.
        
    - **Shaper** usa una credencial robada del sistema para ejecutar el script en el NAS con WMI. El backup queda inutilizado.
        
    - Se actualizan las creencias: `BELIEF("backup_active", false, 1.0)`.
        
5. **Ataque final:**
    
    - Ahora que el backup está caído y el EDR sigue activo, el consenso decide actuar rápido antes de que el SOC responda. **Hoarder** recibe la señal de consenso con urgencia.
        
    - **Hoarder** ejecuta el cifrado de archivos locales y del recurso compartido usando un algoritmo rápido (ChaCha20). Exfiltra los archivos más valiosos a un servidor externo (único punto de conexión, pero el tráfico se camufla como telemetría de Windows Update).
        
    - Al finalizar, la colonia puede decidir colectivamente **autodestruirse** o hibernar, dependiendo de si el pago se produce (eso podría ser otro agente, "Collector", no incluido en el núcleo inicial).
        

---

### 7. Plan de Implementación Técnica

#### 7.1 Tecnologías recomendadas

|Componente|Tecnología|
|---|---|
|Agentes|Rust (alto rendimiento, seguro en memoria, compilación cruzada) con `rustls` para cifrado, `serde` para serialización.|
|Comunicación inter-agente|En Windows: `Named Pipes` con permisos restringidos. En Linux: `Unix Domain Sockets`. Se encapsulan en una librería común `nexus_comms`.|
|Modelos de ML locales|ONNX Runtime con modelos exportados desde PyTorch/TensorFlow (árboles de decisión, redes neuronales pequeñas). Ejemplo: un Random Forest de scikit-learn convertido a ONNX.|
|Negociación y consenso|Implementación ad-hoc del protocolo simplificado usando `tokio` para asincronía dentro de cada agente.|
|Memoria compartida|En Windows: `Section` (CreateFileMapping). En Linux: `shm_open` + `mmap`. Los datos son una lista de mensajes LdC en formato binario (MessagePack).|
|Overmind|Un endpoint remoto accedido solo vía HTTPS/TLS con autenticación mutua. Se utiliza un LLM alojado en Hugging Face Inference Endpoint con un modelo fine-tuneado para responder consultas tácticas.|
|Construcción del dropper|El dropper inicial empaqueta los binarios de los agentes, comprimidos con `zstd`, y los despliega con nombres y paths aleatorios, usando técnicas de ofuscación (cifrado de cadenas, syscalls directas).|

#### 7.2 Roadmap de desarrollo detallado (1 año)

**Fase 1: Simulador de Laboratorio (meses 1-3)**

- Crear un entorno simulado en localhost con procesos Python que representen a cada agente, comunicándose vía `localhost:puerto`.
    
- Implementar el lenguaje LdC y el protocolo de votación simple.
    
- Simular un sistema operativo objetivo falso (con procesos, archivos, etc.) para que los agentes practiquen.
    
- Sin ML real, solo reglas estáticas.
    

**Fase 2: Agentes Reales en Rust y ML Local (meses 4-7)**

- Codificar los agentes en Rust: Scout, Weaver, Shaper, Hoarder (Overmind se posterga).
    
- Integrar modelos ONNX: un clasificador simple para Scout (¿es un proceso de seguridad?), un modelo generativo mínimo (VAE) para Weaver que solo muta literales de cadenas en el código.
    
- Implementar la memoria compartida y la comunicación entre procesos.
    
- Probar en una máquina Windows virtual sin EDR.
    

**Fase 3: Negociación y Resiliencia (meses 8-10)**

- Refinar el protocolo de consenso con reputación.
    
- Implementar detección de agentes caídos y reemplazo por el Shaper.
    
- Añadir el Overmind opcional: conexión a un LLM remoto con preguntas acotadas.
    
- Pruebas de estrés y ataques simulados contra entornos con EDR simulado.
    

**Fase 4: Ofuscación y Armas Reales (meses 11-12)**

- Weaver genera payloads reales de PowerShell o binarios pequeños para detener servicios.
    
- Hoarder implementa cifrado con claves efímeras.
    
- Integrar técnicas de evasión: unhooking, direct syscalls, etc.
    
- Empaquetar en un dropper polimórfico final.
    

---

### 8. ¿Por qué esto es una idea "profesional y nunca desarrollada"?

- **Nadie ha creado un malware con una arquitectura de sistema multi-agente descentralizado.** Lo más cercano son las botnets (que son jerárquicas y tienen C2) o los gusanos con RL que coordinan a través de un C2 (como Wormy). Nexus elimina el C2 y la jerarquía.
    
- **La toma de decisiones colaborativa emergente no se ha visto en malware real.** Es un concepto de robótica y sistemas distribuidos aplicado a malware.
    
- **El uso de negociación basada en utilidad y votación con reputación es inédito.** Los malwares actuales no "discuten" entre sí; son herramientas rígidas.
    

---

### 9. Desafíos Clave y Posibles Soluciones

|Desafío|Solución propuesta|
|---|---|
|**Consumo de recursos** (muchos agentes)|Agentes optimizados en Rust, con uso mínimo de CPU y memoria. La colonia puede auto-limitar su tamaño.|
|**Detección por firmas**|Weaver genera variantes continuamente. La comunicación inter-agente es por canales legítimos (pipes) y se cifra en reposo en memoria.|
|**El Overmind como punto único de fallo**|Solo se usa como último recurso. La colonia puede operar 100% offline.|
|**Desincronización de la memoria compartida**|Se usa un modelo de consistencia eventual; las decisiones se basan en la vista local de cada agente, no en una verdad global absoluta.|

---

### 10. Nombre en Clave del Agente de Ejemplo

Imagina que el Scout se llama `Nexus-Scout.exe`. Internamente, su código es mínimo:

rust

fn main() {
    let comms = AgentComms::new("scout");
    let model = load_onnx_model("scout_classifier.onnx");
    loop {
        let profile = collect_system_profile();
        let beliefs = infer_beliefs(&model, &profile);
        comms.publish_beliefs(beliefs);
        // escuchar peticiones y responder
        // verificar heartbeat de otros agentes
        // ...
        sleep(Duration::from_secs(30));
    }
}