#!/usr/bin/env python3
"""binparse - minimal PE / ELF parser written from scratch (stdlib only).

Shows: headers, sections (with Shannon entropy), imports, exports.
Usage:  python binparse.py <file> [--json]
"""
import argparse
import hashlib
import json
import math
import struct
import sys
from collections import Counter


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def cstr(data: bytes, off: int, limit: int = 512) -> str:
    """Read NUL-terminated ASCII string at offset (bounded)."""
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + limit)
    if end == -1:
        end = min(off + limit, len(data))
    return data[off:end].decode("ascii", errors="replace")


def unpack(fmt: str, data: bytes, off: int):
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        raise ValueError(f"truncated file: need {size} bytes at 0x{off:x}")
    return struct.unpack_from(fmt, data, off)


def verdict(e: float) -> str:
    if e > 7.2:
        return "packed/encrypted?"
    if e > 6.8:
        return "high"
    return ""


# --------------------------------------------------------------------------
# analysis: imphash + heuristics
# --------------------------------------------------------------------------
def imphash(imports: dict):
    """Import hash (same scheme as pefile/VirusTotal, minus ordinal lookup tables)."""
    parts = []
    for dll, funcs in imports.items():
        base = dll.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if base.endswith(ext):
                base = base[:-len(ext)]
        for fn in funcs:
            fn = f"ord{fn[1:]}" if fn.startswith("#") else fn
            parts.append(f"{base}.{fn.lower()}")
    return hashlib.md5(",".join(parts).encode()).hexdigest() if parts else None


# group -> (APIs, min distinct hits to report)
API_GROUPS = {
    "process injection": ({"virtualallocex", "writeprocessmemory", "createremotethread",
                           "ntunmapviewofsection", "queueuserapc", "setthreadcontext",
                           "ntwritevirtualmemory", "rtlcreateuserthread"}, 2),
    "anti-debug": ({"isdebuggerpresent", "checkremotedebuggerpresent",
                    "ntqueryinformationprocess", "outputdebugstringa",
                    "ntsetinformationthread", "ptrace"}, 1),
    "dynamic API resolving": ({"getprocaddress", "loadlibrarya", "loadlibraryw",
                               "loadlibraryexa", "loadlibraryexw", "ldrloaddll",
                               "dlopen", "dlsym"}, 2),
    "networking": ({"internetopena", "internetopenw", "internetopenurla",
                    "urldownloadtofilea", "urldownloadtofilew", "wsastartup",
                    "httpsendrequesta", "winhttpopen", "socket", "connect"}, 2),
    "persistence": ({"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa",
                     "regcreatekeyexw", "createservicea", "createservicew",
                     "startservicea"}, 2),
    "keylogging/hooks": ({"setwindowshookexa", "setwindowshookexw",
                          "getasynckeystate", "getkeystate", "getkeyboardstate"}, 2),
    "crypto": ({"cryptacquirecontexta", "cryptacquirecontextw", "cryptencrypt",
                "cryptdecrypt", "cryptgenkey", "bcryptencrypt", "bcryptdecrypt"}, 2),
    "memory protection changes": ({"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory",
                                   "mprotect"}, 1),
    "process execution": ({"createprocessa", "createprocessw", "shellexecutea",
                           "shellexecutew", "winexec", "execve", "system", "fork"}, 1),
}


def api_findings(names):
    low = {n.lower() for n in names}
    out = []
    for group, (apis, need) in API_GROUPS.items():
        hits = sorted(low & apis)
        if len(hits) >= need:
            out.append(f"{group}: {', '.join(hits)}")
    return out


def section_findings(sections, writable, executable, normal_names):
    out = []
    for s in sections:
        nm, fl = s["name"], s["flags"]
        if not nm and s.get("type") == "NULL":
            continue
        if s["entropy"] > 7.2 and s.get("raw_size", s.get("size", 0)) > 512:
            out.append(f"section {nm or '?'}: very high entropy {s['entropy']} (packed/encrypted?)")
        if writable in fl and executable in fl:
            out.append(f"section {nm or '?'}: writable AND executable")
        if executable in fl and nm not in normal_names:
            out.append(f"section {nm or '?'}: executable with non-standard name")
    return out


# --------------------------------------------------------------------------
# PE
# --------------------------------------------------------------------------
MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
SUBSYSTEMS = {1: "Native", 2: "Windows GUI", 3: "Windows CUI", 9: "WinCE GUI",
              10: "EFI app"}
DIR_NAMES = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
             "DEBUG", "ARCH", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
             "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"]


def pe_flags(ch: int) -> str:
    out = ("R" if ch & 0x40000000 else "-") + \
          ("W" if ch & 0x80000000 else "-") + \
          ("X" if ch & 0x20000000 else "-")
    return out


class PE:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE file (no MZ)")
        (self.e_lfanew,) = unpack("<I", data, 0x3C)
        if data[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("PE signature not found")
        self._parse_headers()
        self._parse_sections()

    def _parse_headers(self):
        d, o = self.data, self.e_lfanew + 4
        (self.machine, self.nsections, self.timestamp, _, _,
         self.opt_size, self.characteristics) = unpack("<HHIIIHH", d, o)
        o += 20
        (self.magic,) = unpack("<H", d, o)
        if self.magic == 0x10B:
            self.bits, ptr = 32, 4
        elif self.magic == 0x20B:
            self.bits, ptr = 64, 8
        else:
            raise ValueError(f"bad optional header magic 0x{self.magic:x}")
        (self.entry_rva,) = unpack("<I", d, o + 16)
        (self.image_base,) = unpack("<I" if ptr == 4 else "<Q", d, o + (28 if ptr == 4 else 24))
        (self.subsystem,) = unpack("<H", d, o + 68)
        nrva_off = o + (92 if ptr == 4 else 108)
        (nrva,) = unpack("<I", d, nrva_off)
        self.ptr_size = ptr
        self.dirs = []
        for i in range(min(nrva, 16)):
            rva, size = unpack("<II", d, nrva_off + 4 + i * 8)
            self.dirs.append((rva, size))
        self.sect_off = o + self.opt_size

    def _parse_sections(self):
        self.sections = []
        for i in range(self.nsections):
            o = self.sect_off + i * 40
            name, vsize, vaddr, rsize, rptr = unpack("<8sIIII", self.data, o)
            (ch,) = unpack("<I", self.data, o + 36)
            raw = self.data[rptr:rptr + rsize]
            self.sections.append({
                "name": name.rstrip(b"\x00").decode("ascii", "replace"),
                "vaddr": vaddr, "vsize": vsize, "raw_ptr": rptr, "raw_size": rsize,
                "flags": pe_flags(ch), "entropy": round(entropy(raw), 3),
            })

    def rva2off(self, rva: int):
        for s in self.sections:
            size = max(s["vsize"], s["raw_size"])
            if s["vaddr"] <= rva < s["vaddr"] + size:
                return rva - s["vaddr"] + s["raw_ptr"]
        if rva < 0x1000:  # headers
            return rva
        return None

    def _read_cstr_rva(self, rva):
        off = self.rva2off(rva)
        return cstr(self.data, off) if off is not None else ""

    def imports(self):
        rva, size = self.dirs[1] if len(self.dirs) > 1 else (0, 0)
        res, off = {}, self.rva2off(rva) if rva else None
        if off is None:
            return res
        fmt, flag = ("<I", 1 << 31) if self.ptr_size == 4 else ("<Q", 1 << 63)
        while True:
            oft, _, _, name_rva, ft = unpack("<IIIII", self.data, off)
            if not (oft or name_rva or ft):
                break
            dll = self._read_cstr_rva(name_rva)
            t = self.rva2off(oft or ft)
            funcs = []
            while t is not None:
                (val,) = unpack(fmt, self.data, t)
                if val == 0:
                    break
                if val & flag:
                    funcs.append(f"#{val & 0xFFFF}")
                else:
                    funcs.append(self._read_cstr_rva((val & 0x7FFFFFFF) + 2))
                t += self.ptr_size
            res[dll] = funcs
            off += 20
        return res

    def exports(self):
        rva, size = self.dirs[0] if self.dirs else (0, 0)
        off = self.rva2off(rva) if rva else None
        if off is None:
            return []
        (_, _, _, _, name_rva, base, nfunc, nnames,
         a_funcs, a_names, a_ords) = unpack("<IIHHIIIIIII", self.data, off)
        funcs, names, ords = (self.rva2off(a_funcs), self.rva2off(a_names),
                              self.rva2off(a_ords))
        named = {}
        for i in range(nnames):
            (n_rva,) = unpack("<I", self.data, names + i * 4)
            (idx,) = unpack("<H", self.data, ords + i * 2)
            named[idx] = self._read_cstr_rva(n_rva)
        out = []
        for i in range(nfunc):
            (f_rva,) = unpack("<I", self.data, funcs + i * 4)
            if f_rva:
                out.append({"ordinal": base + i, "rva": f"0x{f_rva:x}",
                            "name": named.get(i, "")})
        return out

    def info(self):
        imps = self.imports()
        findings = api_findings([f for fs in imps.values() for f in fs]) + \
            section_findings(self.sections, "W", "X", {".text", "CODE", ".code", ".init"})
        return {
            "format": f"PE{'32' if self.bits == 32 else '32+'}",
            "machine": MACHINES.get(self.machine, hex(self.machine)),
            "type": "DLL" if self.characteristics & 0x2000 else "EXE",
            "subsystem": SUBSYSTEMS.get(self.subsystem, str(self.subsystem)),
            "image_base": f"0x{self.image_base:x}",
            "entry_point_rva": f"0x{self.entry_rva:x}",
            "timestamp": self.timestamp,
            "sections": self.sections,
            "imphash": imphash(imps),
            "imports": imps,
            "exports": self.exports(),
            "findings": findings,
        }


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------
E_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
E_MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
SH_NAMES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
            6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM"}
PT_NAMES = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR",
            7: "TLS", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK",
            0x6474E552: "GNU_RELRO"}


class ELF:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.is64 = data[4] == 2
        self.e = "<" if data[5] == 1 else ">"
        self._parse_header()
        self._parse_sections()
        self._parse_segments()

    def _parse_header(self):
        d, e = self.data, self.e
        fmt = e + ("HHIQQQIHHHHHH" if self.is64 else "HHIIIIIHHHHHH")
        (self.type, self.machine, _, self.entry, self.phoff, self.shoff, _, _,
         self.phentsize, self.phnum, self.shentsize, self.shnum,
         self.shstrndx) = unpack(fmt, d, 16)

    def _parse_sections(self):
        d, e = self.data, self.e
        fmt = e + ("IIQQQQIIQQ" if self.is64 else "IIIIIIIIII")
        raw = []
        for i in range(self.shnum):
            raw.append(unpack(fmt, d, self.shoff + i * self.shentsize))
        self.sections = []
        stroff = raw[self.shstrndx][4] if raw and self.shstrndx < len(raw) else 0
        for (name, typ, flags, addr, off, size, link, info, _, entsize) in raw:
            body = d[off:off + size] if typ != 8 else b""
            self.sections.append({
                "name": cstr(d, stroff + name), "type": SH_NAMES.get(typ, hex(typ)),
                "addr": f"0x{addr:x}", "offset": off, "size": size,
                "flags": ("W" if flags & 1 else "-") + ("A" if flags & 2 else "-") +
                         ("X" if flags & 4 else "-"),
                "entropy": round(entropy(body), 3),
                "_link": link, "_entsize": entsize, "_typ": typ,
            })

    def _parse_segments(self):
        d, e = self.data, self.e
        self.segments = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            if self.is64:
                t, fl, off, va, _, fsz, msz, _ = unpack(e + "IIQQQQQQ", d, o)
            else:
                t, off, va, _, fsz, msz, fl, _ = unpack(e + "IIIIIIII", d, o)
            self.segments.append({
                "type": PT_NAMES.get(t, hex(t)), "offset": off,
                "vaddr": f"0x{va:x}", "filesz": fsz, "memsz": msz,
                "flags": ("R" if fl & 4 else "-") + ("W" if fl & 2 else "-") +
                         ("X" if fl & 1 else "-"),
            })

    def _dynsym(self):
        """Return (imports, exports) from .dynsym."""
        d, e = self.data, self.e
        imps, exps = [], []
        for s in self.sections:
            if s["_typ"] != 11:
                continue
            strsec = self.sections[s["_link"]]
            ent = s["_entsize"] or (24 if self.is64 else 16)
            for i in range(1, s["size"] // ent):
                o = s["offset"] + i * ent
                if self.is64:
                    name, info, _, shndx, val, size = unpack(e + "IBBHQQ", d, o)
                else:
                    name, val, size, info, _, shndx = unpack(e + "IIIBBH", d, o)
                nm = cstr(d, strsec["offset"] + name)
                if not nm:
                    continue
                kind = {1: "OBJECT", 2: "FUNC"}.get(info & 0xF, "OTHER")
                (imps if shndx == 0 else exps).append(
                    {"name": nm, "type": kind, "addr": f"0x{val:x}"})
        return imps, exps

    def needed(self):
        """DT_NEEDED libraries from .dynamic."""
        d, e = self.data, self.e
        libs = []
        for s in self.sections:
            if s["_typ"] != 6:
                continue
            strsec = self.sections[s["_link"]]
            ent = 16 if self.is64 else 8
            for i in range(s["size"] // ent):
                tag, val = unpack(e + ("qQ" if self.is64 else "iI"), d, s["offset"] + i * ent)
                if tag == 0:
                    break
                if tag == 1:
                    libs.append(cstr(d, strsec["offset"] + val))
        return libs

    def info(self):
        imps, exps = self._dynsym()
        clean = [{k: v for k, v in s.items() if not k.startswith("_")} for s in self.sections]
        findings = api_findings([i["name"] for i in imps]) + section_findings(
            [c for c in clean if c["name"]], "W", "X",
            {".text", ".init", ".fini", ".plt", ".plt.got", ".plt.sec", ".init_array"})
        for seg in self.segments:
            if seg["type"] == "GNU_STACK" and "X" in seg["flags"]:
                findings.append("GNU_STACK is executable (NX disabled)")
            if seg["type"] == "LOAD" and "W" in seg["flags"] and "X" in seg["flags"]:
                findings.append("LOAD segment is writable AND executable")
        return {
            "format": f"ELF{64 if self.is64 else 32}",
            "machine": E_MACHINES.get(self.machine, str(self.machine)),
            "type": E_TYPES.get(self.type, str(self.type)),
            "endian": "little" if self.e == "<" else "big",
            "entry_point": f"0x{self.entry:x}",
            "segments": self.segments,
            "sections": clean,
            "needed_libs": self.needed(),
            "imports": imps,
            "exports": exps,
            "findings": findings,
        }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x7fELF":
        return ELF(data).info()
    if data[:2] == b"MZ":
        return PE(data).info()
    raise ValueError("unknown format (expected PE or ELF)")


def print_report(r: dict, limit: int):
    print(f"[*] Format    : {r['format']} ({r['machine']}, {r['type']})")
    for k in ("subsystem", "image_base", "entry_point_rva", "entry_point", "endian"):
        if k in r:
            print(f"[*] {k:<10}: {r[k]}")

    if "segments" in r:
        print("\n== Segments ==")
        for s in r["segments"]:
            print(f"  {s['type']:<14} off=0x{s['offset']:<8x} va={s['vaddr']:<12} "
                  f"filesz=0x{s['filesz']:<8x} {s['flags']}")

    print("\n== Sections ==")
    print(f"  {'name':<20}{'size':>10}  {'flags':<6}{'entropy':>8}")
    for s in r["sections"]:
        size = s.get("raw_size", s.get("size", 0))
        print(f"  {s['name']:<20}{size:>10}  {s['flags']:<6}{s['entropy']:>8.3f}  "
              f"{verdict(s['entropy'])}")

    imps = r["imports"]
    if r.get("imphash"):
        print(f"\n[*] imphash   : {r['imphash']}")
    print("\n== Imports ==")
    if isinstance(imps, dict):
        for dll, funcs in imps.items():
            print(f"  {dll} ({len(funcs)})")
            for fn in funcs[:limit]:
                print(f"      {fn}")
            if len(funcs) > limit:
                print(f"      ... +{len(funcs) - limit} more")
    else:
        for lib in r.get("needed_libs", []):
            print(f"  NEEDED {lib}")
        for i in imps[:limit]:
            print(f"      {i['name']}")
        if len(imps) > limit:
            print(f"      ... +{len(imps) - limit} more")

    print("\n== Exports ==")
    for x in r["exports"][:limit]:
        print(f"  {x.get('ordinal', ''):<5} {x.get('rva', x.get('addr')):<12} {x['name']}")
    if len(r["exports"]) > limit:
        print(f"  ... +{len(r['exports']) - limit} more")

    print("\n== Findings ==")
    if r["findings"]:
        for f in r["findings"]:
            print(f"  [!] {f}")
    else:
        print("  nothing suspicious found")


def main():
    ap = argparse.ArgumentParser(description="Minimal PE/ELF parser")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("-n", "--limit", type=int, default=15,
                    help="max imports/exports to print per group (default 15)")
    a = ap.parse_args()
    try:
        r = parse(a.file)
    except (OSError, ValueError, struct.error) as ex:
        sys.exit(f"error: {ex}")
    print(json.dumps(r, indent=2) if a.json else "", end="" if not a.json else "\n")
    if not a.json:
        print_report(r, a.limit)


if __name__ == "__main__":
    main()
