# binparse

Minimal **PE / ELF parser written from scratch** in pure Python (stdlib only, no `pefile` / `pyelftools`).

## Features
- **PE** (PE32 / PE32+): COFF + optional header, sections (RWX flags), imports (by name / ordinal), exports
- **ELF** (32/64-bit, LE/BE): header, program headers, sections, `DT_NEEDED`, `.dynsym` imports/exports
- **Shannon entropy** per section, with a hint for likely packed/encrypted data (> 7.2)
- Human-readable report or `--json`

## Usage
```bash
python binparse.py sample.exe
python binparse.py /bin/ls -n 5        # limit imports/exports per group
python binparse.py sample.dll --json > report.json
```

## Example output
```
[*] Format    : PE32+ (x64, EXE)
[*] image_base: 0x140000000

== Sections ==
  name                      size  flags  entropy
  .text                    55296  R-X      6.397
  .rdata                   14848  R--      4.921
```

## How it works
Everything is parsed manually with `struct`: RVA -> file offset translation through the
section table, import thunks (INT/IAT), export name/ordinal tables, ELF string tables
linked via `sh_link`.

## Roadmap
- [ ] PE: resources, TLS callbacks, delay imports, rich header
- [ ] PE: imphash
- [ ] ELF: relocations, `.symtab`
- [ ] Mach-O support
- [ ] Suspicious-API heuristics (VirtualAlloc + WriteProcessMemory, etc.)

## License
MIT
