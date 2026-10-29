# cortex9-anti-uprobe-guard

Crate de integridad anti-uprobe: compara el `.text` en memoria del proceso
contra el ELF en disco. Un uprobe del kernel reescribe una instrucción con
`int3` (`0xCC`); un proceso que no confía en esa sonda puede detectar la
reescritura leyendo su propio mapeo ejecutable.

Estado: **MVP de un día**. Licencia Apache-2.0.

## Qué hace

```sh
cargo run -- scan                 # veredicto ok | tampered (JSON)
cargo run -- locate               # offset del canario cx9_canary_branch
cargo run -- measure --n 100      # laboratorio (umbrales en lab/prereg.json)
cargo test -- --test-threads=1    # los plants tocan .text compartido
```

API: `scan_self()`, `plant_int3()`, `plant_branch_flip()`. El plant es
simulación en userspace (`mprotect` + escritura) porque esta box tiene
`unprivileged_bpf_disabled=2`.

## Pre-registro

Corpus y umbrales fijados **antes** de medir: [`lab/prereg.json`](lab/prereg.json).

| Métrica | Umbral | n |
|---|---|---|
| TPR en `0xCC` plantado | 100% | 100 |
| TPR en evasión branch-only (`je`↔`jne`, sin int3) | 100% | 100 |
| FPR sin manipulación | 0% | 100 |

## Resultados (medidos)

*Pendiente: se completa en el commit posterior a este pre-registro.*

## Alcance / no verificado

- Uprobe real del kernel: job opcional [`enforce.yml`](.github/workflows/enforce.yml)
  con `sudo`; si el runner no puede registrar el uprobe, el job queda rojo
  (sin skip silencioso).
- `.text` de bibliotecas compartidas (libc, etc.): fuera de alcance.
- Escape Quarkslab de VMA escribible (`valid_vma` rechaza `VM_WRITE`): no mitigado.
- Detección de mapeo `[uprobes]` (xol): no implementada.
- Arquitecturas distintas de x86_64: no soportadas.

## Fuentes leídas

- Célian Glénaz, Quarkslab, *Defeating eBPF Uprobe Monitoring* (2022-08-30):
  <https://blog.quarkslab.com/defeating-ebpf-uprobe-monitoring.html>
  (detección por `0xCC`, mapeo `[uprobes]`, escape con VMA escribible).

## Referencia

Idea #58 del filtro adversario 2026-10-27. `Ref: CX9-58`.
