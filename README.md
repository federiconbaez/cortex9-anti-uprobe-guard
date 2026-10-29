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

Corpus y umbrales fijados **antes** de medir: [`lab/prereg.json`](lab/prereg.json),
commit `b84fc8b`, empujado a GitHub antes de la medición oficial.

| Métrica | Umbral | n |
|---|---|---|
| TPR en `0xCC` plantado | 100% | 100 |
| TPR en evasión branch-only (`je`↔`jne`, sin int3) | 100% | 100 |
| FPR sin manipulación | 0% | 100 |

## Resultados (medidos)

Comando: `cargo run --release -- measure --n 100 --out results/box-2026-10-29.json`.

| Métrica | Umbral | Box (Debian, kernel 6.12, bpf unprivileged disabled) | CI |
|---|---|---|---|
| TPR int3 (`0xCC`) | 100/100 | **100/100** | **100/100** ([ci 40929603851](https://github.com/federiconbaez/cortex9-anti-uprobe-guard/actions/runs/40929603851)) |
| TPR branch-only (`je`↔`jne`) | 100/100 | **100/100** | **100/100** |
| FPR clean | 0/100 | **0/100** | **0/100** |

Salida: [`results/box-2026-10-29.json`](results/box-2026-10-29.json).

**Caveat "por construcción":** 100% TPR y 0% FPR son sobre un corpus sintético
escrito por el mismo autor que el detector (tres brazos: clean / `0xCC` /
flip de branch contra el canario propio). No es una evaluación ciega contra
uprobes eBPF reales. El pre-registro fija ese corpus; no prueba cobertura
del mundo real.

## Alcance / no verificado

- **Uprobe real del kernel:** job opcional [`enforce.yml`](.github/workflows/enforce.yml)
  con `sudo`. Si el runner no puede registrar el uprobe, el job queda rojo
  (sin skip silencioso). No forma parte del criterio de aceptación userspace. En ubuntu-24.04 de Actions el uprobe real **sí adjuntó** ([enforce 40929603700](https://github.com/federiconbaez/cortex9-anti-uprobe-guard/actions/runs/40929603700)).
- `.text` de bibliotecas compartidas (libc, etc.): fuera de alcance.
- Escape Quarkslab de VMA escribible (`valid_vma` rechaza `VM_WRITE` al registrar):
  no mitigado; un proceso que se haga el `.text` escribible evita el uprobe
  sin que este detector lo note como "uprobe", aunque sí vería otros writes.
- Detección del mapeo `[uprobes]` (xol): no implementada.
- Arquitecturas distintas de x86_64: no soportadas.
- El canario bajo `opt-level=3` usa `je` (`0x74`); el plant acepta `je` o `jne`.

## Fuentes leídas

- Célian Glénaz, Quarkslab, *Defeating eBPF Uprobe Monitoring* (2022-08-30):
  <https://blog.quarkslab.com/defeating-ebpf-uprobe-monitoring.html>
  (detección por `0xCC`, mapeo `[uprobes]`, escape con VMA escribible).

## Referencia

Idea #58 del filtro adversario 2026-10-27. `Ref: CX9-58`.
