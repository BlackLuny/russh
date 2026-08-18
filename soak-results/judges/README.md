# Judge artifacts (no secrets)

JSON from `judge_repro.py` / s8 `/stats`. Do not copy `id_ed25519` here.

- `repeat/` — freeze-catchup and 180s flood on the **fixed** binary
- `rekey8m/` — 180s unlimited, `REKEY_BYTES=8MiB`, `RekeyLimit=8M`
- `neg-more-lanes/` — 180s with `more_lanes { continue }` restored (did **not** fail)
- `neg-more-lanes-freeze15/` — 15s freeze with `continue` restored (did **not** fail)
