# -*- coding: utf-8 -*-
"""RIZOM — dvo-sidreni WireGuard koji zamjenjuje jedan `ssh -R` (MASKA faza F3).

  rizom_konfig    generator konfiguracije za rub i sidra (+ nginx, izolirano)
  patch_watchdog  dodaje RIZOM put u tunel_watchdog_config.json (append, nikad prepis)
  deploy_sidro.sh pustanje na sidro s backupom, `nginx -t` prije reloada i vracanjem

Sidro ostaje prolaz dok F4 (probod) ne postoji — vidi docs/MASKA-FAZE.md.
"""
