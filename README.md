# AnyRule

Personal Anywhere rule sets.

## Routing rules

- Apple Podcasts: https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/podcasts.arrs
  Suggested action: Proxy.
- BOC WeChat Direct: https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/BOC-Wechat.arrs
  Suggested action: DIRECT.
  Notes: Bank of China and WeChat Work companion direct rules, cleaned against the common WeChat rule set and optimized to remove noisy captured IPs.
- Qieman: https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/qieman.arrs
  Suggested action: DIRECT.

## MITM rules

Place `.amrs` files in `mitm/`. If a MITM rule needs a matching reject routing rule, keep that related `.arrs` file in `mitm/` as well.

- CamScanner Unlock: https://raw.githubusercontent.com/carolcheng520/anyrule/main/mitm/CamScannerUnlock.amrs
  No reject routing rule required.
