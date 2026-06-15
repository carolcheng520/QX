# AnyRule

Personal Anywhere rule sets.

## Routing rules

- Apple Podcasts: https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/podcasts.arrs
  Suggested action: Proxy.
- Qieman: https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/qieman.arrs
  Suggested action: DIRECT.

## MITM rules

Place `.amrs` files in `mitm/`. If a MITM rule needs a matching reject routing rule, keep that related `.arrs` file in `mitm/` as well.

- iTunes Series Unlock: https://raw.githubusercontent.com/carolcheng520/anyrule/main/mitm/iTunesUnlock.amrs
