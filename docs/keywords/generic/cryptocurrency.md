# Cryptocurrency — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Cryptocurrency

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Bitcoin Address (Bech32) | `bitcoin`, `btc`, `segwit`, `wallet` |
| Bitcoin Address (Legacy) | `bitcoin`, `btc`, `wallet`, `crypto` |
| Bitcoin Cash Address | `bitcoin cash`, `bch`, `wallet` |
| Ethereum Address | `ethereum`, `eth`, `ether`, `wallet`, `crypto` |
| Litecoin Address | `litecoin`, `ltc`, `wallet` |
| Monero Address | `monero`, `xmr`, `wallet` |
| Ripple Address | `ripple`, `xrp`, `wallet` |
