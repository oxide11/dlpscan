# Contact Info — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Contact Information

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| E.164 Phone Number | `phone`, `telephone`, `tel`, `mobile`, `contact number` |
| Email Address | `email`, `e-mail`, `email address`, `mail to`, `contact` |
| IPv4 Address | `ip address`, `ip`, `server`, `host`, `network` |
| IPv6 Address | `ip address`, `ipv6`, `server`, `host`, `network` |
| MAC Address | `mac address`, `hardware address`, `physical address`, `mac` |
