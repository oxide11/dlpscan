# Patterns: Urls With Credentials

## URLs with Credentials

| Pattern Name | Regex |
|---|---|
| URL with Password | `https?://[^:\s]+:[^@\s]+@[^\s]+` |
| URL with Token | `https?://[^\s]*[?&](?:token\|key\|api_key\|apikey\|access_token\|secret\|password\|passwd\|pwd)=[^\s&]+` |
