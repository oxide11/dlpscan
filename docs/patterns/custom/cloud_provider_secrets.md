# Patterns: Cloud Provider Secrets

## Cloud Provider Secrets

| Pattern Name | Regex |
|---|---|
| AWS Access Key | `\bAKIA[0-9A-Z]{16}\b` |
| AWS Secret Key | `(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])` |
| Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` |
