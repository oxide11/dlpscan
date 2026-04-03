# Tokenization & Obfuscation

## Tokenization (Reversible)

Tokenization replaces sensitive data with deterministic tokens that can be reversed later.

```python
from dlpscan import InputGuard, Preset, Action

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.TOKENIZE)
result = guard.scan("Card: 4111-1111-1111-1111")

print(result.redacted_text)     # "Card: TOK_CC_a8f3b2c1"
print(guard.detokenize(result.redacted_text))  # "Card: 4111-1111-1111-1111"
```

### Convenience Method

```python
tokenized_text, vault = guard.tokenize("Card: 4111-1111-1111-1111")
original = vault.detokenize_text(tokenized_text)
```

### TokenVault

The `TokenVault` stores token-to-original mappings:

```python
from dlpscan import TokenVault

vault = TokenVault(prefix="TOK", secret="my-hmac-secret")

# Export/import for persistence
mapping = vault.export_map()
vault.import_map(mapping)

# Stats
print(vault.size)
```

## Obfuscation (Irreversible)

Obfuscation replaces sensitive data with realistic-looking fake data:

```python
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.OBFUSCATE)
result = guard.scan("Card: 4111-1111-1111-1111")
print(result.redacted_text)  # "Card: 4539-7884-2165-0347" (Luhn-valid)
```

### Format-Preserving Fakes

| Data Type | Example Input | Example Output |
|-----------|--------------|----------------|
| Credit card | `4111-1111-1111-1111` | `4539-7884-2165-0347` (Luhn-valid) |
| Email | `user@company.com` | `xkqjmwpl@example.net` |
| Phone | `(555) 123-4567` | `(831) 947-2058` |
| SSN | `123-45-6789` | `847-29-3156` |
| IBAN | `GB29NWBK60161331926819` | `GB47HQZX83729461538274` |
| API key | `ghp_abc123def456` | `ghp_xK9mQ2pL7nR4` |

### Reproducible Obfuscation

Set a seed for deterministic output (useful for testing):

```python
from dlpscan import set_obfuscation_seed

set_obfuscation_seed(42)  # Same seed → same fake data
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.OBFUSCATE)
result = guard.scan("Card: 4111111111111111")
# Always produces the same output with seed 42
```

## Secure Vault (RBAC)

Wrap a vault with role-based access control:

```python
from dlpscan import TokenVault, Role, RBACPolicy, SecureTokenVault

vault = TokenVault()
policy = RBACPolicy(
    default_role=Role.VIEWER,
    role_overrides={"admin": Role.ADMIN},
)
secure = SecureTokenVault(vault=vault, policy=policy)

token = secure.tokenize("4111111111111111", "Credit Card Numbers")
original = secure.detokenize(token, user_id="admin")     # Works
# secure.detokenize(token, user_id="viewer")  # PermissionDeniedError
```

## Persistent Vault

Store tokens across restarts:

```python
from dlpscan.guard.vault_backends import FileBackend, EncryptedVault

# File-based (JSON-lines)
backend = FileBackend("/var/data/vault.jsonl")

# Encrypted at rest (AES-256-GCM)
encrypted = EncryptedVault(backend, key="your-encryption-key")
```
