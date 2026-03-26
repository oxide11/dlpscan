"""Role-based access control for detokenization operations."""

import threading
from enum import Enum
from typing import Dict, FrozenSet, Optional

from .transforms import TokenVault


class Role(Enum):
    """User roles for access control."""

    ADMIN = "admin"
    ANALYST = "analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(Enum):
    """Permissions governing vault operations."""

    DETOKENIZE = "detokenize"
    EXPORT_VAULT = "export_vault"
    IMPORT_VAULT = "import_vault"
    CLEAR_VAULT = "clear_vault"


_ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.ANALYST: frozenset({Permission.DETOKENIZE, Permission.EXPORT_VAULT}),
    Role.OPERATOR: frozenset({Permission.DETOKENIZE}),
    Role.VIEWER: frozenset(),
}


class PermissionDeniedError(Exception):
    """Raised when a user lacks the required permission."""

    def __init__(self, user_id: str, permission: Permission, role: Role) -> None:
        self.user_id = user_id
        self.permission = permission
        self.role = role
        super().__init__(
            f"User {user_id!r} with role {role.value!r} "
            f"lacks permission {permission.value!r}"
        )


class RBACPolicy:
    """Thread-safe role-based access-control policy.

    Args:
        default_role: Role assigned to users without an explicit override.
        role_overrides: Mapping of user_id to Role for specific users.
    """

    def __init__(
        self,
        default_role: Role = Role.VIEWER,
        role_overrides: Optional[Dict[str, Role]] = None,
    ) -> None:
        self._default_role = default_role
        self._role_overrides: Dict[str, Role] = dict(role_overrides or {})
        self._lock = threading.Lock()

    def _resolve_role(self, user_id: str) -> Role:
        with self._lock:
            return self._role_overrides.get(user_id, self._default_role)

    def check(self, user_id: str, permission: Permission) -> bool:
        """Return True if *user_id* holds *permission*."""
        role = self._resolve_role(user_id)
        return permission in _ROLE_PERMISSIONS[role]

    def require(self, user_id: str, permission: Permission) -> None:
        """Raise :class:`PermissionDeniedError` if *user_id* lacks *permission*."""
        role = self._resolve_role(user_id)
        if permission not in _ROLE_PERMISSIONS[role]:
            raise PermissionDeniedError(user_id, permission, role)

    def set_role(self, user_id: str, role: Role) -> None:
        """Assign *role* to *user_id*, overriding the default."""
        with self._lock:
            self._role_overrides[user_id] = role


class SecureTokenVault:
    """RBAC-aware wrapper around :class:`TokenVault`.

    Tokenization (writing tokens) is unrestricted; all read-back and
    management operations require the appropriate permission.

    Args:
        vault: The underlying :class:`TokenVault` to protect.
        policy: The :class:`RBACPolicy` governing access.
    """

    def __init__(self, vault: TokenVault, policy: RBACPolicy) -> None:
        self._vault = vault
        self._policy = policy

    # -- pass-through (no permission check) ----------------------------------

    def tokenize(self, value: str, category: str) -> str:
        """Tokenize a value (no permission check required)."""
        return self._vault.tokenize(value, category)

    # -- guarded operations --------------------------------------------------

    def detokenize(self, token: str, user_id: str) -> Optional[str]:
        """Recover the original value from *token*.

        Requires :attr:`Permission.DETOKENIZE`.
        """
        self._policy.require(user_id, Permission.DETOKENIZE)
        return self._vault.detokenize(token)

    def detokenize_text(self, text: str, user_id: str) -> str:
        """Replace all tokens in *text* with their originals.

        Requires :attr:`Permission.DETOKENIZE`.
        """
        self._policy.require(user_id, Permission.DETOKENIZE)
        return self._vault.detokenize_text(text)

    def export_map(self, user_id: str) -> Dict[str, str]:
        """Export the token-to-original mapping.

        Requires :attr:`Permission.EXPORT_VAULT`.
        """
        self._policy.require(user_id, Permission.EXPORT_VAULT)
        return self._vault.export_map()

    def import_map(self, mapping: Dict[str, str], user_id: str) -> None:
        """Import a token-to-original mapping.

        Requires :attr:`Permission.IMPORT_VAULT`.
        """
        self._policy.require(user_id, Permission.IMPORT_VAULT)
        self._vault.import_map(mapping)

    def clear(self, user_id: str) -> None:
        """Remove all stored token mappings.

        Requires :attr:`Permission.CLEAR_VAULT`.
        """
        self._policy.require(user_id, Permission.CLEAR_VAULT)
        self._vault.clear()
