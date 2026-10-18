from __future__ import annotations

from pathlib import Path

from securevault.crypto import decrypt_secret, encrypt_secret, generate_salt


class SecureVault:
    """High-level interface for working with a password-protected vault."""

    def __init__(self, password: str, vault_file: str | Path = "vault.json"):
        self.password = password
        self.vault_file = Path(vault_file)

    def _ensure_initialized(self) -> dict:
        if not self.vault_file.exists():
            raise FileNotFoundError(f"Vault file not found: {self.vault_file}")
        import json

        with self.vault_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if "salt" not in data or "entries" not in data:
            raise ValueError("Vault file is malformed.")
        return data

    def init(self) -> dict:
        salt = generate_salt()
        data = {"salt": salt.decode("utf-8"), "entries": {}}
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        with self.vault_file.open("w", encoding="utf-8") as handle:
            import json

            json.dump(data, handle, indent=2)
        return data

    def add(self, name: str, secret: str, note: str = "") -> dict:
        vault = self._ensure_initialized()
        salt = vault["salt"].encode("utf-8")
        encrypted = encrypt_secret(secret, self.password, salt)
        vault["entries"][name] = {"value": encrypted, "note": note}
        with self.vault_file.open("w", encoding="utf-8") as handle:
            import json

            json.dump(vault, handle, indent=2)
        return vault["entries"][name]

    def get(self, name: str) -> dict:
        vault = self._ensure_initialized()
        entry = vault["entries"].get(name)
        if entry is None:
            raise KeyError(f"Entry '{name}' does not exist.")
        salt = vault["salt"].encode("utf-8")
        return {
            "name": name,
            "value": decrypt_secret(entry["value"], self.password, salt),
            "note": entry.get("note", ""),
        }

    def list(self) -> list[dict]:
        vault = self._ensure_initialized()
        salt = vault["salt"].encode("utf-8")
        items = []
        for name in sorted(vault["entries"].keys()):
            entry = vault["entries"][name]
            items.append(
                {
                    "name": name,
                    "value": decrypt_secret(entry["value"], self.password, salt),
                    "note": entry.get("note", ""),
                }
            )
        return items

    def delete(self, name: str) -> dict:
        vault = self._ensure_initialized()
        if name not in vault["entries"]:
            raise KeyError(f"Entry '{name}' does not exist.")

        deleted = vault["entries"].pop(name)
        with self.vault_file.open("w", encoding="utf-8") as handle:
            import json

            json.dump(vault, handle, indent=2)
        return deleted
