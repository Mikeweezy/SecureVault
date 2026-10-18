from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securevault.crypto import decrypt_secret, encrypt_secret, generate_salt


class VaultStorage:
    """Simple JSON-backed storage for encrypted secrets."""

    def __init__(self, vault_file: str | Path):
        self.vault_file = Path(vault_file)

    def exists(self) -> bool:
        return self.vault_file.exists()

    def initialize(self, password: str) -> dict[str, Any]:
        salt = generate_salt()
        vault = {
            "salt": salt.decode("utf-8"),
            "entries": {},
        }
        self.save(vault)
        return vault

    def load(self) -> dict[str, Any]:
        if not self.exists():
            raise FileNotFoundError(f"Vault file not found: {self.vault_file}")

        with self.vault_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        if "salt" not in data or "entries" not in data:
            raise ValueError("Vault file is malformed.")
        return data

    def save(self, vault: dict[str, Any]) -> None:
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        with self.vault_file.open("w", encoding="utf-8") as handle:
            json.dump(vault, handle, indent=2)

    def add_entry(self, password: str, name: str, value: str, note: str = "") -> dict[str, Any]:
        vault = self.load()
        salt = vault["salt"].encode("utf-8")
        encrypted_value = encrypt_secret(value, password, salt)

        vault["entries"][name] = {
            "value": encrypted_value,
            "note": note,
        }
        self.save(vault)
        return vault["entries"][name]

    def get_entry(self, password: str, name: str) -> dict[str, Any]:
        vault = self.load()
        salt = vault["salt"].encode("utf-8")
        entry = vault["entries"].get(name)
        if entry is None:
            raise KeyError(f"Entry '{name}' does not exist.")

        decrypted_value = decrypt_secret(entry["value"], password, salt)
        return {
            "name": name,
            "value": decrypted_value,
            "note": entry.get("note", ""),
        }

    def list_entries(self, password: str) -> list[dict[str, Any]]:
        vault = self.load()
        salt = vault["salt"].encode("utf-8")
        names = sorted(vault["entries"].keys())
        items: list[dict[str, Any]] = []

        for name in names:
            entry = vault["entries"][name]
            try:
                value = decrypt_secret(entry["value"], password, salt)
            except Exception as exc:  # pragma: no cover - relies on wrong credentials
                raise ValueError("Incorrect password or corrupted vault.") from exc
            items.append({"name": name, "value": value, "note": entry.get("note", "")})
        return items

    def delete_entry(self, name: str) -> dict[str, Any]:
        vault = self.load()
        if name not in vault["entries"]:
            raise KeyError(f"Entry '{name}' does not exist.")

        deleted = vault["entries"].pop(name)
        self.save(vault)
        return deleted
