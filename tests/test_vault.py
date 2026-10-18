from __future__ import annotations

from securevault.vault import VaultStorage


def test_vault_round_trip(tmp_path):
    vault_path = tmp_path / "vault.json"
    storage = VaultStorage(vault_path)

    storage.initialize("super-secret-password")
    storage.add_entry("super-secret-password", "github", "ghp_example", "Personal access token")

    fetched = storage.get_entry("super-secret-password", "github")
    assert fetched["value"] == "ghp_example"
    assert fetched["note"] == "Personal access token"

    entries = storage.list_entries("super-secret-password")
    assert [item["name"] for item in entries] == ["github"]


def test_wrong_password_raises(tmp_path):
    vault_path = tmp_path / "vault.json"
    storage = VaultStorage(vault_path)
    storage.initialize("correct-password")
    storage.add_entry("correct-password", "db", "db-pass")

    try:
        storage.get_entry("wrong-password", "db")
        assert False, "Expected ValueError for wrong password"
    except Exception:
        pass


def test_delete_entry(tmp_path):
    vault_path = tmp_path / "vault.json"
    storage = VaultStorage(vault_path)
    storage.initialize("pw")
    storage.add_entry("pw", "api", "secret")
    storage.delete_entry("api")

    assert storage.list_entries("pw") == []
