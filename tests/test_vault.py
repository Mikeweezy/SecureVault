from __future__ import annotations

from securevault.vault import SecureVault


def test_vault_round_trip(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = SecureVault(password="super-secret-password", vault_file=vault_path)

    vault.init()
    vault.add("github", "ghp_example", note="Personal access token")

    fetched = vault.get("github")
    assert fetched["value"] == "ghp_example"
    assert fetched["note"] == "Personal access token"

    entries = vault.list()
    assert [item["name"] for item in entries] == ["github"]


def test_wrong_password_raises(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = SecureVault(password="correct-password", vault_file=vault_path)
    vault.init()
    vault.add("db", "db-pass")

    wrong = SecureVault(password="wrong-password", vault_file=vault_path)
    try:
        wrong.get("db")
        assert False, "Expected ValueError for wrong password"
    except Exception:
        pass


def test_delete_entry(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = SecureVault(password="pw", vault_file=vault_path)
    vault.init()
    vault.add("api", "secret")
    vault.delete("api")

    assert vault.list() == []
