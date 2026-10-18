from __future__ import annotations

import argparse
import sys

from securevault.vault import VaultStorage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureVault CLI")
    parser.add_argument("command", choices=["init", "add", "get", "list", "delete"])
    parser.add_argument("--password", required=True, help="Master password for vault access")
    parser.add_argument("--vault-file", default="vault.json", help="Path to the vault JSON file")
    parser.add_argument("--name", help="Secret name")
    parser.add_argument("--secret", help="Plaintext secret")
    parser.add_argument("--note", default="", help="Optional note for the secret")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    storage = VaultStorage(args.vault_file)

    try:
        if args.command == "init":
            storage.initialize(args.password)
            print(f"Vault initialized at {args.vault_file}")

        elif args.command == "add":
            if not args.name or not args.secret:
                parser.error("--name and --secret are required for add")
            storage.add_entry(args.password, args.name, args.secret, args.note)
            print(f"Added secret '{args.name}'")

        elif args.command == "get":
            if not args.name:
                parser.error("--name is required for get")
            entry = storage.get_entry(args.password, args.name)
            print(f"Name: {entry['name']}")
            print(f"Secret: {entry['value']}")
            if entry.get("note"):
                print(f"Note: {entry['note']}")

        elif args.command == "list":
            entries = storage.list_entries(args.password)
            if not entries:
                print("No entries found.")
            else:
                for entry in entries:
                    print(f"- {entry['name']}: {entry['value']}")
                    if entry.get("note"):
                        print(f"  Note: {entry['note']}")

        elif args.command == "delete":
            if not args.name:
                parser.error("--name is required for delete")
            storage.delete_entry(args.name)
            print(f"Deleted secret '{args.name}'")

    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
