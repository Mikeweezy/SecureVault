# SecureVault

SecureVault is a Python-based secure vault application for storing sensitive information using encryption and password-based access control.

## Features

- Password-protected vault initialization
- Encrypted secret storage using PBKDF2 + Fernet
- Add, retrieve, list, and delete secrets
- JSON-backed local storage for quick offline use
- Simple CLI workflow

## Tech stack

- Python 3.11+
- cryptography
- argparse
- JSON file storage

## Getting started

1. Create a virtual environment:

   python -m venv .venv
   source .venv/bin/activate

2. Install dependencies:

   pip install -r requirements.txt

3. Initialize the vault:

   python -m securevault.cli init --password "your-master-password" --vault-file vault.json

4. Add a secret:

   python -m securevault.cli add --password "your-master-password" --name github --secret "ghp_xxx" --note "Personal access token" --vault-file vault.json

5. Retrieve a secret:

   python -m securevault.cli get --password "your-master-password" --name github --vault-file vault.json

## Project status

This repository is in early development and serves as the foundation for a secure local secret manager.
