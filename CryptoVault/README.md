# CryptoVault — Project 1 (ALM-2)

CryptoVault is an educational public-key cryptography toolkit based on the supplied project brief. It demonstrates RSA encryption/decryption and signatures, Diffie–Hellman shared-secret derivation, ElGamal signatures with SHA-512, account registration/login, public-key storage, and downloadable self-signed X.509 certificates.

## Requirements
- Python 3.10+
- Node.js 18+
- npm

## Run on macOS (VS Code terminal)

### 1. Start the backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Backend runs at http://127.0.0.1:5000

### 2. Start the frontend (new terminal)
```bash
cd frontend
npm install
npm run dev
```
Open the URL printed by Vite (usually http://localhost:5173).

## Notes
- This is a learning/demo application, not production-ready security software.
- RSA-OAEP uses SHA-256; RSA signatures use PSS/SHA-256. ElGamal signing is implemented for demonstration with a SHA-512 digest reduced modulo `p-1`.
- The Diffie–Hellman panel uses small demonstration parameters so intermediate values are easy to understand. Do not use these parameters for real security.
- User passwords are hashed with Werkzeug. The private key is returned to the logged-in browser for this educational demo; a real system should not expose or store private keys this way.
- SQLite database is created automatically at `backend/cryptovault.db`.
