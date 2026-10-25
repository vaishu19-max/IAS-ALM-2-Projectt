# Sentinel — Project 3: Intrusion Detection & Firewall Simulator

Educational full-stack simulator aligned with the ALM-2 Project 3 brief. It models (does not inspect or block real network traffic):
- Firewall rule manager (add/delete rules, source/destination IP, port, protocol, action, bastion-host designation)
- Simulated HTTP, SSH login, and Telnet traffic
- Rule-based IDS alerts (e.g. repeated failed SSH attempts and Telnet traffic)
- Statistical anomaly detection using a simple rolling mean and standard deviation threshold
- Threat encyclopedia covering viruses, worms, and countermeasures

## Run on macOS
Open this folder in VS Code.

### Terminal 1 — Flask backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Backend: http://127.0.0.1:5002

### Terminal 2 — React frontend
```bash
cd frontend
npm install
npm run dev
```
Open the URL printed by Vite (normally http://127.0.0.1:5173).

The frontend has a local demo fallback, so the UI can still be explored if the backend is unavailable. All traffic is simulated; this is not a production firewall or a real IDS.
