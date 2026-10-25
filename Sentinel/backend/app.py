from flask import Flask, jsonify, request
from flask_cors import CORS
from statistics import mean, pstdev
from datetime import datetime, timezone
import sqlite3, os, random

app = Flask(__name__)
CORS(app)
DB_PATH = os.path.join(os.path.dirname(__file__), 'sentinel.db')

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            source_ip TEXT NOT NULL DEFAULT '*', dest_ip TEXT NOT NULL DEFAULT '*',
            port TEXT NOT NULL DEFAULT '*', protocol TEXT NOT NULL DEFAULT 'ANY',
            action TEXT NOT NULL DEFAULT 'BLOCK', enabled INTEGER NOT NULL DEFAULT 1,
            bastion INTEGER NOT NULL DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT, title TEXT,
            detail TEXT, source_ip TEXT, created_at TEXT)''')
        if c.execute('SELECT COUNT(*) FROM rules').fetchone()[0] == 0:
            c.executemany('''INSERT INTO rules(name,source_ip,dest_ip,port,protocol,action,bastion)
                VALUES(?,?,?,?,?,?,?)''', [
                ('Block Telnet','*','*','23','TCP','BLOCK',0),
                ('Allow Web Traffic','*','*','80','TCP','ALLOW',0),
                ('Protect Admin Bastion','*','192.168.1.10','22','TCP','ALLOW',1)])

def add_alert(severity, title, detail, ip):
    with db() as c:
        c.execute('INSERT INTO alerts(severity,title,detail,source_ip,created_at) VALUES(?,?,?,?,?)',
                  (severity,title,detail,ip,datetime.now(timezone.utc).isoformat(timespec='seconds')))

def rowdicts(rows): return [dict(r) for r in rows]

@app.get('/api/health')
def health(): return jsonify({'status':'ok','mode':'simulation'})

@app.get('/api/rules')
def get_rules():
    with db() as c: return jsonify(rowdicts(c.execute('SELECT * FROM rules ORDER BY id DESC').fetchall()))

@app.post('/api/rules')
def create_rule():
    d = request.get_json(silent=True) or {}
    required = ['name','source_ip','dest_ip','port','protocol','action']
    if any(not str(d.get(k,'')).strip() for k in required): return jsonify({'error':'Please fill in all rule fields.'}), 400
    if d['action'] not in ('ALLOW','BLOCK'): return jsonify({'error':'Action must be ALLOW or BLOCK.'}), 400
    with db() as c:
        cur = c.execute('''INSERT INTO rules(name,source_ip,dest_ip,port,protocol,action,bastion)
          VALUES(?,?,?,?,?,?,?)''', (d['name'],d['source_ip'],d['dest_ip'],str(d['port']),d['protocol'],d['action'],int(bool(d.get('bastion')))))
        rule = c.execute('SELECT * FROM rules WHERE id=?',(cur.lastrowid,)).fetchone()
        return jsonify(dict(rule)), 201

@app.delete('/api/rules/<int:rid>')
def delete_rule(rid):
    with db() as c:
        cur = c.execute('DELETE FROM rules WHERE id=?',(rid,))
        if not cur.rowcount: return jsonify({'error':'Rule not found'}),404
    return jsonify({'deleted':rid})

@app.get('/api/alerts')
def get_alerts():
    with db() as c: return jsonify(rowdicts(c.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 30').fetchall()))

@app.post('/api/traffic')
def simulate_traffic():
    d = request.get_json(silent=True) or {}
    kind = d.get('kind','HTTP')
    ip = d.get('source_ip') or random.choice(['192.168.1.24','10.0.0.8','172.16.0.44','203.0.113.17'])
    port = int(d.get('port', {'HTTP':80,'SSH':22,'TELNET':23,'PORT_SCAN':random.choice([21,22,23,80,443])}.get(kind,80)))
    failed = int(d.get('failed_attempts', random.choice([1,1,2,3,5,7]))) if kind == 'SSH' else 0
    with db() as c:
        rules = rowdicts(c.execute('SELECT * FROM rules WHERE enabled=1').fetchall())
    matched = next((r for r in rules if (r['source_ip']=='*' or r['source_ip']==ip) and (r['port']=='*' or str(r['port'])==str(port)) and (r['protocol']=='ANY' or r['protocol']==('UDP' if d.get('protocol')=='UDP' else 'TCP'))), None)
    action = matched['action'] if matched else 'ALLOW'
    events=[]
    if kind == 'TELNET' or port == 23:
        events.append(('HIGH','Suspicious Telnet traffic',f'Simulated traffic used insecure Telnet port {port}.',ip))
    if kind == 'SSH' and failed >= 5:
        events.append(('CRITICAL','Possible SSH brute-force attempt',f'{failed} failed SSH login attempts were simulated from {ip}.',ip))
    if kind == 'PORT_SCAN':
        events.append(('HIGH','Possible port scan',f'Multiple service ports were probed by simulated source {ip}.',ip))
    if matched and matched['action']=='BLOCK':
        events.append(('MEDIUM','Firewall blocked traffic',f"Rule '{matched['name']}' blocked simulated {kind} traffic on port {port}.",ip))
    # A compact statistical detector: unusual burst count is compared with a baseline.
    baseline=[2,3,2,4,3,2,3,4,2,3]
    observed=failed if kind=='SSH' else (9 if kind=='PORT_SCAN' else random.randint(1,4))
    threshold=mean(baseline)+3*pstdev(baseline)
    if observed > threshold:
        events.append(('HIGH','Statistical anomaly detected',f'Observed activity {observed:.1f} exceeds the baseline threshold {threshold:.1f}.',ip))
    for e in events: add_alert(*e)
    return jsonify({'id':random.randint(10000,99999),'kind':kind,'source_ip':ip,'port':port,'protocol':d.get('protocol','TCP'),'action':action,'matched_rule':matched,'alerts':[{'severity':e[0],'title':e[1],'detail':e[2],'source_ip':e[3]} for e in events], 'anomaly_metric':observed,'anomaly_threshold':round(threshold,2),'timestamp':datetime.now(timezone.utc).isoformat(timespec='seconds')})

@app.get('/api/stats')
def stats():
    with db() as c:
        rules=c.execute('SELECT COUNT(*) FROM rules').fetchone()[0]
        alerts=c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        critical=c.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    return jsonify({'rules':rules,'alerts':alerts,'critical':critical,'status':'Monitoring (simulation)'})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5002, debug=False)
