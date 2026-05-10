"""
COGNISEC Engine
===============
- AnomalyDetector      : sklearn IsolationForest behavioural scoring
- HoneypotManager      : ALL 1024 registered ports mapped to honeypots
- BenignSimulator      : background normal traffic only (no attacks)
- DeceptionOrchestrator: ties everything together, emits SSE events

Attacks come exclusively from attacker.py via POST /api/ingest
"""

import threading, time, random, json, logging, hashlib, collections
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("COGNISEC")

# ─────────────────────────────────────────────
# ALL 1024 REGISTERED PORTS → HONEYPOT TABLE
# ─────────────────────────────────────────────
_KNOWN_PORTS = {
    # Remote Access
    22:   ("SSH",           "OpenSSH_7.4p1 Ubuntu-4",          "remote_access", "critical"),
    23:   ("Telnet",        "Linux telnetd",                    "remote_access", "critical"),
    512:  ("rexec",         "BSD rexecd",                       "remote_access", "critical"),
    513:  ("rlogin",        "BSD rlogind",                      "remote_access", "critical"),
    514:  ("rsh",           "BSD rshd",                         "remote_access", "critical"),
    3389: ("RDP",           "Microsoft Terminal Services 6.1",  "remote_access", "critical"),
    5900: ("VNC",           "RFB 003.008",                      "remote_access", "high"),
    5901: ("VNC-1",         "RFB 003.008",                      "remote_access", "high"),
    # Web
    80:   ("HTTP",          "Apache/2.2.34 (Ubuntu)",           "web",           "high"),
    81:   ("HTTP-Alt",      "nginx/1.10.3",                     "web",           "medium"),
    443:  ("HTTPS",         "Apache/2.2.34 OpenSSL/1.0.1e",     "web",           "high"),
    591:  ("FileMaker",     "FileMaker HTTP",                   "web",           "medium"),
    631:  ("IPP",           "CUPS 1.4.4",                       "web",           "medium"),
    8008: ("HTTP-Alt2",     "IBM HTTP Server 8.0",              "web",           "medium"),
    8080: ("HTTP-Proxy",    "Apache Tomcat/7.0.82",             "web",           "high"),
    8443: ("HTTPS-Alt",     "Jetty 9.2.9.v20150904",            "web",           "high"),
    8888: ("HTTP-Dev",      "SimpleHTTP/0.6 Python/2.7.14",     "web",           "medium"),
    9090: ("HTTP-Mgmt",     "Prometheus/2.0.0",                 "web",           "medium"),
    # File Transfer
    20:   ("FTP-Data",      "vsftpd 2.3.4",                     "file_transfer", "critical"),
    21:   ("FTP",           "vsftpd 2.3.4",                     "file_transfer", "critical"),
    69:   ("TFTP",          "SolarWinds TFTP Server 10.4",      "file_transfer", "high"),
    115:  ("SFTP",          "OpenSSH_5.1p1 Debian",             "file_transfer", "high"),
    873:  ("Rsync",         "rsync 3.1.1  protocol 31",         "file_transfer", "medium"),
    989:  ("FTPS-Data",     "Pure-FTPd",                        "file_transfer", "medium"),
    990:  ("FTPS",          "Pure-FTPd TLS",                    "file_transfer", "medium"),
    # Email
    25:   ("SMTP",          "Postfix ESMTP 2.9.6",              "email",         "high"),
    110:  ("POP3",          "Dovecot pop3d",                    "email",         "medium"),
    143:  ("IMAP",          "Dovecot imapd",                    "email",         "medium"),
    465:  ("SMTPS",         "Postfix ESMTP TLS",                "email",         "medium"),
    587:  ("SMTP-Sub",      "Postfix ESMTP submission",         "email",         "medium"),
    993:  ("IMAPS",         "Dovecot imapd TLS",                "email",         "medium"),
    995:  ("POP3S",         "Dovecot pop3d TLS",                "email",         "medium"),
    # Databases
    1433: ("MSSQL",         "Microsoft SQL Server 2008 R2",     "database",      "critical"),
    1521: ("Oracle",        "Oracle TNS Listener 11g",          "database",      "critical"),
    3306: ("MySQL",         "MySQL 5.5.60-MariaDB",             "database",      "critical"),
    5432: ("PostgreSQL",    "PostgreSQL 9.3.22",                "database",      "critical"),
    6379: ("Redis",         "Redis 3.2.12",                     "database",      "critical"),
    # Directory / Auth
    88:   ("Kerberos",      "MIT Kerberos KDC 1.13",            "auth",          "critical"),
    389:  ("LDAP",          "OpenLDAP 2.4.40",                  "auth",          "high"),
    636:  ("LDAPS",         "OpenLDAP 2.4.40 TLS",              "auth",          "high"),
    # Network Services
    53:   ("DNS",           "BIND 9.9.5-3ubuntu0.19",           "network",       "high"),
    67:   ("DHCP",          "ISC DHCP 4.3.3",                   "network",       "medium"),
    68:   ("DHCP-Cli",      "ISC DHCP client",                  "network",       "low"),
    123:  ("NTP",           "ntpd 4.2.6p5",                     "network",       "medium"),
    161:  ("SNMP",          "Net-SNMP 5.7.3",                   "network",       "high"),
    162:  ("SNMP-Trap",     "Net-SNMP trap receiver",           "network",       "medium"),
    # Windows / SMB
    135:  ("MSRPC",         "Microsoft Windows RPC",            "windows",       "critical"),
    137:  ("NetBIOS-NS",    "Samba nmbd 4.3.11",                "windows",       "high"),
    138:  ("NetBIOS-DG",    "Samba",                            "windows",       "high"),
    139:  ("NetBIOS-SS",    "Samba smbd 3.X-4.X",               "windows",       "critical"),
    445:  ("SMB",           "Samba smbd 4.3.11-Ubuntu",         "windows",       "critical"),
    # VoIP
    5060: ("SIP",           "Asterisk PBX 13.18.3",             "voip",          "medium"),
    5061: ("SIPS",          "Asterisk PBX TLS",                 "voip",          "medium"),
    # DevOps / Container
    2181: ("ZooKeeper",     "Zookeeper 3.4.10",                 "devops",        "high"),
    2375: ("Docker",        "Docker 18.03.0-ce",                "devops",        "critical"),
    2376: ("Docker-TLS",    "Docker 18.03.0-ce TLS",            "devops",        "critical"),
    4243: ("Docker-Alt",    "Docker 17.12.0-ce",                "devops",        "critical"),
    9200: ("Elasticsearch", "Elasticsearch 5.6.3",              "devops",        "critical"),
    9300: ("ES-Cluster",    "Elasticsearch cluster bus",        "devops",        "high"),
    # Messaging
    5672: ("AMQP",          "RabbitMQ 3.6.10",                  "messaging",     "high"),
    6667: ("IRC",           "UnrealIRCd 3.2.8.1",               "messaging",     "medium"),
    # Proxy / Cache
    1080: ("SOCKS",         "Dante 1.4.1",                      "proxy",         "high"),
    3128: ("Squid",         "Squid/3.5.27",                     "proxy",         "medium"),
    # Industrial / ICS
    102:  ("S7comm",        "Siemens S7-300 PLC",               "ics",           "critical"),
    502:  ("Modbus",        "Modbus TCP",                        "ics",           "critical"),
    # Misc legacy
    79:   ("Finger",        "GNU finger 1.37",                  "misc",          "low"),
    109:  ("POP2",          "popper 2.53",                      "misc",          "low"),
    119:  ("NNTP",          "INN 2.5.4",                        "misc",          "low"),
    194:  ("IRC-old",       "Hybrid IRCd 8.2.24",               "misc",          "low"),
    543:  ("Klogin",        "BSD klogind",                      "misc",          "medium"),
    544:  ("Kshell",        "BSD kshd",                         "misc",          "medium"),
    # Printer / File
    70:   ("Gopher",        "Gopher+/2.2",                      "misc",          "low"),
    111:  ("RPCbind",       "rpcbind 0.2.1",                    "network",       "high"),
    179:  ("BGP",           "Quagga 0.99.23.1",                 "network",       "high"),
}

_GENERIC_BANNERS = [
    "OpenSSH_5.9p1 Debian-5ubuntu1",
    "Apache/2.0.64 (Unix)",
    "Microsoft-IIS/6.0",
    "vsFTPd 1.2.1",
    "Postfix MTA 2.6.6",
    "ProFTPD 1.3.3a Server",
    "lighttpd/1.4.26",
    "nginx/0.8.54",
    "Exim smtpd 4.69",
    "WU-FTPD 2.6.2",
    "RomPager/4.07 UPnP/1.0",
    "3Com 3CDaemon FTP Server 2.0",
]

def _build_honeypot_table():
    table = {}
    rng = random.Random(42)
    for port in range(1, 1025):
        if port in _KNOWN_PORTS:
            svc, banner, category, risk = _KNOWN_PORTS[port]
        else:
            svc = f"SVC-{port}"
            banner = rng.choice(_GENERIC_BANNERS)
            # Assign categories based on port ranges
            if port < 20:    category, risk = "network", "medium"
            elif port < 100: category, risk = "network", "medium"
            elif port < 200: category, risk = "misc",    "low"
            elif port < 500: category, risk = "misc",    "low"
            else:            category, risk = "unknown", "low"
        table[port] = {
            "port": port, "service": svc, "banner": banner,
            "category": category, "risk": risk,
            "active": True, "connections": 0,
            "last_hit": None, "bytes_captured": 0,
        }
    return table

HONEYPOT_TABLE = _build_honeypot_table()
WELL_KNOWN_PORTS = sorted(p for p in _KNOWN_PORTS if p <= 1024)

ATTACK_COLORS = {
    "port_scan":        "#00d4ff",
    "stealth_scan":     "#a29bfe",
    "brute_force":      "#ff9f43",
    "credential_stuff": "#fd79a8",
    "vuln_scan":        "#feca57",
    "exploit_known":    "#ff6b6b",
    "syn_flood":        "#ff0000",
    "lateral_move":     "#ff3c5a",
    "zero_day":         "#fd79a8",
    "data_exfil":       "#e17055",
}

RISK_COLORS = {"critical":"#ff3c5a","high":"#ff9f43","medium":"#feca57","low":"#00d4ff"}


# ─────────────────────────────────────────────
# ML ANOMALY DETECTOR
# ─────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import numpy as np
        self.model = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
        self.scaler = StandardScaler()
        self.np = np
        self._train()

    def _train(self):
        np = self.np
        rng = np.random.RandomState(0)
        X = np.column_stack([
            rng.uniform(1, 20,   1000),
            rng.choice([22,80,443,25,53], 1000),
            rng.uniform(0, 5,    1000),
            rng.uniform(40, 600, 1000),
            rng.uniform(0, 0.2,  1000),
            rng.uniform(0, 1,    1000),
            rng.uniform(0, 2,    1000),
        ])
        self.scaler.fit(X)
        self.model.fit(self.scaler.transform(X))
        log.info("AnomalyDetector trained on %d samples", len(X))

    def score(self, f: dict) -> float:
        np = self.np
        vec = np.array([[
            f.get("packets_per_sec", 1),
            f.get("target_port", 80),
            f.get("unique_ports_hit", 0),
            f.get("avg_payload_size", 200),
            f.get("payload_entropy", 0),
            f.get("syn_flood_ratio", 0),
            f.get("failed_auth_rate", 0),
        ]])
        raw = self.model.decision_function(self.scaler.transform(vec))[0]
        return max(0, min(100, int((1 - (raw + 0.5)) * 80)))


# ─────────────────────────────────────────────
# HONEYPOT MANAGER
# ─────────────────────────────────────────────
class HoneypotManager:
    def __init__(self):
        self.honeypots = HONEYPOT_TABLE
        self.redirections = []
        self.total_redirected = 0
        self.lock = threading.Lock()

    def handle(self, attacker_ip, port, technique, payload_size=0):
        hp_port = port if 1 <= port <= 1024 else (port % 1024) or 80
        hp = self.honeypots.get(hp_port, self.honeypots[80])
        with self.lock:
            hp["connections"] += 1
            hp["bytes_captured"] += payload_size
            hp["last_hit"] = datetime.now().isoformat()
            self.total_redirected += 1
            rec = {
                "id":          hashlib.md5(f"{attacker_ip}{time.time()}".encode()).hexdigest()[:8],
                "attacker_ip": attacker_ip,
                "from_port":   port,
                "to_port":     hp_port,
                "service":     hp["service"],
                "banner":      hp["banner"],
                "category":    hp["category"],
                "risk":        hp["risk"],
                "technique":   technique,
                "ts":          datetime.now().strftime("%H:%M:%S"),
            }
            self.redirections.append(rec)
            if len(self.redirections) > 500:
                self.redirections = self.redirections[-500:]
        log.info("HIT  %s → :%d (%s) [%s]", attacker_ip, hp_port, hp["service"], technique)
        return rec

    def get_status(self):
        with self.lock:
            display = {p: dict(self.honeypots[p]) for p in WELL_KNOWN_PORTS if p in self.honeypots}
            return {
                "honeypots":        display,
                "total_redirected": self.total_redirected,
                "recent":           self.redirections[-20:][::-1],
                "hot_ports":        self._hot_ports(),
                "category_counts":  self._category_counts(),
            }

    def _hot_ports(self):
        hits = sorted(
            [(p, h["connections"], h["service"], h["risk"])
             for p, h in self.honeypots.items() if h["connections"] > 0],
            key=lambda x: x[1], reverse=True
        )
        return [{"port":p,"service":s,"hits":c,"risk":r} for p,c,s,r in hits[:12]]

    def _category_counts(self):
        cats = {}
        for hp in self.honeypots.values():
            if hp["connections"] > 0:
                cats[hp["category"]] = cats.get(hp["category"], 0) + hp["connections"]
        return cats


# ─────────────────────────────────────────────
# BENIGN TRAFFIC SIMULATOR (background only)
# ─────────────────────────────────────────────
class BenignSimulator:
    def __init__(self, cb):
        self.cb = cb
        self._t = threading.Thread(target=self._run, daemon=True)

    def start(self): self._t.start()

    def _run(self):
        while True:
            if random.random() < 0.4:
                ip = f"{random.randint(10,203)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
                self.cb("benign", {
                    "src_ip": ip,
                    "dst_port": random.choice([80,443,53,25,110,143]),
                    "protocol": "TCP",
                    "payload_size": random.randint(200, 1400),
                    "ts": datetime.now().strftime("%H:%M:%S"),
                })
            time.sleep(random.uniform(0.8, 2.5))


# ─────────────────────────────────────────────
# DECEPTION ORCHESTRATOR
# ─────────────────────────────────────────────
class DeceptionOrchestrator:
    def __init__(self):
        self.detector    = AnomalyDetector()
        self.honeypot    = HoneypotManager()
        self.benign_sim  = BenignSimulator(self._on_event)
        self.event_queue = collections.deque(maxlen=1000)
        self.stats = {
            "total_packets":        0,
            "threats_detected":     0,
            "attackers_redirected": 0,
            "benign_passed":        0,
            "active_attackers":     {},
            "timeline":             collections.deque(maxlen=120),
        }
        self._lock  = threading.Lock()
        self._tick_t = threading.Thread(target=self._tick, daemon=True)

    def start(self):
        self.benign_sim.start()
        self._tick_t.start()
        log.info("COGNISEC started — %d honeypot ports armed", len(self.honeypot.honeypots))

    def _tick(self):
        while True:
            time.sleep(1)
            with self._lock:
                self.stats["timeline"].append({
                    "t":         datetime.now().strftime("%H:%M:%S"),
                    "threats":   self.stats["threats_detected"],
                    "redirected":self.stats["attackers_redirected"],
                    "benign":    self.stats["benign_passed"],
                })

    # Called from /api/ingest
    def ingest_attack(self, src_ip, dst_port, technique, protocol,
                      payload_size, entropy, packets_per_sec,
                      unique_ports, syn_ratio, failed_auths):
        pkt = {
            "src_ip": src_ip, "dst_port": dst_port,
            "technique": technique, "protocol": protocol,
            "payload_size": payload_size, "entropy": entropy,
            "ts": datetime.now().strftime("%H:%M:%S"),
            "features": {
                "packets_per_sec": packets_per_sec,
                "target_port": dst_port,
                "unique_ports_hit": unique_ports,
                "avg_payload_size": payload_size,
                "payload_entropy": entropy,
                "syn_flood_ratio": syn_ratio,
                "failed_auth_rate": failed_auths,
            },
        }
        self._on_event("packet", pkt)
        return {"threat_score": pkt.get("threat_score", 0), "redirected": pkt.get("redirected", False)}

    def register_attacker(self, ip, profile, skill):
        with self._lock:
            self.stats["active_attackers"][ip] = {"ip": ip, "profile": profile, "skill": skill}
            self._push("new_attacker", {"ip": ip, "profile": profile, "skill": skill})

    def deregister_attacker(self, ip):
        with self._lock:
            self.stats["active_attackers"].pop(ip, None)
            self._push("attacker_gone", {"ip": ip})

    def _on_event(self, kind, data):
        with self._lock:
            if kind == "packet":
                self.stats["total_packets"] += 1
                score = self.detector.score(data.get("features", {}))
                data["threat_score"] = score
                data["color"] = ATTACK_COLORS.get(data.get("technique", ""), "#888")
                svc = HONEYPOT_TABLE.get(
                    data["dst_port"] if 1 <= data["dst_port"] <= 1024 else 80, {}
                ).get("service", "?")

                if score >= 45:
                    self.stats["threats_detected"] += 1
                    rec = self.honeypot.handle(
                        data["src_ip"], data["dst_port"],
                        data.get("technique", "unknown"),
                        data.get("payload_size", 0)
                    )
                    self.stats["attackers_redirected"] += 1
                    data["redirected"] = True
                    self._push("redirect", rec)
                else:
                    self.stats["benign_passed"] += 1
                    data["redirected"] = False

                self._push("packet", {
                    "src_ip": data["src_ip"], "dst_port": data["dst_port"],
                    "technique": data.get("technique", "unknown"),
                    "threat_score": score, "redirected": data["redirected"],
                    "color": data["color"], "ts": data["ts"],
                    "protocol": data.get("protocol", "TCP"), "service": svc,
                })

            elif kind == "benign":
                self.stats["benign_passed"] += 1
                port = data["dst_port"]
                svc_info = HONEYPOT_TABLE.get(port if 1 <= port <= 1024 else 80, {})
                self._push("benign_pkt", {
                    "src_ip":       data["src_ip"],
                    "dst_port":     port,
                    "protocol":     data.get("protocol", "TCP"),
                    "service":      svc_info.get("service", f"SVC-{port}"),
                    "technique":    "benign",
                    "threat_score": 0,
                    "redirected":   False,
                    "color":        "#3a6a84",
                    "ts":           data["ts"],
                })

    def _push(self, kind, data):
        self.event_queue.append({"kind": kind, "data": data, "ts": time.time()})

    def get_state(self):
        with self._lock:
            hp = self.honeypot.get_status()
            return {
                "stats": {
                    "total_packets":        self.stats["total_packets"],
                    "threats_detected":     self.stats["threats_detected"],
                    "attackers_redirected": self.stats["attackers_redirected"],
                    "benign_passed":        self.stats["benign_passed"],
                    "active_attackers":     list(self.stats["active_attackers"].values()),
                    "total_honeypot_ports": len(self.honeypot.honeypots),
                },
                "honeypots":           hp["honeypots"],
                "recent_redirections": hp["recent"],
                "hot_ports":           hp["hot_ports"],
                "category_counts":     hp["category_counts"],
                "timeline":            list(self.stats["timeline"]),
            }

    def drain_events(self, since=0):
        with self._lock:
            return [e for e in self.event_queue if e["ts"] > since]


orchestrator = DeceptionOrchestrator()