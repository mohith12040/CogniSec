#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           COGNISEC — Attack Simulator CLI                    ║
║  Sends real attack packets to the COGNISEC server.           ║
║  Run AFTER starting app.py:  python attacker.py              ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python attacker.py                    # interactive menu
    python attacker.py --host 127.0.0.1  # target a remote server
    python attacker.py --list             # list all attack types
"""

import argparse
import json
import random
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────
# ATTACK DEFINITIONS
# Each attack has:
#   name, description, technique tag,
#   ports   : list of ports to probe
#   packets : how many packets to send
#   pps     : packets-per-second (float)
#   entropy : payload entropy 0-1
#   syn_ratio, failed_auths
#   delay   : seconds between bursts
# ─────────────────────────────────────────────
ATTACKS = {
    "1": {
        "name":        "Port Scan (Full Range)",
        "desc":        "Sweeps all 1024 registered ports sequentially, looking for open services.",
        "technique":   "port_scan",
        "ports":       list(range(1, 1025)),
        "packets":     200,
        "pps":         40.0,
        "payload":     60,
        "entropy":     0.1,
        "syn_ratio":   0.3,
        "failed_auth": 0.0,
        "delay":       0.03,
        "skill":       1,
    },
    "2": {
        "name":        "Stealth SYN Scan (Slow)",
        "desc":        "Low-and-slow scan randomising port order to evade rate-based IDS.",
        "technique":   "stealth_scan",
        "ports":       random.sample(range(1, 1025), 150),
        "packets":     150,
        "pps":         2.5,
        "payload":     40,
        "entropy":     0.05,
        "syn_ratio":   0.95,
        "failed_auth": 0.0,
        "delay":       0.4,
        "skill":       3,
    },
    "3": {
        "name":        "SSH Brute Force",
        "desc":        "Rapid credential stuffing against SSH (port 22).",
        "technique":   "brute_force",
        "ports":       [22] * 80,
        "packets":     80,
        "pps":         20.0,
        "payload":     128,
        "entropy":     0.3,
        "syn_ratio":   0.8,
        "failed_auth": 0.85,
        "delay":       0.05,
        "skill":       1,
    },
    "4": {
        "name":        "FTP Brute Force",
        "desc":        "Dictionary attack against FTP (port 21) with common credentials.",
        "technique":   "brute_force",
        "ports":       [21] * 60,
        "packets":     60,
        "pps":         15.0,
        "payload":     96,
        "entropy":     0.25,
        "syn_ratio":   0.75,
        "failed_auth": 0.90,
        "delay":       0.07,
        "skill":       1,
    },
    "5": {
        "name":        "Web Vulnerability Scan",
        "desc":        "Probes HTTP/HTTPS endpoints for known CVEs, misconfigurations, and exposed dirs.",
        "technique":   "vuln_scan",
        "ports":       [80, 443, 8080, 8443, 8888, 9090, 81, 591, 631],
        "packets":     90,
        "pps":         12.0,
        "payload":     512,
        "entropy":     0.4,
        "syn_ratio":   0.2,
        "failed_auth": 0.1,
        "delay":       0.08,
        "skill":       2,
    },
    "6": {
        "name":        "SMB / Windows Exploit",
        "desc":        "Targets SMB (445), NetBIOS (139), and MSRPC (135) — EternalBlue-style.",
        "technique":   "exploit_known",
        "ports":       [445, 139, 135, 137, 138],
        "packets":     50,
        "pps":         18.0,
        "payload":     1024,
        "entropy":     0.65,
        "syn_ratio":   0.55,
        "failed_auth": 0.3,
        "delay":       0.06,
        "skill":       3,
    },
    "7": {
        "name":        "Database Attack (MySQL / MSSQL / Postgres)",
        "desc":        "Probes database ports with auth attempts and SQL injection payloads.",
        "technique":   "exploit_known",
        "ports":       [3306, 1433, 5432, 1521, 6379],
        "packets":     70,
        "pps":         14.0,
        "payload":     768,
        "entropy":     0.55,
        "syn_ratio":   0.4,
        "failed_auth": 0.75,
        "delay":       0.07,
        "skill":       3,
    },
    "8": {
        "name":        "SYN Flood DoS",
        "desc":        "High-rate SYN flood targeting port 80 — overwhelms the connection table.",
        "technique":   "syn_flood",
        "ports":       [80] * 300,
        "packets":     300,
        "pps":         150.0,
        "payload":     40,
        "entropy":     0.0,
        "syn_ratio":   1.0,
        "failed_auth": 0.0,
        "delay":       0.005,
        "skill":       1,
    },
    "9": {
        "name":        "Credential Stuffing (Multi-Service)",
        "desc":        "Sprays breached credentials across SSH, RDP, FTP, SMTP, and IMAP.",
        "technique":   "credential_stuff",
        "ports":       [22, 3389, 21, 25, 143, 110, 993, 995, 587, 465],
        "packets":     100,
        "pps":         8.0,
        "payload":     200,
        "entropy":     0.35,
        "syn_ratio":   0.6,
        "failed_auth": 0.95,
        "delay":       0.12,
        "skill":       2,
    },
    "10": {
        "name":        "Lateral Movement (Internal Pivot)",
        "desc":        "Simulates post-breach pivoting across RDP, SMB, WMI, and admin shares.",
        "technique":   "lateral_move",
        "ports":       [3389, 445, 139, 135, 5900, 5901, 22],
        "packets":     60,
        "pps":         6.0,
        "payload":     640,
        "entropy":     0.5,
        "syn_ratio":   0.35,
        "failed_auth": 0.2,
        "delay":       0.15,
        "skill":       4,
    },
    "11": {
        "name":        "Data Exfiltration (DNS / HTTPS Tunnelling)",
        "desc":        "Encodes data in DNS queries and HTTPS payloads to exfiltrate over covert channels.",
        "technique":   "data_exfil",
        "ports":       [53, 443, 80],
        "packets":     120,
        "pps":         5.0,
        "payload":     1400,
        "entropy":     0.92,
        "syn_ratio":   0.1,
        "failed_auth": 0.0,
        "delay":       0.2,
        "skill":       4,
    },
    "12": {
        "name":        "Zero-Day Exploit Attempt",
        "desc":        "Crafts anomalous packets mimicking an unknown exploit against HTTPS and Docker.",
        "technique":   "zero_day",
        "ports":       [443, 8443, 2375, 2376, 9200],
        "packets":     40,
        "pps":         25.0,
        "payload":     1500,
        "entropy":     0.97,
        "syn_ratio":   0.7,
        "failed_auth": 0.15,
        "delay":       0.04,
        "skill":       4,
    },
    "13": {
        "name":        "ICS / SCADA Attack",
        "desc":        "Targets industrial control ports Modbus (502) and S7comm (102).",
        "technique":   "exploit_known",
        "ports":       [502, 102],
        "packets":     30,
        "pps":         3.0,
        "payload":     256,
        "entropy":     0.6,
        "syn_ratio":   0.5,
        "failed_auth": 0.1,
        "delay":       0.3,
        "skill":       4,
    },
    "14": {
        "name":        "Full APT Campaign",
        "desc":        "Runs port_scan → vuln_scan → exploit → lateral_move → data_exfil in sequence.",
        "technique":   "multi_stage",
        "ports":       [],   # handled specially
        "packets":     0,
        "pps":         0,
        "payload":     0,
        "entropy":     0,
        "syn_ratio":   0,
        "failed_auth": 0,
        "delay":       0,
        "skill":       4,
    },
}

APT_STAGES = ["1", "5", "6", "10", "11"]   # used by attack 14

# ─────────────────────────────────────────────
# COLOURS (ANSI)
# ─────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
BLD= "\033[1m"
RST= "\033[0m"

SKILL_COLOR = {1: G, 2: Y, 3: M, 4: R}
TECH_COLOR  = {
    "port_scan":C, "stealth_scan":M, "brute_force":Y,
    "credential_stuff":M, "vuln_scan":Y, "exploit_known":R,
    "syn_flood":R, "lateral_move":R, "zero_day":M,
    "data_exfil":Y, "multi_stage":R,
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def _fake_ip():
    """Return a random attacker IP that looks external."""
    return f"{random.choice([45,103,185,91,194,77,62,185])}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def _post(url, payload):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        return {"error": str(e)}

def _check_server(base_url):
    try:
        with urllib.request.urlopen(f"{base_url}/api/state", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False

def _progress_bar(done, total, width=30):
    filled = int(width * done / max(total, 1))
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / max(total, 1))
    return f"[{bar}] {pct:3d}%"

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
def print_banner():
    print(f"""
{R}╔══════════════════════════════════════════════════════════╗
║  {W}{BLD}COGNISEC — Attack Simulator{RST}{R}                            ║
║  {DIM}Sends real attack packets to the COGNISEC deception engine{RST}{R} ║
╚══════════════════════════════════════════════════════════╝{RST}
""")

def print_menu():
    print(f"\n{C}{BLD}{'─'*62}{RST}")
    print(f"  {W}{BLD}SELECT ATTACK TYPE{RST}")
    print(f"{C}{'─'*62}{RST}")
    for key, atk in ATTACKS.items():
        sc = SKILL_COLOR.get(atk["skill"], W)
        tc = TECH_COLOR.get(atk["technique"], W)
        skill_label = ["","Novice","Intermediate","Advanced","APT/Nation"][atk["skill"]]
        print(f"  {C}{BLD}{key:>2}{RST}  {W}{atk['name']:<38}{RST}  "
              f"{tc}[{atk['technique']}]{RST}  {sc}{skill_label}{RST}")
    print(f"{C}{'─'*62}{RST}")
    print(f"   {DIM}q  Quit{RST}")
    print()

# ─────────────────────────────────────────────
# SEND ONE ATTACK WAVE
# ─────────────────────────────────────────────
def run_attack(key, base_url, src_ip, verbose=True):
    atk = ATTACKS[key]

    # APT multi-stage: recurse through sub-attacks
    if atk["technique"] == "multi_stage":
        print(f"\n{R}{BLD}⚡ APT CAMPAIGN INITIATED — {len(APT_STAGES)} stages{RST}\n")
        for i, sub_key in enumerate(APT_STAGES, 1):
            sub = ATTACKS[sub_key]
            print(f"  {M}STAGE {i}/{len(APT_STAGES)}: {sub['name']}{RST}")
            _post(f"{base_url}/api/attacker/register", {
                "ip": src_ip, "profile": "APT Operator", "skill": 4
            })
            run_attack(sub_key, base_url, src_ip, verbose=False)
            time.sleep(1.5)
        _post(f"{base_url}/api/attacker/deregister", {"ip": src_ip})
        print(f"\n  {G}✓ APT Campaign complete.{RST}")
        return

    tc = TECH_COLOR.get(atk["technique"], W)
    sc = SKILL_COLOR.get(atk["skill"], W)

    print(f"\n{tc}{BLD}⚡ {atk['name']}{RST}")
    print(f"  {DIM}{atk['desc']}{RST}")
    print(f"  Source IP : {C}{src_ip}{RST}")
    print(f"  Technique : {tc}{atk['technique']}{RST}  Skill: {sc}{'★'*atk['skill']}{'☆'*(4-atk['skill'])}{RST}")
    print(f"  Ports     : {len(atk['ports'])} probes  |  "
          f"Rate: {atk['pps']:.0f} pkt/s  |  Entropy: {atk['entropy']:.2f}")
    print()

    # Register attacker with the server
    skill_names = {1:"Script Kiddie",2:"Opportunist",3:"Persistent Actor",4:"APT Operator"}
    _post(f"{base_url}/api/attacker/register", {
        "ip": src_ip,
        "profile": skill_names.get(atk["skill"], "Unknown"),
        "skill": atk["skill"],
    })

    redirected = 0
    threats    = 0
    errors     = 0
    ports      = atk["ports"]
    total      = len(ports)

    for i, port in enumerate(ports):
        payload = {
            "src_ip":          src_ip,
            "dst_port":        port,
            "technique":       atk["technique"],
            "protocol":        "UDP" if port == 53 else "TCP",
            "payload_size":    atk["payload"] + random.randint(-20, 20),
            "entropy":         round(atk["entropy"] + random.uniform(-0.05, 0.05), 3),
            "packets_per_sec": atk["pps"] + random.uniform(-5, 5),
            "unique_ports":    min(i + 1, 1024),
            "syn_ratio":       atk["syn_ratio"],
            "failed_auths":    atk["failed_auth"],
        }

        result = _post(f"{base_url}/api/ingest", payload)

        if "error" in result:
            errors += 1
        else:
            if result.get("redirected"):
                redirected += 1
                status = f"{G}→ HONEYPOT{RST}"
            elif result.get("threat_score", 0) >= 45:
                threats += 1
                status = f"{Y}! THREAT{RST}"
            else:
                status = f"{DIM}  benign{RST}"

            if verbose and (result.get("redirected") or result.get("threat_score", 0) >= 45):
                score = result.get("threat_score", 0)
                bar_color = R if score >= 70 else Y if score >= 45 else G
                print(f"  :{port:<6} {status}  score={bar_color}{score:3d}{RST}  "
                      f"{_progress_bar(i+1, total, 20)}")

        # Print progress line every 10 packets when not verbose
        if not verbose and (i + 1) % 10 == 0:
            print(f"  {_progress_bar(i+1, total)}  {i+1}/{total} probes", end="\r")

        time.sleep(atk["delay"])

    # Deregister
    _post(f"{base_url}/api/attacker/deregister", {"ip": src_ip})

    # Summary
    print(f"\n  {'─'*50}")
    print(f"  {W}{BLD}ATTACK SUMMARY{RST}")
    print(f"  Probes sent   : {W}{total}{RST}")
    print(f"  → Honeypotted : {G}{BLD}{redirected}{RST}  ({int(redirected/max(total,1)*100)}%)")
    print(f"  ! Threats det.: {Y}{threats}{RST}")
    if errors:
        print(f"  ✗ Errors      : {R}{errors}{RST}  (is the server running?)")
    print()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="COGNISEC Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python attacker.py\n  python attacker.py --host 192.168.1.10\n  python attacker.py --list"
    )
    parser.add_argument("--host",   default="127.0.0.1", help="COGNISEC server host (default: 127.0.0.1)")
    parser.add_argument("--port",   default=5000, type=int, help="COGNISEC server port (default: 5000)")
    parser.add_argument("--list",   action="store_true", help="List all attack types and exit")
    parser.add_argument("--attack", default=None, help="Run a specific attack key directly (e.g. --attack 3)")
    parser.add_argument("--ip",     default=None, help="Override attacker source IP")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"

    if args.list:
        print_banner()
        print_menu()
        sys.exit(0)

    print_banner()
    print(f"  Target server : {C}{base_url}{RST}")

    # Check server is up
    sys.stdout.write(f"  Checking server... ")
    sys.stdout.flush()
    if not _check_server(base_url):
        print(f"{R}OFFLINE{RST}")
        print(f"\n  {R}✗ Cannot reach {base_url}{RST}")
        print(f"  Start the server first:  {W}python app.py{RST}\n")
        sys.exit(1)
    print(f"{G}ONLINE{RST}\n")

    src_ip = args.ip or _fake_ip()
    print(f"  Attacker IP   : {C}{src_ip}{RST}  {DIM}(randomised){RST}")

    # Non-interactive mode
    if args.attack:
        if args.attack not in ATTACKS:
            print(f"  {R}Unknown attack key: {args.attack}{RST}")
            sys.exit(1)
        run_attack(args.attack, base_url, src_ip)
        sys.exit(0)

    # Interactive loop
    while True:
        print_menu()
        try:
            choice = input(f"  {W}Enter attack number{RST} {DIM}(or q to quit){RST}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {DIM}Exiting.{RST}\n")
            break

        if choice.lower() == "q":
            print(f"\n  {DIM}Exiting.{RST}\n")
            break
        if choice not in ATTACKS:
            print(f"  {R}Invalid choice. Enter 1–{len(ATTACKS)} or q.{RST}")
            continue

        # Allow custom IP per attack
        custom = input(f"  {DIM}Custom source IP? (press Enter for random {src_ip}): {RST}").strip()
        if custom:
            src_ip = custom

        run_attack(choice, base_url, src_ip)

        again = input(f"  {DIM}Run another attack? [Y/n]: {RST}").strip().lower()
        if again == "n":
            print(f"\n  {DIM}Exiting.{RST}\n")
            break
        # Randomise IP for next round
        src_ip = args.ip or _fake_ip()


if __name__ == "__main__":
    main()
