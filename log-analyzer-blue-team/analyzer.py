import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque

def alert(msg):
    print(f"[ALERT] {msg}")
    sys.stdout.flush()

# ---------- SSH ----------
SSH_FAIL = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
SSH_OK = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

def parse_ssh_time(line, year):
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+", line)
    if not m:
        return None
    return datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")

def analyze_ssh(path, threshold=5, window=60):
    year = datetime.now().year
    recent = defaultdict(deque)      # ip -> deque[timestamps]
    total_fail = defaultdict(int)
    total_ok = defaultdict(int)
    bruteforce_flagged = set()

    with open(path, "r", errors="ignore") as f:
        for line in f:
            t = parse_ssh_time(line, year)
            if not t:
                continue

            mf = SSH_FAIL.search(line)
            if mf:
                ip = mf.group("ip")
                total_fail[ip] += 1

                q = recent[ip]
                q.append(t)

                cutoff = t - timedelta(seconds=window)
                while q and q[0] < cutoff:
                    q.popleft()

                if len(q) >= threshold and ip not in bruteforce_flagged:
                    bruteforce_flagged.add(ip)
                    alert(f"Possible brute force from {ip} (>= {threshold} failures in {window}s)")
                continue

            mo = SSH_OK.search(line)
            if mo:
                ip = mo.group("ip")
                total_ok[ip] += 1
                if total_fail[ip] >= threshold:
                    alert(f"Suspicious success after many failures from {ip} (fails={total_fail[ip]})")

    print("\n--- SSH Summary ---")
    for ip, cnt in sorted(total_fail.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:15} failed={cnt} success={total_ok.get(ip,0)}")
    sys.stdout.flush()

# ---------- APACHE ----------
IP_RE = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s")
STATUS_RE = re.compile(r'"\s(?P<status>\d{3})\s')
PATH_RE = re.compile(r'"\s(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s(?P<path>\S+)')

SUSPICIOUS = ("/.env", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin", "/wp-admin", "/admin", "/login")

def analyze_apache(path, suspicious_hits=3, high_4xx=20):
    hits = defaultdict(int)
    err4xx = defaultdict(int)
    sus = defaultdict(int)

    with open(path, "r", errors="ignore") as f:
        for line in f:
            mip = IP_RE.search(line)
            if not mip:
                continue
            ip = mip.group("ip")
            hits[ip] += 1

            ms = STATUS_RE.search(line)
            if ms:
                code = int(ms.group("status"))
                if 400 <= code < 500:
                    err4xx[ip] += 1

            mp = PATH_RE.search(line)
            if mp:
                p = mp.group("path")
                if any(p.startswith(s) for s in SUSPICIOUS):
                    sus[ip] += 1

    for ip, c in sus.items():
        if c >= suspicious_hits:
            alert(f"Suspicious web scanning from {ip} (suspicious hits={c})")

    for ip, c in err4xx.items():
        if c >= high_4xx:
            alert(f"High 4xx errors from {ip} (4xx={c})")

    print("\n--- Apache Summary ---")
    for ip in sorted(hits, key=hits.get, reverse=True):
        print(f"{ip:15} requests={hits[ip]} 4xx={err4xx[ip]} suspicious={sus[ip]}")
    sys.stdout.flush()

# ---------- CLI ----------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python analyzer.py ssh samples/ssh_auth.log")
        print("  python analyzer.py apache samples/apache_access.log")
        sys.exit(1)

    mode = sys.argv[1].lower()
    file_path = sys.argv[2]

    if mode == "ssh":
        analyze_ssh(file_path)
    elif mode == "apache":
        analyze_apache(file_path)
    else:
        print("Mode must be: ssh OR apache")
