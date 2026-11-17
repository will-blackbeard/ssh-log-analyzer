#!/usr/bin/env python3
"""
SSH Brute-Force & Auth Log Analyzer with IP Reputation Lookup
-------------------------------------------------------------
Reads a Linux auth log (e.g. /var/log/auth.log), finds IPs that hammer SSH with
bad passwords, spots "they got in!" moments, and checks each IP's reputation.

Zero dependencies (standard library only). Python 3.8+.

Try it with no real log:
    python3 ssh_log_analyzer.py --demo

Use it on a real log:
    python3 ssh_log_analyzer.py /var/log/auth.log
    export ABUSEIPDB_KEY="your-free-key"   # optional, adds reputation scores
"""

import argparse
import csv
import ipaddress
import json
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib import error, request

# ---------- 1. PATTERNS: how we recognise interesting log lines ----------
TS_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
TS_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s")
FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)

CACHE_FILE = "ip_cache.json"


# ---------- 2. PARSING ----------
def parse_ts(line, now):
    """Turn the start of a log line into a datetime (handles both common formats)."""
    m = TS_ISO.match(line)
    if m:
        return datetime.strptime(m["ts"], "%Y-%m-%dT%H:%M:%S")
    m = TS_SYSLOG.match(line)
    if m:
        text = f"{now.year} " + " ".join(m["ts"].split())
        t = datetime.strptime(text, "%Y %b %d %H:%M:%S")
        if t > now + timedelta(days=1):  # log from late last year
            t = t.replace(year=now.year - 1)
        return t
    return None


def parse_log(path):
    """Return {ip: info} where info holds failures, usernames, successes."""
    now = datetime.now()
    ips = defaultdict(lambda: {"fail_times": [], "users": Counter(),
                               "invalid_users": 0, "successes": []})
    with open(path, errors="replace") as f:
        for line in f:
            if "sshd" not in line:
                continue
            ts = parse_ts(line, now)
            if ts is None:
                continue
            m = FAILED.search(line)
            if m:
                d = ips[m["ip"]]
                d["fail_times"].append(ts)
                d["users"][m["user"]] += 1
                if m["invalid"]:
                    d["invalid_users"] += 1
                continue
            m = ACCEPTED.search(line)
            if m:
                ips[m["ip"]]["successes"].append((ts, m["user"], m["method"]))
    return ips


# ---------- 3. DETECTION ----------
def max_in_window(times, minutes):
    """Biggest number of events inside any sliding window of N minutes."""
    times = sorted(times)
    best, j = 0, 0
    for i, t in enumerate(times):
        while t - times[j] > timedelta(minutes=minutes):
            j += 1
        best = max(best, i - j + 1)
    return best


def analyze(ips, threshold, window):
    results = []
    for ip, d in ips.items():
        fails = sorted(d["fail_times"])
        flags = []
        burst = max_in_window(fails, window) if fails else 0
        if len(fails) >= threshold:
            flags.append("BRUTE_FORCE")
        if burst >= threshold:
            flags.append(f"FAST({burst} in {window}min)")
        if "root" in d["users"]:
            flags.append("TRIED_ROOT")
        if len(d["users"]) >= 5:
            flags.append("USERNAME_GUESSING")
        # Success AFTER failures from the same IP = scariest signal
        breach = [s for s in d["successes"] if fails and s[0] >= fails[0]]
        if breach and len(fails) >= 3:
            flags.append("POSSIBLE_BREACH")
        results.append({
            "ip": ip,
            "failures": len(fails),
            "unique_users": len(d["users"]),
            "top_users": ", ".join(u for u, _ in d["users"].most_common(3)),
            "first_seen": fails[0] if fails else None,
            "last_seen": fails[-1] if fails else None,
            "successes": len(d["successes"]),
            "breach_detail": (f"{breach[0][1]} via {breach[0][2]} at {breach[0][0]}"
                              if breach and "POSSIBLE_BREACH" in flags else ""),
            "flags": flags,
        })
    results.sort(key=lambda r: ("POSSIBLE_BREACH" in r["flags"], r["failures"]),
                 reverse=True)
    return results


# ---------- 4. IP REPUTATION ----------
def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def http_json(url, headers=None):
    req = request.Request(url, headers=headers or {})
    with request.urlopen(req, timeout=10) as r:
        return json.load(r)


def lookup_ip(ip, cache, key, mock=False):
    if mock:  # fake but stable numbers, for the demo only
        n = sum(map(ord, ip))
        return {"abuse_score": (n * 7) % 100, "reports": n % 300,
                "country": "DEMO", "isp": "Demo ISP (mock)", "hosting": n % 2 == 0}
    if ip in cache:
        return cache[ip]
    if not is_public(ip):
        return {"note": "private/reserved - skipped"}
    info = {}
    try:
        if key:  # AbuseIPDB: free tier, 1000 checks/day
            d = http_json(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                {"Key": key, "Accept": "application/json"})["data"]
            info.update(abuse_score=d["abuseConfidenceScore"],
                        reports=d["totalReports"],
                        country=d.get("countryCode"), isp=d.get("isp"))
        # ip-api.com: free, no key, ~45 requests/minute
        g = http_json(f"http://ip-api.com/json/{ip}?fields=status,country,isp,hosting")
        if g.get("status") == "success":
            info.setdefault("country", g["country"])
            info.setdefault("isp", g["isp"])
            info["hosting"] = g.get("hosting")
        time.sleep(1.5)  # be polite to the free service
    except (error.URLError, TimeoutError, KeyError, ValueError) as e:
        info["error"] = str(e)
        return info  # don't cache failures
    cache[ip] = info
    return info


def load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except OSError:
        pass


def verdict(r):
    rep = r.get("rep", {})
    score = rep.get("abuse_score") or 0
    if "POSSIBLE_BREACH" in r["flags"]:
        return "CRITICAL"
    if score >= 75 or r["failures"] >= 50:
        return "HIGH"
    if r["flags"]:
        return "MEDIUM"
    return "LOW"


# ---------- 5. REPORTING ----------
def print_report(results, total_lines_note, top):
    line = "=" * 78
    print(line)
    print("SSH AUTH LOG ANALYSIS")
    print(line)
    print(total_lines_note)
    print(f"IPs seen: {len(results)}   |   "
          f"Flagged: {sum(1 for r in results if r['flags'])}")
    print()
    for r in results[:top]:
        rep = r.get("rep", {})
        print(f"[{r['verdict']}] {r['ip']}")
        print(f"   failed logins : {r['failures']}  "
              f"(tried {r['unique_users']} usernames: {r['top_users'] or '-'})")
        if r["first_seen"]:
            print(f"   active        : {r['first_seen']}  ->  {r['last_seen']}")
        print(f"   flags         : {', '.join(r['flags']) or 'none'}")
        if r["breach_detail"]:
            print(f"   !! LOGIN SUCCEEDED: {r['breach_detail']}")
        if "abuse_score" in rep:
            print(f"   reputation    : abuse score {rep['abuse_score']}/100, "
                  f"{rep.get('reports', 0)} reports")
        if rep.get("country") or rep.get("isp"):
            host = " (datacenter/hosting)" if rep.get("hosting") else ""
            print(f"   whois-ish     : {rep.get('country', '?')} - "
                  f"{rep.get('isp', '?')}{host}")
        if rep.get("note") or rep.get("error"):
            print(f"   reputation    : {rep.get('note') or 'lookup failed: ' + rep['error']}")
        print()
    print(line)
    print("WHAT TO DO NEXT")
    print(line)
    crit = [r["ip"] for r in results if r["verdict"] == "CRITICAL"]
    high = [r["ip"] for r in results if r["verdict"] == "HIGH"]
    if crit:
        print(f"* CRITICAL: check what {', '.join(crit)} did after logging in, "
              "change that account's password, look for new SSH keys.")
    if high or crit:
        print("* Block the bad IPs (firewall or fail2ban) and turn OFF password "
              "login in favour of SSH keys.")
    if not (crit or high):
        print("* Nothing scary found. Keep watching.")


def write_csv(results, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["verdict", "ip", "failures", "unique_users", "top_users",
                    "first_seen", "last_seen", "successes", "flags",
                    "abuse_score", "country", "isp"])
        for r in results:
            rep = r.get("rep", {})
            w.writerow([r["verdict"], r["ip"], r["failures"], r["unique_users"],
                        r["top_users"], r["first_seen"], r["last_seen"],
                        r["successes"], "|".join(r["flags"]),
                        rep.get("abuse_score", ""), rep.get("country", ""),
                        rep.get("isp", "")])


# ---------- 6. DEMO LOG GENERATOR ----------
def make_demo(path):
    """Write a pretend auth.log with a loud attacker, a sneaky one, a breach, and normal users."""
    random.seed(7)
    now = datetime.now().replace(microsecond=0)
    start = now - timedelta(hours=6)
    rows = []

    def add(t, msg):
        stamp = f"{t:%b} {t.day:2d} {t:%H:%M:%S}"
        rows.append((t, f"{stamp} server sshd[{random.randint(1000, 9999)}]: {msg}"))

    names = ["admin", "root", "ubuntu", "test", "oracle", "postgres", "pi", "user", "guest"]
    # Loud bot: 120 tries in ~10 minutes
    t0 = start + timedelta(hours=1)
    for i in range(120):
        u = random.choice(names)
        pre = "invalid user " if u != "root" else ""
        add(t0 + timedelta(seconds=i * 5),
            f"Failed password for {pre}{u} from 203.0.113.50 port {random.randint(30000, 60000)} ssh2")
    # Sneaky slow attacker: root only, spread over hours
    for i in range(14):
        add(start + timedelta(minutes=i * 25),
            f"Failed password for root from 198.51.100.23 port {random.randint(30000, 60000)} ssh2")
    # Attacker who eventually guesses a password
    t1 = start + timedelta(hours=3)
    for i in range(9):
        add(t1 + timedelta(seconds=i * 20),
            f"Failed password for invalid user admin from 192.0.2.77 port {40000 + i} ssh2")
    add(t1 + timedelta(seconds=200),
        "Accepted password for admin from 192.0.2.77 port 40010 ssh2")
    # Normal people
    for i in range(4):
        add(start + timedelta(minutes=45 * i + 10),
            "Accepted publickey for will from 10.0.0.5 port 51000 ssh2")
    add(start + timedelta(hours=2), "Failed password for will from 192.168.1.20 port 51234 ssh2")
    add(start + timedelta(hours=2, seconds=30),
        "Accepted password for will from 192.168.1.20 port 51240 ssh2")

    rows.sort(key=lambda x: x[0])
    with open(path, "w") as f:
        f.write("\n".join(line for _, line in rows) + "\n")


# ---------- 7. MAIN ----------
def main():
    ap = argparse.ArgumentParser(description="SSH brute-force & auth log analyzer")
    ap.add_argument("logfile", nargs="?", help="path to auth.log")
    ap.add_argument("--demo", action="store_true",
                    help="make a fake log, analyze it, use mock reputation data")
    ap.add_argument("--threshold", type=int, default=5,
                    help="failed logins before we call it brute force (default 5)")
    ap.add_argument("--window", type=int, default=10,
                    help="minutes for the 'too fast' check (default 10)")
    ap.add_argument("--no-lookup", action="store_true", help="skip reputation lookups")
    ap.add_argument("--top", type=int, default=15, help="how many IPs to show")
    ap.add_argument("--csv", help="also save results to this CSV file")
    args = ap.parse_args()

    if args.demo:
        args.logfile = "demo_auth.log"
        make_demo(args.logfile)
        print(f"(Demo mode: wrote fake log to {args.logfile}; "
              "reputation numbers are MOCK.)\n")
    if not args.logfile:
        ap.error("give a log file path, or use --demo")
    if not os.path.exists(args.logfile):
        sys.exit(f"File not found: {args.logfile}")

    ips = parse_log(args.logfile)
    results = analyze(ips, args.threshold, args.window)

    cache = load_cache()
    key = os.environ.get("ABUSEIPDB_KEY")
    for r in results:
        # only look up suspicious IPs; no need to ask about every typo
        if r["flags"] and not args.no_lookup:
            r["rep"] = lookup_ip(r["ip"], cache, key, mock=args.demo)
        else:
            r["rep"] = {}
        r["verdict"] = verdict(r)
    if not args.demo:
        save_cache(cache)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda r: (order[r["verdict"]], -r["failures"]))

    if not key and not args.no_lookup and not args.demo:
        print("Tip: set ABUSEIPDB_KEY (free) to get abuse scores. "
              "Using location lookup only.\n")
    print_report(results, f"Log file: {args.logfile}", args.top)
    if args.csv:
        write_csv(results, args.csv)
        print(f"\nSaved CSV: {args.csv}")


if __name__ == "__main__":
    main()
