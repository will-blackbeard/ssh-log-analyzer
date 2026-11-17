# SSH Brute-Force & Auth Log Analyzer

A lightweight Python tool that reads Linux SSH auth logs, detects brute-force
activity, and enriches suspicious IPs with threat-intelligence lookups.
No dependencies, no paid software.

![demo](demo.png)

## What it detects
- Brute force: many failed logins from one IP
- Fast attacks: a burst of failures in a short window (sliding window)
- Username guessing and attempts against `root`
- **Possible compromise**: a successful login after repeated failures
- IP reputation: AbuseIPDB score (free API) plus country/ISP/hosting via ip-api

## Usage
    python3 ssh_log_analyzer.py --demo                    # try it on a fake log
    python3 ssh_log_analyzer.py /var/log/auth.log --csv report.csv
    export ABUSEIPDB_KEY="..."                            # optional

## How it works
1. Parse `sshd` lines with regex (supports syslog and ISO timestamps)
2. Group events per source IP
3. Flag by threshold and time window
4. Correlate failures with later successes
5. Look up only flagged IPs (cached, rate-limited)
6. Output verdict: LOW / MEDIUM / HIGH / CRITICAL

## MITRE ATT&CK mapping
T1110 Brute Force (T1110.001 Password Guessing), T1078 Valid Accounts

## Limitations / next steps
- Only parses OpenSSH logs
- Next: auto-generated block list, Windows Event ID 4625, alerting
