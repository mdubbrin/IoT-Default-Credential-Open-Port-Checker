import argparse
import json
import socket

def load_defaults(path="defaults.json"):
    with open(path) as f:
        return json.load(f)


def load_wordlist(path):
    passwords = []
    seen = set()

    with open(path) as f:
        for line in f:
            password = line.rstrip("\n\r")
            password = password.strip()
            if not password or password.startswith("#"):
                continue
            if password in seen:
                continue
            seen.add(password)
            passwords.append(password)

    return passwords

def defaults_for_port(defaults, port):
    return [d for d in defaults if d["port"] == port]


def credential_candidates_for_port(defaults, port, extra_passwords=None):
    candidates = []
    seen = set()

    for entry in defaults_for_port(defaults, port):
        username = entry.get("username")
        password = entry.get("password")

        if username is None:
            continue

        key = (entry["service"], entry["port"], username, password)
        if key not in seen:
            seen.add(key)
            candidates.append({
                "service": entry["service"],
                "port": entry["port"],
                "username": username,
                "password": password,
                "source": "default",
            })

        if not extra_passwords:
            continue

        for extra_password in extra_passwords:
            key = (entry["service"], entry["port"], username, extra_password)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "service": entry["service"],
                "port": entry["port"],
                "username": username,
                "password": extra_password,
                "source": "wordlist",
            })

    return candidates
#List of standard service ports
PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    3306: "MYSQL",
    3386: "RDP",
    8080: "HTTP-alt",
    8081: "HTTP-alt2",
    8443: "HTTPS-alt",
    8291: "Winbox",
    37777: "DVR-common",
    9100: "Printer-RAW",
}

def check_port(ip, port, timeout=2):
    #Try to connect to ip:port. Return True if open, False otherwise
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
        
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_target(ip, timeout=2):
    #Scan all PORTS against ip. Returns dict of {port: (name, is_open)}
    results = {}

    for port, name in PORTS.items():
        is_open = check_port(ip, port, timeout)
        results[port] = (name, is_open)
    return results


def print_results(ip, results):
    print(f"\n{ip}")

    open_count = 0

    for port, (name, is_open) in results.items():
        if is_open:
            print(f"{port:<6} {name:<15} OPEN")
            open_count += 1

    if open_count == 0:
        print("(no common ports open)")
    return open_count


def print_credential_candidates(results, defaults, extra_passwords=None, limit=5):
    printed_header = False

    for port, (name, is_open) in results.items():
        if not is_open:
            continue

        candidates = credential_candidates_for_port(defaults, port, extra_passwords)
        if not candidates:
            continue

        if not printed_header:
            print("\nCredential candidates:")
            printed_header = True

        print(f"{port:<6} {name:<15} {len(candidates)} candidates")

        for candidate in candidates[:limit]:
            password = candidate["password"] if candidate["password"] != "" else "<blank>"
            print(f"      {candidate['username']} / {password} [{candidate['source']}]")

        if len(candidates) > limit:
            print(f"      ... {len(candidates) - limit} more")


if __name__ == "__main__":
    print("This tool is for educational purposes only. Do not use this against anything that you do not own or have explicit, written permission from the owner to test. You have been warned....\n\n\n")

    parser = argparse.ArgumentParser(description="Scan targets for common open ports and report known credential candidates.")
    parser.add_argument("targets_file", help="File containing one target IP or host per line")
    parser.add_argument("timeout_sec", nargs="?", type=int, default=2, help="Socket timeout in seconds")
    parser.add_argument("--wordlist", "-w", help="Optional password wordlist to augment the default credential list")
    args = parser.parse_args()

    targets_file = args.targets_file
    timeout = args.timeout_sec

    defaults = load_defaults()
    extra_passwords = load_wordlist(args.wordlist) if args.wordlist else None

    total_targets = 0
    total_open = 0

    with open(targets_file) as f:
        for line in f:
            ip = line.strip()
            if not ip:
                continue
            total_targets += 1
            results = scan_target(ip, timeout)
            total_open += print_results(ip, results)
            if extra_passwords:
                print_credential_candidates(results, defaults, extra_passwords)
    print(f"\nNumber of targets scanned:{total_targets}\nNumber of open ports:{total_open}")
