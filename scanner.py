import socket
import json

def load_defaults(path="defaults.json"):
    with open(path) as f:
        return json.load(f)

def defaults_for_port(defaults, port):
    return [d for d in defaults if d["port"] == port]

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
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


if __name__ == "__main__":
    import sys

    print("This tool is for educational purposes only. Do not use this against anything that you do not own or have explicit, written permission from the owner to test. You have been warned....\n\n\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <targets_file> [timeout_sec]")
        sys.exit(1)

    targets_file = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 2

    defaults = load_defaults()

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
    print(f"\nNumber of targets scanned:{total_targets}\nNumber of open ports:{total_open}")