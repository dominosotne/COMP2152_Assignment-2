"""
Author: Alikhan Zhilkibayev
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import datetime
import os
import platform
import socket
import sqlite3
import threading


print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")


# Maps well-known TCP port numbers to human-readable service names for scan output.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


class NetworkTool:
    """Base class for network utilities with a validated target address."""

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property exposes target like a normal attribute while the real value stays in
    # private __target, so callers cannot bypass validation. The setter runs every time
    # target is assigned, which keeps empty or invalid values from corrupting state. This
    # is clearer and safer than letting external code read or write self.__target directly.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it gets the target property, setter validation,
# and destructor behavior without rewriting them. For example, PortScanner(..., target)
# calls super().__init__(target), which initializes the private __target field and makes
# scanner.target and scanner.target = ... behave exactly like any NetworkTool instance.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # If the host were unreachable or the network failed, connect_ex or other socket
        # calls could raise OSError (socket.error). Without try-except, that exception
        # would crash the worker thread and could leave the whole scan incomplete. The
        # handler prints a clear message so one bad port does not stop the entire range.
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def get_open_ports(self):
        return [t for t in self.scan_results if t[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Each connect waits up to one second for a timeout, so scanning 1024 ports
    # sequentially could take many minutes. Threads probe many ports concurrently,
    # so wall-clock time stays much lower. Without threads, a full localhost scan would
    # still work but would be unnecessarily slow and poor UX for an interactive tool.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )"""
        )
        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now())),
            )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn is not None:
            conn.close()


def load_past_scans():
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
            return
        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
    except sqlite3.Error:
        print("No past scans found.")
    finally:
        if conn is not None:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        raw_target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
        target_ip = raw_target if raw_target else "127.0.0.1"
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
    else:
        if not (1 <= start_port <= 1024 and 1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to the start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)
            open_ports = scanner.get_open_ports()
            open_ports.sort(key=lambda x: x[0])
            print(f"\n--- Scan Results for {target_ip} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")
            save_results(target_ip, scanner.scan_results)
            history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if history == "yes":
                load_past_scans()


# Q5: New Feature Proposal
# Add a "Port Risk Classifier" that runs after get_open_ports(): for each open port, use
# nested if-statements (or a list comprehension with conditional expressions) to label
# risk as HIGH (e.g. 21, 22, 23, 3389), MEDIUM (e.g. 25, 110, 143, 3306), or LOW, then
# append (port, service, risk_level) and print a short risk report. This helps students
# see which exposed services deserve attention without replacing a full vulnerability scan.
# Diagram: See diagram_101574906.png in the repository root
