#!/usr/bin/env python3
"""
Port & ARP-RARP Scanner Tool
أداة مسح المنافذ و ARP و RARP
مشروع مادة لغة البرمجة للأمن السيبراني
Pure Python - لا مكتبات خارجية
"""

import argparse
import socket
import subprocess
import platform
import sys
import os
import logging
import json
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

__version__ = "1.0.0"
__author__ = "Cybersecurity Programming Course Project"

# ==================== إعداد التسجيل ====================
def setup_logging(level: str = "INFO"):
    """إعداد نظام التسجيل مع مستوى محدد"""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    return logging.getLogger("PortARPScanner")

# ==================== تحميل الإعدادات ====================
def load_config(config_path: str = None) -> dict:
    """تحميل ملف الإعدادات إن وُجد، وإلا استخدام القيم الافتراضية"""
    defaults = {
        "default_ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
        "timeout": 1.0,
        "max_threads": 50,
        "ping_timeout": 1
    }
    if not config_path:
        return defaults
    try:
        if not os.path.isfile(config_path):
            logging.warning(f"Config file not found: {config_path} - using defaults")
            return defaults
        with open(config_path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        defaults.update(user_cfg)
        logging.info(f"Config loaded from: {config_path}")
        return defaults
    except json.JSONDecodeError:
        logging.error(f"Config file is corrupted or invalid JSON: {config_path}")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied reading config file: {config_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading config: {e}")
        sys.exit(1)

# ==================== Network Auto-Detect (works on ANY LAN) ====================
def get_local_ip() -> str:
    """
    Detect this machine's primary local IP on ANY network.
    Multiple methods so it works online/offline, Windows/Linux/Kali.
    """
    # Method 1: UDP socket trick (works even without real traffic)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # Method 2: hostname
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # Method 3: getaddrinfo
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass

    # Method 4: OS commands
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(["ipconfig"], text=True, timeout=8, errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if "IPv4" in line and ":" in line:
                    part = line.split(":")[-1].strip()
                    try:
                        ipaddress.ip_address(part)
                        if not part.startswith("127."):
                            return part
                    except ValueError:
                        pass
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show", "scope", "global"],
                    text=True, timeout=5, errors="ignore"
                )
                for line in out.splitlines():
                    parts = line.split()
                    if "inet" in parts:
                        idx = parts.index("inet")
                        if idx + 1 < len(parts):
                            ip = parts[idx + 1].split("/")[0]
                            try:
                                ipaddress.ip_address(ip)
                                if not ip.startswith("127."):
                                    return ip
                            except ValueError:
                                pass
            except Exception:
                pass
            try:
                out = subprocess.check_output(["hostname", "-I"], text=True, timeout=5, errors="ignore")
                for ip in out.split():
                    try:
                        ipaddress.ip_address(ip)
                        if not ip.startswith("127."):
                            return ip
                    except ValueError:
                        pass
            except Exception:
                pass
    except Exception:
        pass

    return "127.0.0.1"


def _mask_to_prefix(mask: str) -> int:
    """Convert dotted netmask to prefix length"""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return 24


def get_local_prefix_len(ip: str = None) -> int:
    """Detect real subnet prefix for this machine (any network)."""
    if not ip:
        ip = get_local_ip()
    system = platform.system().lower()

    try:
        if system == "windows":
            out = subprocess.check_output(["ipconfig"], text=True, timeout=8, errors="ignore")
            lines = out.splitlines()
            last_ip = None
            for line in lines:
                s = line.strip()
                if "IPv4" in s and ":" in s:
                    part = s.split(":")[-1].strip()
                    try:
                        ipaddress.ip_address(part)
                        if not part.startswith("127."):
                            last_ip = part
                    except ValueError:
                        pass
                if last_ip and ("Subnet" in s or "Mask" in s) and ":" in s:
                    mask = s.split(":")[-1].strip()
                    if mask.count(".") == 3:
                        if last_ip == ip:
                            return _mask_to_prefix(mask)
            # second pass: any mask near matching IP
            last_ip = None
            for line in lines:
                s = line.strip()
                if "IPv4" in s and ":" in s:
                    part = s.split(":")[-1].strip()
                    try:
                        ipaddress.ip_address(part)
                        if not part.startswith("127."):
                            last_ip = part
                    except ValueError:
                        pass
                if last_ip and ("Subnet" in s or "Mask" in s) and ":" in s:
                    mask = s.split(":")[-1].strip()
                    if mask.count(".") == 3 and last_ip:
                        return _mask_to_prefix(mask)
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show"],
                    text=True, timeout=5, errors="ignore"
                )
                for line in out.splitlines():
                    if ip in line and "inet" in line:
                        parts = line.split()
                        idx = parts.index("inet")
                        cidr = parts[idx + 1]
                        if "/" in cidr:
                            return int(cidr.split("/")[1])
            except Exception:
                pass
            try:
                out = subprocess.check_output(["ifconfig"], text=True, timeout=5, errors="ignore")
                for block in out.split("\n\n"):
                    if ip in block:
                        for line in block.splitlines():
                            if "netmask" in line.lower():
                                parts = line.split()
                                for k, p in enumerate(parts):
                                    if p.lower() == "netmask" and k + 1 < len(parts):
                                        mask = parts[k + 1]
                                        if mask.startswith("0x"):
                                            return bin(int(mask, 16)).count("1")
                                        if mask.count(".") == 3:
                                            return _mask_to_prefix(mask)
            except Exception:
                pass
    except Exception:
        pass
    return 24


def get_network_cidr(ip: str = None) -> str:
    """
    Auto-detect local network CIDR for ANY user / ANY LAN.
    Uses real IP + subnet mask; falls back to /24.
    """
    if not ip:
        ip = get_local_ip()
    if not ip or ip.startswith("127."):
        return "192.168.1.0/24"
    try:
        prefix = get_local_prefix_len(ip)
        if prefix < 16:
            prefix = 16  # avoid huge accidental scans as default
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except Exception:
        try:
            return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
        except Exception:
            return "192.168.1.0/24"


def get_default_gateway() -> str:
    """Detect default gateway on the current network (any LAN)."""
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(["ipconfig"], text=True, timeout=8, errors="ignore")
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    try:
                        ipaddress.ip_address(gw)
                        return gw
                    except ValueError:
                        pass
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "route", "show", "default"],
                    text=True, timeout=5, errors="ignore"
                )
                parts = out.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
            except Exception:
                pass
    except Exception:
        pass
    try:
        ip = get_local_ip()
        if ip and not ip.startswith("127."):
            parts = ip.split(".")
            parts[-1] = "1"
            return ".".join(parts)
    except Exception:
        pass
    return ""

def is_valid_ip(ip: str) -> bool:
    """التحقق من صحة عنوان IP"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_mac(mac: str) -> bool:
    """التحقق من صحة عنوان MAC"""
    mac = mac.replace("-", ":").replace(".", ":").lower()
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    try:
        return all(0 <= int(p, 16) <= 255 for p in parts)
    except ValueError:
        return False

def normalize_mac(mac: str) -> str:
    """توحيد صيغة MAC إلى aa:bb:cc:dd:ee:ff"""
    mac = mac.replace("-", ":").replace(".", ":").lower()
    parts = mac.split(":")
    return ":".join(f"{int(p, 16):02x}" for p in parts)

# ==================== مسح المنافذ (Port Scanner) ====================
def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP connect scan for a single port (Pure Python socket)."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # connect_ex returns 0 only when the port is open and accepting
        return sock.connect_ex((host, port)) == 0
    except (socket.gaierror, socket.error, OSError, ValueError):
        return False
    except Exception:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

def parse_ports(ports_str: str) -> list:
    """Parse port string like 80,443 or 1-100 or mix"""
    if not ports_str or not ports_str.strip():
        print("\n  [Error] Ports cannot be empty")
        print("  Example: 80  or  22,80,443  or  1-1000")
        raise SystemExit(1)

    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                if start > end:
                    print(f"\n  [Error] Invalid port range '{part}': start must be <= end")
                    print("  Example: 1-1000")
                    raise SystemExit(1)
                if start < 1 or end > 65535:
                    print(f"\n  [Error] Invalid port range '{part}': ports must be between 1 and 65535")
                    print("  Example: 1-1000")
                    raise SystemExit(1)
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"\n  [Error] Invalid port range: '{part}'")
                print("  Example: 80  or  22,80,443  or  1-1000")
                raise SystemExit(1)
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    print(f"\n  [Error] Invalid port '{part}': must be between 1 and 65535")
                    print("  Example: 80  or  22,80,443  or  1-1000")
                    raise SystemExit(1)
                ports.add(p)
            except ValueError:
                print(f"\n  [Error] Invalid port: '{part}' (must be a number)")
                print("  Example: 80  or  22,80,443  or  1-1000")
                raise SystemExit(1)

    if not ports:
        print("\n  [Error] No valid ports found")
        print("  Example: 80  or  22,80,443  or  1-1000")
        raise SystemExit(1)

    return sorted(ports)

def port_scan(host: str, ports: list, timeout: float, max_threads: int, logger) -> dict:
    """Scan TCP ports on a single target"""
    host = host.strip()

    def _reject(msg):
        logger.error(msg)
        print(f"\n  [Error] {msg}")
        print("  Example of valid target: 192.168.1.1  or  scanme.nmap.org")
        raise SystemExit(1)

    if not host:
        _reject("Target cannot be empty")

    if is_valid_ip(host):
        pass  # valid IP address
    elif host.replace(".", "").isdigit() and host.count(".") != 3:
        # Reject pure numbers or incomplete IPs like "122365" or "192.168"
        _reject(f"Invalid target: '{host}' is not a valid IP address or hostname")
    else:
        # Try to resolve as hostname
        try:
            resolved = socket.gethostbyname(host)
            host = resolved
        except socket.gaierror:
            _reject(f"Invalid target: '{host}' is not a valid IP address or hostname")

    logger.info(f"Starting port scan on {host} ...")
    logger.info(f"Ports: {len(ports)} | Timeout: {timeout}s | Threads: {max_threads}")

    open_ports = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
                    logger.info(f"[OPEN] Port {port}/tcp")
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")

    elapsed = time.time() - start_time
    result = {
        "host": host,
        "open_ports": sorted(open_ports),
        "total_scanned": len(ports),
        "elapsed_seconds": round(elapsed, 2)
    }
    return result

# ==================== ARP ====================
def _parse_linux_arp_output(output: str) -> list:
    """Parse ARP output from arp -a / arp -n / ip neigh"""
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
        if " at " in line:
            try:
                if "(" in line and ")" in line:
                    ip_part = line.split("(")[1].split(")")[0]
                else:
                    ip_part = line.split()[0]
                mac_part = line.split(" at ")[1].split()[0]
                if mac_part.lower() in ("<incomplete>", "incomplete"):
                    continue
                if is_valid_ip(ip_part) and is_valid_mac(mac_part):
                    entries.append({"ip": ip_part, "mac": normalize_mac(mac_part), "type": "dynamic"})
            except (IndexError, ValueError):
                continue
        else:
            # Format: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
            # or: 192.168.1.1 0x1 0x2 00:11:22:33:44:55 * eth0  (/proc/net/arp style via arp -n)
            parts = line.split()
            if len(parts) >= 2 and is_valid_ip(parts[0]):
                ip = parts[0]
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1]
                        if is_valid_mac(mac):
                            state = parts[-1] if parts else "unknown"
                            entries.append({"ip": ip, "mac": normalize_mac(mac), "type": state})
                else:
                    # arp -n format: IP HW-type Flags MAC Mask Device
                    for p in parts[1:]:
                        if is_valid_mac(p):
                            entries.append({"ip": ip, "mac": normalize_mac(p), "type": "dynamic"})
                            break
    return entries


def _read_proc_net_arp() -> list:
    """Read /proc/net/arp directly (Linux only, very reliable)"""
    entries = []
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
        # Skip header: IP address HW type Flags HW address Mask Device
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3]
                if is_valid_ip(ip) and is_valid_mac(mac) and mac != "00:00:00:00:00:00":
                    entries.append({"ip": ip, "mac": normalize_mac(mac), "type": "dynamic"})
    except Exception:
        pass
    return entries


def _is_valid_host_mac(mac: str) -> bool:
    """Reject broadcast / empty / multicast MACs that pollute ARP results."""
    if not mac:
        return False
    m = mac.lower().replace("-", ":")
    if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "unknown"):
        return False
    # Multicast MAC: least significant bit of first octet is 1
    try:
        first = int(m.split(":")[0], 16)
        if first & 0x01:
            return False
    except Exception:
        return False
    return is_valid_mac(m)


def _is_usable_arp_ip(ip: str) -> bool:
    """Keep only unicast host IPs (drop multicast / broadcast / link-local noise)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    if addr.is_loopback:
        return False
    # 169.254.x.x link-local usually not useful in LAN scan results
    if addr.is_link_local:
        return False
    return True


def get_arp_table(logger) -> list:

    """Read ARP table using system commands (Windows & Linux/Kali compatible)"""
    system = platform.system().lower()
    entries = []

    try:
        if system == "windows":
            output = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.STDOUT, text=True, timeout=15
            )
            for line in output.splitlines():
                line = line.strip()
                parts = line.split()
                if len(parts) >= 2 and is_valid_ip(parts[0]):
                    ip = parts[0]
                    mac = parts[1].replace("-", ":").lower()
                    if is_valid_mac(mac):
                        entries.append({
                            "ip": ip,
                            "mac": normalize_mac(mac),
                            "type": parts[2] if len(parts) > 2 else "unknown"
                        })
        else:
            # Linux / Kali: try multiple methods
            # Method 1: /proc/net/arp (fastest and most reliable)
            entries = _read_proc_net_arp()

            # Method 2: ip neigh
            if not entries:
                try:
                    output = subprocess.check_output(
                        ["ip", "neigh", "show"], stderr=subprocess.STDOUT, text=True, timeout=8
                    )
                    entries = _parse_linux_arp_output(output)
                except Exception:
                    pass

            # Method 3: arp -n / arp -a
            if not entries:
                for cmd in [["arp", "-n"], ["arp", "-a"]]:
                    try:
                        output = subprocess.check_output(
                            cmd, stderr=subprocess.STDOUT, text=True, timeout=8
                        )
                        entries = _parse_linux_arp_output(output)
                        if entries:
                            break
                    except Exception:
                        continue

            if not entries:
                logger.warning("Could not read ARP table (tried /proc/net/arp, ip neigh, arp)")

    except subprocess.TimeoutExpired:
        logger.error("Timeout while reading ARP table")
        # Last chance: try /proc/net/arp even after timeout
        if system != "windows":
            entries = _read_proc_net_arp()
        if not entries:
            return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute ARP command: {e}")
        if system != "windows":
            entries = _read_proc_net_arp()
        if not entries:
            return []
    except FileNotFoundError:
        logger.error("arp or ip command not found on this system")
        if system != "windows":
            entries = _read_proc_net_arp()
        if not entries:
            return []
    except PermissionError:
        logger.error("Insufficient permissions to read ARP table")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while reading ARP: {e}")
        return []

    # Filter noise + remove duplicates
    seen = set()
    unique = []
    for e in entries:
        ip, mac = e.get("ip", ""), e.get("mac", "")
        if not _is_usable_arp_ip(ip):
            continue
        if not _is_valid_host_mac(mac):
            continue
        key = (ip, mac)
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique

def ping_host(ip: str, timeout: int = 1) -> bool:
    """Host liveness check via system ping (Windows & Linux)."""
    system = platform.system().lower()
    try:
        # Slightly generous process timeout so slow replies still count
        proc_timeout = max(timeout + 2, 3)
        if system == "windows":
            # -n 1: one echo; -w: timeout in milliseconds
            ms = max(int(timeout * 1000), 500)
            cmd = ["ping", "-n", "1", "-w", str(ms), ip]
        else:
            # -c 1: one packet; -W: timeout seconds (Linux)
            cmd = ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), ip]
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=proc_timeout
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False
    except Exception:
        return False

def arp_scan(network: str, timeout: int, max_threads: int, logger) -> list:
    """Scan local network to discover live hosts then read ARP"""
    network = network.strip() if network else ""
    if not network:
        print("\n  [Error] Network range cannot be empty")
        print("  Example: 192.168.1.0/24")
        raise SystemExit(1)
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        logger.error(f"Invalid network range: {network}")
        print(f"\n  [Error] Invalid network range: '{network}'")
        print("  Example: 192.168.1.0/24  or  10.0.0.0/8")
        raise SystemExit(1)

    hosts = [str(ip) for ip in net.hosts()]
    logger.info(f"Starting ARP/network scan on {network} ({len(hosts)} possible hosts)...")

    live_hosts = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {executor.submit(ping_host, ip, timeout): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    live_hosts.append(ip)
                    logger.info(f"[LIVE] {ip}")
            except Exception:
                pass

    logger.info(f"Live hosts found: {len(live_hosts)}")
    # Wait for OS ARP cache to update after pings
    time.sleep(2.0)
    arp_entries = get_arp_table(logger)

    # Index ARP entries that belong ONLY to the scanned network
    arp_map = {}
    for entry in arp_entries:
        ip = entry.get("ip", "")
        try:
            if ipaddress.ip_address(ip) not in net:
                continue
        except ValueError:
            continue
        if not _is_usable_arp_ip(ip) or not _is_valid_host_mac(entry.get("mac", "")):
            continue
        arp_map[ip] = entry

    live_set = set(live_hosts)
    result = []
    seen = set()

    # 1) Live hosts first (with MAC from ARP when available)
    for ip in sorted(live_hosts, key=lambda x: ipaddress.IPv4Address(x)):
        if ip in seen:
            continue
        seen.add(ip)
        if ip in arp_map:
            result.append(arp_map[ip])
        else:
            result.append({"ip": ip, "mac": "unknown", "type": "live"})

    # 2) Other in-range dynamic ARP entries (ping may be blocked by firewall)
    for ip, entry in sorted(arp_map.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
        if ip in seen:
            continue
        etype = str(entry.get("type", "")).lower()
        # Skip obvious static/broadcast leftovers already filtered; keep dynamic/reachable
        if etype in ("static",) and entry.get("mac", "").lower() in ("ff:ff:ff:ff:ff:ff",):
            continue
        seen.add(ip)
        result.append(entry)

    logger.info(f"ARP results in range {network}: {len(result)} host(s)")
    return result

# ==================== RARP / DNS Lookup ====================
def rarp_lookup(mac: str, logger) -> list:
    """Reverse lookup: MAC to IP using current ARP table"""
    mac = mac.strip() if mac else ""
    if not mac:
        print("\n  [Error] MAC address cannot be empty")
        print("  Example: 00:11:22:33:44:55  or  00-11-22-33-44-55")
        raise SystemExit(1)

    if not is_valid_mac(mac):
        logger.error(f"Invalid MAC address: {mac}")
        print(f"\n  [Error] Invalid MAC address: '{mac}'")
        print("  Example: 00:11:22:33:44:55  or  00-11-22-33-44-55")
        raise SystemExit(1)

    mac = normalize_mac(mac)
    logger.info(f"Looking up IP for MAC: {mac}")

    table = get_arp_table(logger)
    matches = [e for e in table if e["mac"] == mac]

    if not matches:
        logger.warning("No match found in current ARP table")
        logger.info("Tip: Ping the device first or run an ARP scan to update the table")
    return matches


def resolve_host(query: str, logger) -> dict:
    """
    Forward DNS: Domain/Hostname → IP
    Reverse DNS: IP → Domain/Hostname
    Pure Python using socket only (no third-party libraries).
    """
    query = query.strip() if query else ""
    if not query:
        print("\n  [Error] Address or domain cannot be empty")
        print("  Example: google.com  or  www.example.com  or  8.8.8.8")
        raise SystemExit(1)

    # ===== Reverse DNS: IP → Hostname/Domain =====
    if is_valid_ip(query):
        logger.info(f"Reverse DNS lookup for IP: {query}")
        hostname = None
        aliases = []
        try:
            hostname, aliases, _ = socket.gethostbyaddr(query)
            logger.info(f"Reverse DNS: {query} → {hostname}")
        except socket.herror:
            logger.warning(f"No reverse DNS record for {query}")
        except socket.gaierror:
            logger.warning(f"Could not reverse-resolve {query}")
        except Exception as e:
            logger.debug(f"Reverse DNS error: {e}")

        return {
            "query": query,
            "primary_ip": query,
            "all_ips": [query],
            "hostname": hostname,
            "aliases": aliases or [],
            "type": "reverse_dns" if hostname else "ip"
        }

    # Reject pure numbers that look like invalid input
    if query.replace(".", "").isdigit() and query.count(".") != 3:
        print(f"\n  [Error] Invalid address or domain: '{query}'")
        print("  Example: google.com  or  192.168.1.1  or  00:11:22:33:44:55")
        raise SystemExit(1)

    # ===== Forward DNS: Domain/Hostname → IP =====
    logger.info(f"Resolving domain/hostname: {query}")
    try:
        infos = socket.getaddrinfo(query, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        if not ips:
            raise socket.gaierror("No addresses returned")

        primary = ips[0]
        for ip in ips:
            try:
                if ipaddress.ip_address(ip).version == 4:
                    primary = ip
                    break
            except ValueError:
                pass

        logger.info(f"Resolved {query} → {primary}")
        return {
            "query": query,
            "primary_ip": primary,
            "all_ips": ips,
            "hostname": query,
            "aliases": [],
            "type": "domain"
        }
    except socket.gaierror:
        logger.error(f"Could not resolve: {query}")
        print(f"\n  [Error] Could not resolve '{query}' to an IP address")
        print("  Check the domain name or your internet connection.")
        print("  Example: google.com  or  www.example.com")
        raise SystemExit(1)
    except Exception as e:
        logger.error(f"Resolve error: {e}")
        print(f"\n  [Error] Failed to resolve '{query}': {e}")
        raise SystemExit(1)


def smart_lookup(query: str, logger):
    """
    Auto-detect input type and perform the right lookup:
    - MAC address       → RARP (MAC to IP via ARP table)
    - Domain / hostname → Forward DNS (Domain to IP)
    - IP address        → Reverse DNS (IP to Domain/Hostname)
    """
    query = query.strip() if query else ""
    if not query:
        print("\n  [Error] Input cannot be empty")
        print("  Enter a MAC address, domain, or IP")
        print("  Examples: 00:11:22:33:44:55  |  google.com  |  8.8.8.8")
        raise SystemExit(1)

    # MAC → RARP
    if is_valid_mac(query):
        matches = rarp_lookup(query, logger)
        return {"mode": "rarp", "query": query, "matches": matches}

    # Domain / hostname / IP → DNS (forward or reverse)
    result = resolve_host(query, logger)
    return {"mode": "dns", "query": query, "result": result}


def print_dns_result(data: dict):
    """Pretty-print DNS / Reverse DNS result"""
    r = data["result"]
    print("\n" + "=" * 50)
    if r.get("type") == "reverse_dns":
        print("RARP-related / Reverse DNS Results (IP → Domain)")
    elif r.get("type") == "ip":
        print("IP Lookup Results")
    else:
        print("DNS / Host Lookup Results (Domain → IP)")
    print("=" * 50)
    print(f"Query      : {r['query']}")
    print(f"Type       : {r['type']}")
    if r.get("hostname"):
        print(f"Hostname   : {r['hostname']}")
    if r.get("aliases"):
        print(f"Aliases    : {', '.join(r['aliases'])}")
    print(f"Primary IP : {r['primary_ip']}")
    if len(r.get("all_ips", [])) > 1:
        print("All IPs    :")
        for ip in r["all_ips"]:
            print(f"  → {ip}")
    if r.get("type") == "ip" and not r.get("hostname"):
        print("Hostname   : (no reverse DNS record found)")
    print("=" * 50)

# ==================== CLI Interface ====================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Port & ARP-RARP Scanner Tool (Pure Python)",
        epilog="Example: python scanner.py port --target 192.168.1.1 --ports 80,443,22"
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=str, default=None, help="Path to config file (JSON)")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: INFO)")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Port scan command
    port_parser = subparsers.add_parser("port", help="Scan TCP ports on a target")
    port_parser.add_argument("--target", "-t", required=True, help="Target IP address or hostname")
    port_parser.add_argument("--ports", "-p", default=None, help="Ports (e.g. 80,443 or 1-1000)")
    port_parser.add_argument("--timeout", type=float, default=None, help="Connection timeout in seconds")
    port_parser.add_argument("--threads", type=int, default=None, help="Number of parallel threads")

    # ARP command
    arp_parser = subparsers.add_parser("arp", help="Show ARP table or scan local network")
    arp_parser.add_argument("--network", "-n", default=None, help="Network range (e.g. 192.168.1.0/24)")
    arp_parser.add_argument("--scan", action="store_true", help="Perform active scan (ping) then read ARP")
    arp_parser.add_argument("--timeout", type=int, default=None, help="Ping timeout in seconds")
    arp_parser.add_argument("--threads", type=int, default=None, help="Number of threads")

    # RARP / DNS lookup command
    rarp_parser = subparsers.add_parser("rarp", help="Lookup: MAC→IP (RARP) or Domain/Host→IP (DNS)")
    rarp_parser.add_argument("--mac", "-m", default=None, help="MAC address (e.g. 00:11:22:33:44:55)")
    rarp_parser.add_argument("--host", default=None, help="Domain or hostname (e.g. google.com)")
    rarp_parser.add_argument("query", nargs="?", default=None, help="MAC, domain, or IP (auto-detect)")

    return parser

def print_port_result(result: dict):
    print("\n" + "=" * 50)
    print("Port Scan Results")
    print("=" * 50)
    print(f"Target         : {result['host']}")
    print(f"Ports scanned  : {result['total_scanned']}")
    print(f"Time elapsed   : {result['elapsed_seconds']} sec")
    print("-" * 50)
    if result["open_ports"]:
        print("Open ports:")
        for p in result["open_ports"]:
            print(f"  -> {p}/tcp")
    else:
        print("No open ports found in the specified range.")
    print("=" * 50)

def print_arp_result(entries: list, title: str = "ARP Table"):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    if not entries:
        print("No entries found.")
    else:
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Type'}")
        print("-" * 60)
        for e in entries:
            print(f"{e['ip']:<18} {e['mac']:<20} {e.get('type', '')}")
    print("=" * 60)
    print(f"Total entries: {len(entries)}")


# ==================== الواجهة التفاعلية ====================
def clear_screen():
    """مسح الشاشة حسب نظام التشغيل"""
    os.system("cls" if platform.system().lower() == "windows" else "clear")


def show_main_help():
    """Show help for the main interactive menu"""
    print("\n" + "=" * 55)
    print("  HELP - Main Menu")
    print("=" * 55)
    print("""
  [1]  Port Scanner
       Scan TCP ports on a target IP or hostname.
       You will be asked for:
         - Target IP / hostname
         - Ports (single, list, or range)
         - Timeout (optional)

  [2]  ARP Table / Network Scan
       Show current ARP table or scan the local network.
       Sub-options:
         [1] Show ARP table only
         [2] Active scan (ping hosts then read ARP)

  [3]  RARP Lookup (MAC / Domain / IP)
       - MAC → IP (RARP via ARP table)
       - Domain → IP (DNS)
       - IP → Domain (Reverse DNS)
       Examples: 00:11:22:33:44:55 | google.com | 8.8.8.8

  [0]  Exit the tool

  Extra commands:
  [h] or [help]       Show this help message
  [v] or [version]    Show tool version
  [c] or [config]     Load a config file (JSON)
  [l] or [log-level]  Change logging level
""")
    print("=" * 55)
    input("  Press Enter to continue...")


def show_port_help():
    """Help for Port Scanner"""
    print("\n" + "-" * 50)
    print("  HELP - Port Scanner")
    print("-" * 50)
    print("""
  What you need to enter:

  1. Target IP or hostname
     Examples: 192.168.1.1  or  scanme.nmap.org

  2. Ports
     - Single port : 80
     - Multiple    : 22,80,443
     - Range       : 1-1000
     - Press Enter : use default common ports

  3. Timeout (seconds)
     - Press Enter for default (1.0)
     - Use higher value (2 or 3) on slow networks

  Tip: Type 'b' or 'back' at any prompt to cancel.
""")
    print("-" * 50)


def show_arp_help():
    """Help for ARP"""
    print("\n" + "-" * 50)
    print("  HELP - ARP Table / Network Scan")
    print("-" * 50)
    print("""
  [1] Show current ARP table only
      Displays devices already known by your system.

  [2] Scan local network (Ping + ARP)
      - Pings all hosts in the network range
      - Then reads the ARP table
      - You can enter a range like: 192.168.1.0/24
      - Or press Enter to auto-detect your network

  Tip: Type 'b' or 'back' to cancel.
""")
    print("-" * 50)


def show_rarp_help():
    """Help for RARP / DNS Lookup"""
    print("\n" + "-" * 50)
    print("  HELP - RARP Lookup (MAC / Domain / IP)")
    print("-" * 50)
    print("""
  This option accepts THREE types of input:

  1) MAC address → IP from ARP table (RARP)
     Formats: 00:11:22:33:44:55  |  00-11-22-33-44-55
     Tip: Run an ARP scan first if device is not listed.

  2) Domain / Hostname → IP (Forward DNS)
     Examples: google.com  |  www.example.com

  3) IP address → Domain/Hostname (Reverse DNS)
     Examples: 8.8.8.8  |  1.1.1.1

  Tip: Type 'b' or 'back' to cancel.
""")
    print("-" * 50)


def interactive_menu(config: dict, logger):
    """Interactive menu with built-in help, version, config, and log-level support"""
    current_log_level = "INFO"

    while True:
        clear_screen()
        print("=" * 55)
        print("   Port & ARP-RARP Scanner Tool")
        print(f"   Version {__version__}")
        print("=" * 55)
        print()
        print("  Select a function:")
        print()
        print("  [1]  Port Scanner")
        print("  [2]  ARP Table / Network Scan")
        print("  [3]  RARP Lookup (MAC / Domain / IP)")
        print()
        print("  [h]  Help")
        print("  [v]  Version")
        print("  [c]  Config")
        print("  [l]  Log-level")
        print("  [0]  Exit")
        print()
        print(f"  Current log-level: {current_log_level}")
        print("-" * 55)

        choice = input("  Enter option number (or h for help): ").strip().lower()

        if choice in ("0", "exit", "quit"):
            print("\n  Thank you for using the tool. Goodbye!")
            break

        elif choice in ("h", "help", "?"):
            show_main_help()
            continue

        elif choice in ("v", "version"):
            print(f"\n  Port & ARP-RARP Scanner Tool  v{__version__}")
            print("  Pure Python - No third-party libraries")
            input("\n  Press Enter to continue...")
            continue

        elif choice in ("c", "config"):
            print("\n" + "=" * 40)
            print("  Load Config File")
            print("=" * 40)
            path = input("  Enter path to config.json (or press Enter to cancel): ").strip()
            if path:
                new_cfg = load_config(path)
                config.update(new_cfg)
                print("  Config loaded successfully.")
                print(f"  Default ports : {config.get('default_ports', '')[:50]}...")
                print(f"  Timeout       : {config.get('timeout')}")
                print(f"  Max threads   : {config.get('max_threads')}")
            else:
                print("  Cancelled.")
            input("\n  Press Enter to continue...")
            continue

        elif choice in ("l", "log-level", "loglevel"):
            print("\n" + "=" * 40)
            print("  Change Log Level")
            print("=" * 40)
            print("  Available levels: DEBUG, INFO, WARNING, ERROR")
            print(f"  Current level   : {current_log_level}")
            new_level = input("  Enter new level: ").strip().upper()
            if new_level in ("DEBUG", "INFO", "WARNING", "ERROR"):
                current_log_level = new_level
                logger = setup_logging(current_log_level)
                print(f"  Log level changed to: {current_log_level}")
            elif new_level == "":
                print("  Cancelled. Keeping current setting.")
            else:
                print(f"\n  [Error] Invalid log level: '{new_level}'")
                print("  Allowed values: DEBUG, INFO, WARNING, ERROR")
            input("\n  Press Enter to continue...")
            continue

        elif choice == "1":
            # ===== Port Scanner =====
            print("\n" + "=" * 40)
            print("  Port Scanner")
            print("  (type 'h' for help, 'b' to go back)")
            print("=" * 40)

            target = input("  Enter target IP or hostname: ").strip()
            if target.lower() in ("h", "help", "?"):
                show_port_help()
                target = input("  Enter target IP or hostname: ").strip()
            if target.lower() in ("b", "back", ""):
                continue

            default_preview = config["default_ports"]
            if len(default_preview) > 55:
                default_preview = default_preview[:55] + "..."
            ports_input = input(f"  Enter ports (e.g. 80,443 or 1-1000)\n  [Enter=default: {default_preview}]: ").strip()
            if ports_input.lower() in ("h", "help", "?"):
                show_port_help()
                ports_input = input(f"  Enter ports [Enter=default: {default_preview}]: ").strip()
            if ports_input.lower() in ("b", "back"):
                continue
            ports_str = ports_input if ports_input else config["default_ports"]

            timeout_input = input(f"  Connection timeout in seconds [default {config['timeout']}]: ").strip()
            if timeout_input.lower() in ("h", "help", "?"):
                show_port_help()
                timeout_input = input(f"  Timeout [default {config['timeout']}]: ").strip()
            if timeout_input.lower() in ("b", "back"):
                continue
            if timeout_input:
                try:
                    timeout = float(timeout_input)
                    if timeout <= 0 or timeout > 60:
                        print(f"\n  [Error] Invalid timeout '{timeout_input}': must be between 0.1 and 60 seconds")
                        input("\n  Press Enter to return to menu...")
                        continue
                except ValueError:
                    print(f"\n  [Error] Invalid timeout '{timeout_input}': must be a number")
                    print("  Example: 1  or  2.5")
                    input("\n  Press Enter to return to menu...")
                    continue
            else:
                timeout = config["timeout"]

            try:
                ports = parse_ports(ports_str)
                result = port_scan(target, ports, timeout, config["max_threads"], logger)
                print_port_result(result)
            except SystemExit:
                pass
            except Exception as e:
                print(f"\n  [Error] {e}")

            input("\n  Press Enter to return to menu...")

        elif choice == "2":
            # ===== ARP =====
            print("\n" + "=" * 40)
            print("  ARP Table / Network Scan")
            print("  (type 'h' for help, 'b' to go back)")
            print("=" * 40)
            print()
            print("  [1] Show current ARP table only")
            print("  [2] Scan local network (Ping + ARP)")
            print("  [h] Help")
            print("  [b] Back")
            print()
            sub = input("  Choose: ").strip().lower()

            if sub in ("h", "help", "?"):
                show_arp_help()
                sub = input("  Choose [1/2]: ").strip().lower()

            if sub in ("b", "back", ""):
                continue

            if sub == "1":
                entries = get_arp_table(logger)
                print_arp_result(entries, "Current ARP Table")

            elif sub == "2":
                default_net = get_network_cidr()
                net_input = input(f"  Enter network range [default {default_net}]: ").strip()
                if net_input.lower() in ("h", "help", "?"):
                    show_arp_help()
                    net_input = input(f"  Network range [default {default_net}]: ").strip()
                if net_input.lower() in ("b", "back"):
                    continue
                network = net_input if net_input else default_net

                try:
                    entries = arp_scan(network, config["ping_timeout"], config["max_threads"], logger)
                    print_arp_result(entries, f"ARP Scan Results on {network}")
                except SystemExit:
                    pass
                except Exception as e:
                    print(f"\n  [Error] {e}")
            else:
                print("  Invalid option.")

            input("\n  Press Enter to return to menu...")

        elif choice == "3":
            # ===== RARP Lookup: MAC / Domain / IP =====
            print("\n" + "=" * 40)
            print("  RARP Lookup (MAC / Domain / IP)")
            print("  (type 'h' for help, 'b' to go back)")
            print("=" * 40)
            print("  MAC → IP  |  Domain → IP  |  IP → Domain")
            print("  Examples: 00:11:22:33:44:55 | google.com | 8.8.8.8")

            query = input("  Enter MAC / Domain / IP: ").strip()
            if query.lower() in ("h", "help", "?"):
                show_rarp_help()
                query = input("  Enter MAC / Domain / IP: ").strip()
            if query.lower() in ("b", "back", ""):
                continue

            try:
                data = smart_lookup(query, logger)
                if data["mode"] == "rarp":
                    print_arp_result(data["matches"], f"RARP Lookup Results for {query}")
                else:
                    print_dns_result(data)
            except SystemExit:
                pass
            except Exception as e:
                print(f"\n  [Error] {e}")

            input("\n  Press Enter to return to menu...")

        else:
            print("\n  Invalid option. Type 'h' for help.")
            input("  Press Enter to continue...")


def main():
    parser = build_parser()
    args = parser.parse_args()

    # إعداد التسجيل
    logger = setup_logging(args.log_level)

    # تحميل الإعدادات
    config = load_config(args.config)

    # إذا لم يتم تمرير أي أمر → تشغيل الواجهة التفاعلية
    if not args.command:
        try:
            interactive_menu(config, logger)
        except KeyboardInterrupt:
            print("\n\n  Exited by user.")
        return

    # ===== Traditional CLI mode =====
    try:
        if args.command == "port":
            ports_str = args.ports or config["default_ports"]
            ports = parse_ports(ports_str)
            timeout = args.timeout if args.timeout is not None else config["timeout"]
            threads = args.threads if args.threads is not None else config["max_threads"]

            result = port_scan(args.target, ports, timeout, threads, logger)
            print_port_result(result)

        elif args.command == "arp":
            if args.scan:
                network = args.network or get_network_cidr()
                timeout = args.timeout if args.timeout is not None else config["ping_timeout"]
                threads = args.threads if args.threads is not None else config["max_threads"]
                entries = arp_scan(network, timeout, threads, logger)
                print_arp_result(entries, f"ARP Scan Results on {network}")
            else:
                entries = get_arp_table(logger)
                print_arp_result(entries, "Current ARP Table")

        elif args.command == "rarp":
            # Accept --mac, --host, or positional query (auto-detect)
            query = args.mac or args.host or args.query
            if not query:
                print("\n  [Error] Provide a MAC, domain, or IP")
                print("  Examples:")
                print("    python scanner.py rarp --mac 00:11:22:33:44:55")
                print("    python scanner.py rarp --host google.com")
                print("    python scanner.py rarp google.com")
                sys.exit(1)
            data = smart_lookup(query, logger)
            if data["mode"] == "rarp":
                print_arp_result(data["matches"], f"RARP Lookup Results for {query}")
            else:
                print_dns_result(data)

    except KeyboardInterrupt:
        logger.warning("\nProcess interrupted by user (Ctrl+C)")
        sys.exit(130)
    except PermissionError as e:
        logger.error(f"Permission error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.log_level == "DEBUG":
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
