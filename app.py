import gradio as gr
import socket
import threading
import matplotlib.pyplot as plt
import json
import csv
import time
from datetime import datetime, timedelta
import os
import random
import string
import math
import re
import hashlib
import base64
import ipaddress
import urllib.parse
import html
import requests
import io
from llm_engine import explain_with_llm 
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, padding

CSV_LOG_FILE = "auth_logs.csv"

print("PWD:", os.getcwd(), flush=True)
print("List root:", os.listdir("/"), flush=True)
baseline_folder = None
baseline_hashes = {}
AES_GCM = "AES-GCM (Modern)"
AES_CBC = "AES-CBC (Legacy)"
FERNET = "Fernet (High-Level)"
# =========================================================
# AUTHORIZES NETWORKS FOR SCANNING (Module 1)
# =========================================================
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.1/32"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("103.5.112.0/22"),  
    ipaddress.ip_network("11.12.0.0/19")
]

def is_ip_allowed(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in ALLOWED_NETWORKS)
    except ValueError:
        return False
# =========================================================
# GLOBAL STORAGE (Module 2)
# =========================================================
baseline_hashes = {}


# =========================================================
# SERVICE NAMES (Module 1)
# =========================================================
SERVICE_NAMES = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    445: "SMB",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle DB",
    27017: "MongoDB",
    6379: "Redis",
}

def get_service_name(port):
    return SERVICE_NAMES.get(port, "Unknown")
# =========================================================
# PASSWORD TOOLS (Module 3)
# =========================================================
def generate_password(length: int = 14):
    alphabet = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+[]{};:,.<>?/"
    )
    return "".join(random.choice(alphabet) for _ in range(length))

HISTORY_FILE = "password_history.json"

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {"Weak":0,"Medium":0,"Strong":0}

def save_history(data):
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f)
# =========================================================
# ATTACK MODELS (ACADEMIC)
# =========================================================
ATTACK_MODELS = {
    "Online attack (rate-limited)": 1e3,
    "Offline CPU brute-force": 1e7,
    "Offline GPU brute-force (Hashcat)": 1e11,
    "Advanced GPU cluster": 1e13,
}
def seconds_to_human(seconds: float):
    units = [
        ("years", 3600 * 24 * 365),
        ("days", 3600 * 24),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit in units:
        if seconds >= unit:
            val = seconds / unit
            return f"{val:.1f} {name}" if val < 10 else f"{int(val)} {name}"
    return "less than 1 second"

def calculate_entropy(password: str):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[!@#$%^&*()_\-+=\[\]{};:,.<>?/]", password): pool += 32
    if pool == 0:
        return 0
    return len(password) * math.log2(pool)

def estimate_crack_times(password: str):
    entropy = calculate_entropy(password)
    if entropy == 0:
        return {}
    results = {}
    LOG10_2 = math.log10(2)
    # Classical attacks
    for model, rate in ATTACK_MODELS.items():
        log_seconds = entropy * LOG10_2 - math.log10(rate)
        seconds = 10 ** log_seconds
        results[model] = seconds_to_human(seconds)
    # Quantum attack 
    quantum_rate = 1e12
    log_quantum_seconds = (entropy / 2) * LOG10_2 - math.log10(quantum_rate)
    quantum_seconds = 10 ** log_quantum_seconds
    results["Quantum attack (Grover’s algorithm – theoretical)"] = seconds_to_human(quantum_seconds)
    return results
# =========================================================
# PASSWORD ANALYSIS
# =========================================================
COMMON_WORDS = {
    "password","123456","qwerty","letmein","admin",
    "welcome","iloveyou","password1","12345678"
}

def analyze_password(password: str):
    try:
        if not password:
            password = ""

        reasons, suggestions = [], []
        score = 0

        if len(password) >= 12:
            score += 1
        else:
            reasons.append("Password is short (use 12+ characters).")
            suggestions.append("Increase length to at least 12 characters.")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            reasons.append("No lowercase letters.")
            suggestions.append("Add lowercase letters.")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            reasons.append("No uppercase letters.")
            suggestions.append("Add uppercase letters.")

        if re.search(r"\d", password):
            score += 1
        else:
            reasons.append("No numbers.")
            suggestions.append("Add numbers.")

        if re.search(r"[!@#$%^&*()_\-+=\[\]{};:,.<>?/]", password):
            score += 1
        else:
            reasons.append("No special characters.")
            suggestions.append("Add special characters.")

        low = password.lower()

        if any(w in low for w in COMMON_WORDS):
            reasons.append("Contains dictionary/common patterns.")
            suggestions.append("Avoid dictionary words.")

        if re.search(r"(.)\1\1", password):
            reasons.append("Repeated characters detected.")
            suggestions.append("Avoid repeated characters.")

        if re.search(r"(012|123|234|345|abcd|bcde)", low):
            reasons.append("Sequential pattern detected.")
            suggestions.append("Avoid sequential patterns.")

        if score <= 2:
            verdict = "Weak"
        elif score <= 4:
            verdict = "Medium"
        else:
            verdict = "Strong"

        history = load_history()
        history.setdefault("Weak", 0)
        history.setdefault("Medium", 0)
        history.setdefault("Strong", 0)

        history[verdict] += 1
        save_history(history)

        crack_times = estimate_crack_times(password)

        explanation_md = f"### Strength: **{verdict.upper()}**\n\n"
        explanation_md += "#### Estimated Crack Time by Attack Model:\n"

        for k, v in crack_times.items():
            explanation_md += f"- **{k}:** {v}\n"

        fig, ax = plt.subplots(figsize=(5,3))

        cats = ["Weak","Medium","Strong"]
        vals = [history[c] for c in cats]

        ax.bar(cats, vals)
        ax.set_title("Password Strength History")

        plt.tight_layout()

        return explanation_md, fig

    except Exception as e:
        return f"### Internal Error\n\n```\n{str(e)}\n```", None
# =========================================================
# NETWORK SCANNER (Module 1)
# =========================================================
def scan_port(ip, port, results, lock):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((ip, port))
        results.append((port, True))
        with lock:
            results.append((port, True))
    except:
        with lock:
            results.append((port, False))
    finally:
        s.close()

def run_port_scanner(ip_input, port_range):

    # simple validation
    if not ip_input:
        return "Enter a valid IP address (e.g. 127.0.0.1)", None
    if not is_ip_allowed(ip_input):
        return "Target IP not authorized for scanning.", None
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if start_port < 1 or end_port > 65525 or start_port > end_port:
            raise ValueError
    except:
        return "Invalid port range format. Use e.g. 1-10000", None

    results = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip_input, port, results, lock)

    # build textual output
    output_lines = []
    open_count = 0
    closed_count = 0
    for port, is_open in sorted(results):
        svc = get_service_name(port)
        if is_open:
            output_lines.append(f"🟢 Port {port} ({svc}) : OPEN")
            open_count += 1
        else:
            output_lines.append(f"🔴 Port {port} ({svc}) : CLOSED")
            closed_count += 1

    output_text = "\n".join(output_lines) if output_lines else "No ports scanned."

    # build summary chart
    fig, ax = plt.subplots(figsize=(4,3))
    ax.bar(["Open", "Closed"], [open_count, closed_count])
    ax.set_title(f"Scan Summary for {ip_input}")
    ax.set_ylabel("Number of Ports")

    for i, v in enumerate([open_count, closed_count]):
        ax.text(i, v + 0.5, str(v), ha="center")

    plt.tight_layout()

    return output_text, fig
# =========================================================
# FILE INTEGRITY MONITOR (Module 2)
# =========================================================
# FILE HASH FUNCTION
def compute_file_hash(file_path):
    hash_obj = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hash_obj.update(chunk)

        return hash_obj.hexdigest()
    except Exception as e:
        return None
# Baseline Folder Scan
def create_baseline(files):
    global baseline_hashes, baseline_folder
    baseline_hashes = {}

    if not files:
        return "❌ No folder selected."
    
    baseline_folder = os.path.dirname(files[0])

    if not os.path.isdir(baseline_folder):
        return "❌ Invalid folder path."
    
    for root, dirs, file_list in os.walk(baseline_folder):
        for file in file_list:
            full_path = os.path.join(root, file)
            file_hash = compute_file_hash(full_path)
            if file_hash:
                baseline_hashes[full_path] = file_hash
    
    return f"✅ Baseline created. {len(baseline_hashes)} files recorded."

# Integrity Re-check

def check_integrity():
    if not baseline_hashes or not baseline_folder:
        return "❌ Baseline not created yet.", None

    current_hashes = {}

    for root, dirs, file_list in os.walk(baseline_folder):
        for file in file_list:
            full_path = os.path.join(root, file)
            file_hash = compute_file_hash(full_path)
            if file_hash:
                current_hashes[full_path] = file_hash

    unchanged, modified, missing, new_files = [], [], [], []

    for file_path, base_hash in baseline_hashes.items():
        if file_path in current_hashes:
            if current_hashes[file_path] == base_hash:
                unchanged.append(file_path)
            else:
                modified.append(file_path)
        else:
            missing.append(file_path)

    for file_path in current_hashes:
        if file_path not in baseline_hashes:
            new_files.append(file_path)

    output = ""
    for f in unchanged:
        output += f"✅ Unchanged : {f}\n"
    for f in modified:
        output += f"⚠ Modified  : {f}\n"
    for f in missing:
        output += f"❌ Missing   : {f}\n"
    for f in new_files:
        output += f"🆕 New File  : {f}\n"

    summary = {
        "unchanged": len(unchanged),
        "modified": len(modified),
        "missing": len(missing),
        "new": len(new_files)
    }

    return output, integrity_graph(summary)

    # Status counters
    unchanged = []
    modified = []
    missing = []
    new_files = []

    # Compare baseline with current
    for file_path, base_hash in baseline_hashes.items():
        if file_path in current_hashes:
            if current_hashes[file_path] == base_hash:
                unchanged.append(file_path)
            else:
                modified.append(file_path)
        else:
            missing.append(file_path)

    # Detect new files
    for file_path in current_hashes:
        if file_path not in baseline_hashes:
            new_files.append(file_path)

    # Build readable output
    output = ""

    for f in unchanged:
        output += f"✅ Unchanged : {f}\n"
    for f in modified:
        output += f"⚠ Modified  : {f}\n"
    for f in missing:
        output += f"❌ Missing   : {f}\n"
    for f in new_files:
        output += f"🆕 New File  : {f}\n"

    # Summary counts (for graph later)
    summary = {
        "unchanged": len(unchanged),
        "modified": len(modified),
        "missing": len(missing),
        "new": len(new_files)
    }

    return output, summary

# Gradio UI + Visualization

def integrity_graph(summary):
    labels = ["Unchanged", "Modified", "Missing", "New"]
    values = [
        summary["unchanged"],
        summary["modified"],
        summary["missing"],
        summary["new"]
    ]

    colors = ["#2ca02c", "#ff7f0e", "#d62728", "#1f77b4"]

    fig, ax = plt.subplots(figsize=(5,3))
    ax.bar(labels, values, color=colors)
    ax.set_title("File Integrity Status")
    ax.set_ylabel("Number of Files")

    for i, v in enumerate(values):
        ax.text(i, v + 0.05, str(v), ha="center")

    plt.tight_layout()
    return fig


# =========================================================
# PYLOGDEFENDER     (Module 4)
# =========================================================

# Brute force Detection

def detect_bruteforce_csv(csv_path, threshold=5, window_seconds=60):
    attempts = {}

    if not os.path.exists(csv_path):
        return ["❌ Log file not found."], {}

    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("status") != "FAIL":
                continue

            try:
                ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            except:
                continue

            ip = row.get("ip", "UNKNOWN")
            user = row.get("user", "UNKNOWN")

            attempts.setdefault((ip, user), []).append(ts)

    alerts = []
    failed_by_ip = {}

    for (ip, user), times in attempts.items():
        times.sort()
        failed_by_ip[ip] = len(times)

        for i in range(len(times)):
            window = times[i:i + threshold]
            if len(window) == threshold:
                if (window[-1] - window[0]).seconds <= window_seconds:
                    alerts.append(
                        f"🚨 BRUTE FORCE detected | IP={ip} | USER={user} | "
                        f"{threshold} failures in {window_seconds}s"
                    )
                    break

    if not alerts:
        alerts.append("✅ No brute-force activity detected.")

    return alerts, failed_by_ip

# log entries

def get_last_logs(csv_path, limit=20):
    if not os.path.exists(csv_path):
        return "No logs available yet."

    with open(csv_path, newline="") as f:
        rows = list(csv.reader(f))

    if len(rows) <= 1:
        return "No logs available yet."

    data = rows[1:][-limit:]
    output = []

    for row in data:
        if len(row) < 4:
            continue

        ts, ip, user, status = row[:4]
        output.append(
            f"{ts} | IP={ip} | USER={user} | STATUS={status}"
        )

    return "\n".join(output) if output else "No logs available yet."

# Attack Probability Indicator

def calculate_attack_probability(failed_by_ip):
    total = sum(failed_by_ip.values())

    if total >= 10:
        return 90
    elif total >= 5:
        return 60
    elif total >= 3:
        return 30
    elif total > 0:
        return 10
    return 0

# UI Callback

def analyze_logs_ui():
    try:
        alerts, failed_by_ip = detect_bruteforce_csv(CSV_LOG_FILE)
        fig = plot_failed_attempts(failed_by_ip)
        probability = calculate_attack_probability(failed_by_ip)
        last_logs = get_last_logs(CSV_LOG_FILE)

        return (
            "\n".join(alerts),
            fig,
            f"⚠️ Attack Probability: {probability}%",
            last_logs
        )

    except Exception as e:
        return (
            f"❌ Analysis error: {e}",
            None,
            "N/A",
            "No logs available"
        )

# Visualization

def plot_failed_attempts(failed_by_ip):
    if not failed_by_ip:
        return None

    ips = list(failed_by_ip.keys())
    counts = list(failed_by_ip.values())

    colors = [
        "red" if c >= 5 else "orange" if c >= 3 else "green"
        for c in counts
    ]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(ips, counts, color=colors)
    ax.set_title("Failed Login Attempts by IP")
    ax.set_xlabel("IP Address")
    ax.set_ylabel("Failure Count")
    plt.xticks(rotation=45)
    plt.tight_layout()

    return fig

# =========================================================
# Encryption & Decryption
# =========================================================

# String Encoding Functions 

def base64_encode(t): return base64.b64encode(t.encode()).decode()
def base64_decode(t):
    try: return base64.b64decode(t).decode()
    except: return "❌ Invalid Base64"

def hex_encode(t): return t.encode().hex()
def hex_decode(t):
    try: return bytes.fromhex(t).decode()
    except: return "❌ Invalid Hex"

def html_encode(t): return html.escape(t)
def html_decode(t): return html.unescape(t)

def qp_encode(t): return t.encode("quopri").decode()

# Hash Functions 

def hash_text(text, algo):
    try:
        if not text:
            return "❌ Input text required"
        if not algo:
            return "❌ Select a hash algorithm"

        algos = {
            "MD5": hashlib.md5,
            "SHA-1": hashlib.sha1,
            "SHA-256": hashlib.sha256,
            "SHA-384": hashlib.sha384,
            "SHA-512": hashlib.sha512
        }

        if algo not in algos:
            return "❌ Unsupported algorithm"

        return algos[algo](text.encode()).hexdigest()

    except Exception as e:
        return f"❌ Internal error: {str(e)}"


# Password-Based Key Derivation

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()

    )
    return kdf.derive(password.encode())

# AES-GCM Encryption

def aes_gcm_encrypt(text, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)

    aes = AESGCM(key)
    cipher = aes.encrypt(nonce, text.encode(), None)

    return(
        base64.b64encode(cipher).decode(),
        base64.b64encode(salt).decode(),
        base64.b64encode(nonce).decode()
    )

def aes_gcm_decrypt(cipher, password, salt_b64, nonce_b64):
    try:
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        key = derive_key(password, salt)

        aes = AESGCM(key)
        plain = aes.decrypt(nonce, base64.b64decode(cipher), None)
        return plain.decode()
    except:
        return "❌ Decryption Failed"

# AEC-CBC + HMAC

def aes_cbc_encrypt(text, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(salt).decode(),
        base64.b64encode(iv).decode()
    )

def aes_cbc_decrypt(cipher_b64, password, salt_b64, iv_b64):
    try:
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(cipher_b64)

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()

        return plain.decode()
    except:
        return "❌ Decryption failed"


# Fernet

def fernet_encrypt(text, password):
    salt = os.urandom(16)
    key = base64.urlsafe_b64encode(derive_key(password, salt))
    f = Fernet(key)
    cipher = f.encrypt(text.encode())

    return cipher.decode(), base64.b64encode(salt).decode()

def fernet_decrypt(cipher_text, password, salt_b64):
    try:
        salt = base64.b64decode(salt_b64)
        key = base64.urlsafe_b64encode(derive_key(password, salt))
        f = Fernet(key)
        plain = f.decrypt(cipher_text.encode())
        return plain.decode()
    except:
        return "❌ Decryption failed"

# =========================================================
# CVSS CALCULATION LOGIC ( Module 6 )
# =========================================================

#  Utility 

def roundup(score):
    return math.ceil(score * 10) / 10.0

#  Metric Weights 

AV_VALUES = {
    "Network": 0.85,
    "Adjacent": 0.62,
    "Local": 0.55,
    "Physical": 0.20
}

AC_VALUES = {
    "Low": 0.77,
    "High": 0.44
}

UI_VALUES = {
    "None": 0.85,
    "Required": 0.62
}

S_VALUES = {
    "Unchanged": "U",
    "Changed": "C"
}

PR_VALUES_U = {
    "None": 0.85,
    "Low": 0.62,
    "High": 0.27
}

PR_VALUES_C = {
    "None": 0.85,
    "Low": 0.68,
    "High": 0.50
}

CIA_VALUES = {
    "None": 0.00,
    "Low": 0.22,
    "High": 0.56
}

#  Severity Mapping 

def severity_label(score):
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"

#  CVSS v3.1 Calculation 

def calculate_cvss(av, ac, pr, ui, scope, c, i, a):
    AV = AV_VALUES[av]
    AC = AC_VALUES[ac]
    UI = UI_VALUES[ui]
    S = S_VALUES[scope]

    PR = PR_VALUES_U[pr] if S == "U" else PR_VALUES_C[pr]

    C_impact = CIA_VALUES[c]
    I_impact = CIA_VALUES[i]
    A_impact = CIA_VALUES[a]

    # Impact calculation
    impact = 1 - ((1 - C_impact) * (1 - I_impact) * (1 - A_impact))

    # 🔴 CVSS RULE: If impact is zero → score MUST be zero
    if impact <= 0:
        vector = f"CVSS:3.1/AV:{av[0]}/AC:{ac[0]}/PR:{pr[0]}/UI:{ui[0]}/S:{S}/C:{c[0]}/I:{i[0]}/A:{a[0]}"
        explanation = (
            "No impact on Confidentiality, Integrity, or Availability.\n"
            "As per CVSS v3.1 specification, Base Score is 0.0 when impact is zero."
        )
        return 0.0, "None", vector, explanation

    # Impact subscore
    if S == "U":
        impact_score = 6.42 * impact
    else:
        impact_score = (
            7.52 * (impact - 0.029)
            - 3.25 * ((impact - 0.02) ** 15)
        )

    # Exploitability subscore
    exploitability = 8.22 * AV * AC * PR * UI

    # Base score
    base_score = roundup(min(impact_score + exploitability, 10))

    vector = (
        f"CVSS:3.1/"
        f"AV:{av[0]}/AC:{ac[0]}/PR:{pr[0]}/UI:{ui[0]}/"
        f"S:{S}/C:{c[0]}/I:{i[0]}/A:{a[0]}"
    )

    explanation = (
        f"Attack Vector: {av}\n"
        f"Attack Complexity: {ac}\n"
        f"Privileges Required: {pr}\n"
        f"User Interaction: {ui}\n"
        f"Scope: {scope}\n"
        f"Impact → C:{c}, I:{i}, A:{a}\n"
        f"Exploitability and Impact combined as per CVSS v3.1 formula.\n"
        f"Severity derived automatically from Base Score."
    )

    return base_score, severity_label(base_score), vector, explanation


# =========================================================
# JWT SECURITY ANALYZER  (Module 7 - Upgraded)
# =========================================================

def base64url_decode(input_str):
    try:
        input_str = input_str.strip()
        padding = '=' * (-len(input_str) % 4)
        decoded_bytes = base64.urlsafe_b64decode(input_str + padding)
        return decoded_bytes.decode("utf-8")
    except Exception:
        return None


def analyze_jwt(token):
    if not token:
        return {}, {}, "", "❌ No token provided.", ""

    token = token.strip()

    if token.count(".") != 2:
        return {}, {}, "", "❌ Invalid JWT format. A valid JWT must contain exactly 3 parts separated by dots.", ""

    header_b64, payload_b64, signature = token.split(".")

    header_json = {}
    payload_json = {}
    analysis_md = ""
    warnings_md = ""

    # ==========================
    # Decode Header
    # ==========================
    header_decoded = base64url_decode(header_b64)
    if not header_decoded:
        return {}, {}, "", "❌ Header decoding failed. Ensure it is valid Base64URL.", ""

    try:
        header_json = json.loads(header_decoded)
    except Exception:
        return {}, {}, "", "❌ Header is not valid JSON format.", ""

    # ==========================
    # Decode Payload
    # ==========================
    payload_decoded = base64url_decode(payload_b64)
    if not payload_decoded:
        return header_json, {}, signature, "❌ Payload decoding failed. Ensure it is valid Base64URL.", ""

    try:
        payload_json = json.loads(payload_decoded)
    except Exception:
        return header_json, {}, signature, "❌ Payload is not valid JSON format.", ""

    # ==========================
    # ANALYSIS SECTION
    # ==========================

    analysis_md += "### 🔍 Token Security Analysis\n\n"

    alg = header_json.get("alg", "Not specified")
    typ = header_json.get("typ", "Not specified")

    analysis_md += f"- **Algorithm Used:** {alg}\n"
    analysis_md += f"- **Token Type:** {typ}\n"

    # Signed or not
    if isinstance(alg, str) and alg.lower() == "none":
        analysis_md += "- **Signed:** ❌ No (Unsigned Token)\n"
    else:
        analysis_md += "- **Signed:** ✅ Yes\n"

    # Signing type
    if isinstance(alg, str):
        if alg.startswith("HS"):
            analysis_md += "- **Signing Type:** Symmetric (Shared Secret Key)\n"
        elif alg.startswith("RS") or alg.startswith("ES"):
            analysis_md += "- **Signing Type:** Asymmetric (Public/Private Key)\n"
        else:
            analysis_md += "- **Signing Type:** Unknown / Custom\n"
    else:
        analysis_md += "- **Signing Type:** Unknown\n"

    analysis_md += "- **Encrypted:** ❌ No (Standard JWT is encoded, not encrypted)\n\n"

    # ==========================
    # Expiration Handling
    # ==========================

    now = datetime.utcnow()

    if "exp" in payload_json:
        try:
            exp_timestamp = int(payload_json["exp"])
            exp_time = datetime.utcfromtimestamp(exp_timestamp)

            analysis_md += f"- **Expiration (UTC):** {exp_time}\n"

            if now > exp_time:
                analysis_md += "- **Token Status:** ❌ Expired\n"
            else:
                remaining_seconds = int((exp_time - now).total_seconds())

                days = remaining_seconds // 86400
                hours = (remaining_seconds % 86400) // 3600
                minutes = (remaining_seconds % 3600) // 60

                analysis_md += f"- **Token Status:** ✅ Valid\n"
                analysis_md += f"- **Time Remaining:** {days}d {hours}h {minutes}m\n"

        except Exception:
            analysis_md += "- **Expiration:** Invalid UNIX timestamp format\n"
    else:
        analysis_md += "- **Expiration Claim:** Not Present\n"

    # Optional Claims
    if "iss" in payload_json:
        analysis_md += f"- **Issuer (iss):** {payload_json['iss']}\n"

    if "sub" in payload_json:
        analysis_md += f"- **Subject (sub):** {payload_json['sub']}\n"

    if "iat" in payload_json:
        try:
            issued_time = datetime.utcfromtimestamp(int(payload_json["iat"]))
            analysis_md += f"- **Issued At (iat):** {issued_time}\n"
        except:
            analysis_md += "- **Issued At (iat):** Invalid format\n"

    # ==========================
    # SECURITY WARNINGS
    # ==========================

    warnings = []

    # alg=none
    if isinstance(alg, str) and alg.lower() == "none":
        warnings.append("🚨 CRITICAL: 'alg=none' detected. This token is not cryptographically signed.")

    # No expiration
    if "exp" not in payload_json:
        warnings.append("⚠️ No expiration claim detected. Token may remain valid indefinitely.")

    # Symmetric algorithm warning
    if isinstance(alg, str) and alg.upper().startswith("HS"):
        warnings.append("⚠️ Symmetric signing detected. If the secret key is exposed, tokens can be forged.")

    # Very long-lived token warning
    if "exp" in payload_json:
        try:
            exp_timestamp = int(payload_json["exp"])
            exp_time = datetime.utcfromtimestamp(exp_timestamp)
            if exp_time - now > timedelta(days=30):
                warnings.append("⚠️ Token validity exceeds 30 days. Long-lived tokens increase risk.")
        except:
            pass

    # Sensitive payload data
    sensitive_keywords = ["password", "secret", "key", "token", "auth"]
    for field in payload_json.keys():
        if any(word in field.lower() for word in sensitive_keywords):
            warnings.append("🚨 Sensitive information detected in payload. JWT payload is readable by anyone.")
            break

    # Risk Level Calculation
    risk_level = "Low"
    if any("CRITICAL" in w for w in warnings):
        risk_level = "High"
    elif warnings:
        risk_level = "Medium"

    analysis_md += f"\n- **Overall Risk Level:** {risk_level}\n"

    # Format Warnings Output
    if warnings:
        warnings_md = "### 🚨 Security Observations\n\n"
        for w in warnings:
            warnings_md += f"- {w}\n"
    else:
        warnings_md = "### ✅ No obvious security misconfigurations detected."

    return header_json, payload_json, signature, analysis_md, warnings_md

# =========================================================
# Classical Cipher Logic  (Module 8 )
# =========================================================

ALPHABET = string.ascii_uppercase

def clean_text(text):
    return re.sub(r'[^A-Za-z]', '', text).upper()


# ======================
# Frequency Analysis
# ======================

def plot_frequency(text):
    text = clean_text(text)
    freq = {ch: 0 for ch in ALPHABET}

    for ch in text:
        freq[ch] += 1

    letters = list(freq.keys())
    counts = list(freq.values())

    fig, ax = plt.subplots(figsize=(6,3))
    ax.bar(letters, counts)
    ax.set_title("Letter Frequency Distribution")
    ax.set_ylabel("Count")
    plt.tight_layout()

    return fig


# ======================
# CAESAR CIPHER
# ======================

def caesar_encrypt(text, shift):
    text = clean_text(text)
    result = ""
    steps = []

    for ch in text:
        p = ord(ch) - 65
        c = (p + shift) % 26
        cipher_char = chr(c + 65)
        result += cipher_char
        steps.append(f"{ch}({p}) → {cipher_char}({c})")

    return result, "\n".join(steps), plot_frequency(result)


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def caesar_bruteforce(cipher):
    cipher = clean_text(cipher)
    results = []

    for k in range(1, 26):
        decrypted = ""
        for ch in cipher:
            c = ord(ch) - 65
            p = (c - k) % 26
            decrypted += chr(p + 65)
        results.append(f"Key {k:2d} → {decrypted}")

    return "\n".join(results)


# ======================
# VIGENERE CIPHER
# ======================

def expand_key(text, key):
    key = clean_text(key)
    expanded = ""
    key_index = 0

    for ch in text:
        expanded += key[key_index % len(key)]
        key_index += 1

    return expanded


def vigenere_encrypt(text, key):
    text = clean_text(text)
    key = clean_text(key)

    if not key:
        return "❌ Key required", "", ""

    expanded = expand_key(text, key)
    result = ""
    steps = []

    for p_char, k_char in zip(text, expanded):
        p = ord(p_char) - 65
        k = ord(k_char) - 65
        c = (p + k) % 26
        cipher_char = chr(c + 65)
        result += cipher_char
        steps.append(f"{p_char}({p}) + {k_char}({k}) → {cipher_char}({c})")

    return result, "\n".join(steps), expanded


def vigenere_decrypt(cipher, key):
    cipher = clean_text(cipher)
    key = clean_text(key)

    if not key:
        return "❌ Key required", "", ""

    expanded = expand_key(cipher, key)
    result = ""
    steps = []

    for c_char, k_char in zip(cipher, expanded):
        c = ord(c_char) - 65
        k = ord(k_char) - 65
        p = (c - k) % 26
        plain_char = chr(p + 65)
        result += plain_char
        steps.append(f"{c_char}({c}) - {k_char}({k}) → {plain_char}({p})")

    return result, "\n".join(steps), expanded


# ======================
# OTP Key Reuse Demo
# ======================

def otp_reuse_attack(p1, p2):
    p1 = clean_text(p1)
    p2 = clean_text(p2)

    if len(p1) != len(p2):
        return "❌ Messages must be same length"

    result = ""
    for a, b in zip(p1, p2):
        x = (ord(a) - 65) ^ (ord(b) - 65)
        result += chr((x % 26) + 65)

    return f"P1 ⊕ P2 = {result}\n\nIf attacker knows one plaintext, the other is recoverable."

def overview_dashboard():
    return """
    <div class='card'>
        <h2>🛡 CYBERGUARD SOC DASHBOARD</h2>
        <p>Real-Time Security Toolkit</p>
        <hr>
        <div style="display:flex; gap:40px; font-size:20px;">
            <div>
                <span style="color:#00f0ff;">8</span><br>
                Modules Active
            </div>
            <div>
                <span style="color:#7a00ff;">Monitoring</span><br>
                System Status
            </div>
            <div>
                <span style="color:#00ff88;">Operational</span><br>
                Environment
            </div>
        </div>
    </div>
    """

# =========================================================
# SUBNET CALCULATOR — MODULE 9
# =========================================================

def ip_to_binary(ip):
    return ".".join(format(int(octet), "08b") for octet in ip.split("."))


def get_ip_class(ip):
    first_octet = int(ip.split(".")[0])
    if 1 <= first_octet <= 126:
        return "Class A"
    elif 128 <= first_octet <= 191:
        return "Class B"
    elif 192 <= first_octet <= 223:
        return "Class C"
    elif 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    elif 240 <= first_octet <= 255:
        return "Class E (Reserved)"
    return "Unknown"


def calculate_subnet(ip_input, prefix):
    try:
        if not ip_input:
            return "❌ IP address required.", "", ""

        prefix = int(prefix)
        if prefix < 0 or prefix > 32:
            return "❌ CIDR must be between 0 and 32.", "", ""

        ip_obj = ipaddress.IPv4Address(ip_input)
        network = ipaddress.IPv4Network(f"{ip_input}/{prefix}", strict=False)

        total_ips = network.num_addresses
        host_bits = 32 - prefix

        # Host range logic (memory safe)
        if prefix < 31:
            usable_hosts = total_ips - 2
            first_host = str(network.network_address + 1)
            last_host = str(network.broadcast_address - 1)
        else:
            usable_hosts = total_ips
            first_host = "N/A"
            last_host = "N/A"

        # Binary AND Visualization
        ip_bin = ip_to_binary(ip_input)
        mask_bin = ip_to_binary(str(network.netmask))
        net_bin = ip_to_binary(str(network.network_address))

        # IP Type Detection
        if ip_obj.is_private:
            ip_type = "Private (RFC1918)"
        elif ip_obj.is_loopback:
            ip_type = "Loopback"
        elif ip_obj.is_multicast:
            ip_type = "Multicast"
        elif ip_obj.is_reserved:
            ip_type = "Reserved"
        else:
            ip_type = "Public"

        ip_class = get_ip_class(ip_input)

        result_md = f"""
## 🌐 Subnet Calculation Result

- **Input IP:** {ip_input}
- **IP Type:** {ip_type}
- **IP Class (Legacy):** {ip_class}
- **CIDR Prefix:** /{prefix}
- **Subnet Mask:** {network.netmask}
- **Network Address:** {network.network_address}
- **Broadcast Address:** {network.broadcast_address}
- **Total IPs:** {total_ips}
- **Usable Hosts:** {usable_hosts}
- **First Usable Host:** {first_host}
- **Last Usable Host:** {last_host}
"""

        explanation_md = f"""
## 🧠 Binary AND Operation

IP Address:
{ip_bin}

Subnet Mask:
{mask_bin}

----------------------------------------
Network Address (IP AND Mask):
{net_bin}

## 📐 Host Calculation

Host bits = 32 - {prefix} = {host_bits}

Total IPs = 2^{host_bits}

Usable Hosts = 2^{host_bits} - 2  
(1 reserved for Network ID, 1 reserved for Broadcast)

Broadcast Address = Network + (2^{host_bits} - 1)
"""

        security_notes = """
## 🔐 Security & Networking Notes

✔ CIDR allows variable-length subnet masking  
✔ Reduces IP wastage compared to classful addressing  
✔ /30 commonly used for point-to-point networks  
✔ /31 used in RFC 3021 (no broadcast)  
✔ /32 represents a single host  

⚠ Incorrect subnetting causes routing failures  
⚠ Misconfigured broadcast domains cause network congestion  
⚠ Always validate subnet boundaries in firewall/router configs
"""

        return result_md, explanation_md, security_notes

    except Exception as e:
        return f"❌ Error: {str(e)}", "", ""
    

# =========================================================
# HTTP HEADER ANALYZER — MODULE 10
# =========================================================

def analyze_http_headers(url):

    if not url:
        return "❌ URL required.", "", "", "", "", ""

    safe, error = is_safe_public_url(url)
    if not safe:
        return f"❌ {error}", "", "", "", "", ""

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

    except requests.exceptions.Timeout:
        return "❌ Request timed out.", "", "", "", "", ""

    except requests.exceptions.ConnectionError:
        return "❌ Connection failed.", "", "", "", "", ""

    except Exception as e:
        return f"❌ Error: {str(e)}", "", "", "", "", ""

    headers = response.headers
    risk_score = 0
    findings = []
    explanations = []

    # ===============================
    # HEADER PRESENCE CHECKS
    # ===============================

    # CSP
    csp = headers.get("Content-Security-Policy")
    if not csp:
        risk_score += 25
        findings.append("❌ Missing Content-Security-Policy")
        explanations.append(
            "CSP prevents XSS attacks by restricting script execution sources. "
            "Without it, injection attacks become easier."
        )
    else:
        if "unsafe-inline" in csp or "*" in csp:
            risk_score += 10
            findings.append("⚠ Weak CSP configuration detected")
            explanations.append(
                "CSP contains 'unsafe-inline' or wildcard. "
                "This weakens XSS protection."
            )

    # HSTS
    hsts = headers.get("Strict-Transport-Security")
    if not hsts:
        risk_score += 20
        findings.append("❌ Missing HSTS")
        explanations.append(
            "HSTS forces HTTPS usage and prevents SSL stripping attacks."
        )
    else:
        if "max-age" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0])
                if max_age < 15768000:  # 6 months
                    risk_score += 5
                    findings.append("⚠ Weak HSTS max-age (less than 6 months)")
            except:
                pass

    # X-Frame-Options
    if "X-Frame-Options" not in headers:
        risk_score += 15
        findings.append("❌ Missing X-Frame-Options")
        explanations.append(
            "Without X-Frame-Options, site is vulnerable to clickjacking attacks."
        )

    # X-Content-Type-Options
    if "X-Content-Type-Options" not in headers:
        risk_score += 10
        findings.append("❌ Missing X-Content-Type-Options")
        explanations.append(
            "Prevents MIME sniffing. Without it, browsers may misinterpret content types."
        )

    # Server Header Exposure
    if "Server" in headers:
        risk_score += 5
        findings.append("⚠ Server header exposed")
        explanations.append(
            "Server version disclosure may help attackers fingerprint the system."
        )

    # HTTP instead of HTTPS
    if url.startswith("http://"):
        risk_score += 10
        findings.append("⚠ Using HTTP (not HTTPS)")
        explanations.append(
            "Unencrypted HTTP allows MITM attacks and data interception."
        )

    # ===============================
    # REDIRECT ANALYSIS
    # ===============================

    redirect_chain = ""
    if response.history:
        redirect_chain = "Redirect Chain:\n"
        for r in response.history:
            redirect_chain += f"{r.status_code} → {r.url}\n"
        redirect_chain += f"{response.status_code} → {response.url}"

    # ===============================
    # RISK LEVEL CLASSIFICATION
    # ===============================

    if risk_score <= 20:
        risk_level = "🟢 LOW RISK"
    elif risk_score <= 50:
        risk_level = "🟠 MEDIUM RISK"
    else:
        risk_level = "🔴 HIGH RISK"

    # ===============================
    # FORMAT OUTPUT
    # ===============================

    header_output = ""
    for key, value in headers.items():
        header_output += f"{key}: {value}\n"

    report = f"## 🔐 Security Assessment\n\n"
    report += f"**Risk Score:** {risk_score}/100\n\n"
    report += f"**Risk Level:** {risk_level}\n\n"

    if findings:
        report += "### Findings:\n"
        for f in findings:
            report += f"- {f}\n"

        report += "\n### Impact Explanation:\n"
        for e in explanations:
            report += f"- {e}\n"
    else:
        report += "✅ No major security misconfigurations detected."

    report += "\n\n---\nMapped to OWASP Top 10 categories where applicable."

    return (
        header_output,
        report,
        f"HTTP {response.status_code}",
        f"{risk_score}/100",
        risk_level,
        redirect_chain
    )

def is_safe_public_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False, "Only HTTP/HTTPS URLs allowed."

        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL."

        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        if (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_link_local
        ):
            return False, "Internal/private IPs are not allowed."

        return True, None

    except Exception:
        return False, "URL validation failed."
    
# =========================================================
# FILE METADATA ANALYZER (Module 11)
# =========================================================

def extract_exif_data(image_path):
    try:
        image = Image.open(image_path)
        exif_data_raw = image._getexif()

        if not exif_data_raw:
            return {"general": {}, "gps": {}}, None

        exif_data = {}
        gps_data = {}

        for tag, value in exif_data_raw.items():
            tag_name = TAGS.get(tag, tag)

            if tag_name == "GPSInfo":
                for gps_tag in value:
                    sub_tag = GPSTAGS.get(gps_tag, gps_tag)
                    gps_data[sub_tag] = value[gps_tag]
            else:
                exif_data[tag_name] = value

        return {"general": exif_data, "gps": gps_data}, None

    except Exception as e:
        return None, f"Error reading image: {str(e)}"

def convert_gps_to_decimal(gps_data):
    try:
        def to_deg(value):
            d = value[0][0] / value[0][1]
            m = value[1][0] / value[1][1]
            s = value[2][0] / value[2][1]
            return d + (m / 60.0) + (s / 3600.0)

        lat = to_deg(gps_data["GPSLatitude"])
        if gps_data.get("GPSLatitudeRef") != "N":
            lat = -lat

        lon = to_deg(gps_data["GPSLongitude"])
        if gps_data.get("GPSLongitudeRef") != "E":
            lon = -lon

        return lat, lon
    except:
        return None, None


def strip_metadata(image_path):
    try:
        image = Image.open(image_path)
        clean_image = Image.new(image.mode, image.size)
        clean_image.putdata(list(image.getdata()))

        clean_path = "clean_image.jpg"
        clean_image.save(clean_path, format="JPEG")

        return clean_path

    except Exception:
        return None


def analyze_metadata(image_path):

    if not image_path:
        return "❌ No image uploaded.", "", "", ""

    data, error = extract_exif_data(image_path)

    if error:
        return error, "", "", ""

    if not data:
        return "❌ Unable to extract metadata.", "", "", ""

    general = data.get("general", {})
    gps = data.get("gps", {})

    risk_score = 0
    findings = []
    report = "## 🔍 Metadata Security Analysis\n\n"

    # Device Info
    device = general.get("Model")
    software = general.get("Software")

    if device:
        findings.append(f"📱 Device Model: {device}")
        risk_score += 10

    if software:
        findings.append(f"🖥 Software Used: {software}")
        risk_score += 5

    if "DateTimeOriginal" in general:
        findings.append(f"📅 Original Capture Time: {general['DateTimeOriginal']}")
        risk_score += 5

    gps_output = ""

    if gps:
        lat, lon = convert_gps_to_decimal(gps)

        if lat is not None and lon is not None:
            maps_link = f"https://www.google.com/maps?q={lat},{lon}"
            gps_output = (
                f"📍 GPS Coordinates Detected:\n"
                f"Latitude: {lat}\n"
                f"Longitude: {lon}\n\n"
                f"Google Maps Link:\n{maps_link}"
            )
            risk_score += 40
            findings.append("🚨 GPS location embedded in image.")
        else:
            gps_output = "GPS data present but could not decode."
            risk_score += 20

    if risk_score <= 10:
        level = "🟢 LOW"
    elif risk_score <= 30:
        level = "🟠 MEDIUM"
    else:
        level = "🔴 HIGH"

    report += f"**Risk Score:** {risk_score}/100\n"
    report += f"**Risk Level:** {level}\n\n"

    if findings:
        report += "### Findings:\n"
        for f in findings:
            report += f"- {f}\n"
    else:
        report += "No significant metadata risks detected.\n"

    report += """
---

### 🧠 Privacy & OSINT Risk Explanation

Image metadata can reveal:
- Device information
- Capture timestamp
- Exact GPS location

Always remove metadata before sharing images publicly.
"""

    raw_json = json.dumps(general, indent=2) if general else "No EXIF metadata found."

    return raw_json, report, gps_output, level

# =========================================================
# XSS PAYLOAD SIMULATOR (Module 12 - Safe Sandbox)
# =========================================================

def sanitize_input(user_input):
    """
    Very basic sanitization logic for demonstration.
    Removes script tags and event handlers.
    (Educational purpose only – not production grade)
    """

    # Remove <script>...</script>
    cleaned = re.sub(r"<script.*?>.*?</script>", "", user_input, flags=re.IGNORECASE | re.DOTALL)

    # Remove inline event handlers like onclick=, onerror=
    cleaned = re.sub(r'on\w+=".*?"', "", cleaned, flags=re.IGNORECASE)

    return cleaned


def analyze_xss_payload(payload):

    if not payload:
        return "❌ No input provided.", "", "", "", ""

    # Raw (exact user input)
    raw_output = payload

    # Escaped output (safe rendering)
    escaped_output = html.escape(payload)

    # Sanitized output (basic removal)
    sanitized_output = sanitize_input(payload)

    # Detection Logic
    risk_score = 0
    findings = []

    if "<script" in payload.lower():
        risk_score += 40
        findings.append("🚨 Script tag detected")

    if "onerror" in payload.lower() or "onclick" in payload.lower():
        risk_score += 25
        findings.append("⚠ Inline JavaScript event handler detected")

    if "javascript:" in payload.lower():
        risk_score += 20
        findings.append("⚠ javascript: protocol detected")

    if "<img" in payload.lower():
        risk_score += 10

    # Risk Classification
    if risk_score == 0:
        level = "🟢 LOW"
    elif risk_score <= 40:
        level = "🟠 MEDIUM"
    else:
        level = "🔴 HIGH"

    # Professional Security Explanation
    explanation = f"""
## 🔎 XSS Security Analysis Report

**Risk Score:** {risk_score}/100  
**Risk Level:** {level}

### Findings:
"""

    if findings:
        for f in findings:
            explanation += f"- {f}\n"
    else:
        explanation += "- No obvious malicious patterns detected.\n"

    explanation += """

---

### 🧠 What This Demonstrates

• Browsers interpret unescaped HTML as executable DOM content  
• Escaping converts special characters to harmless text  
• Sanitization removes dangerous elements before rendering  

If user input is rendered directly into the DOM without escaping,
the browser executes embedded scripts — resulting in Cross-Site Scripting (XSS).

Secure Development Rule:
✔ Always validate input  
✔ Always escape output  
✔ Use Content Security Policy (CSP)  
✔ Never trust client-side input  

This simulator is SAFE.
It does NOT execute payloads.
"""

    return raw_output, escaped_output, sanitized_output, explanation, level


# =========================================================
# URL & PHISHING DETECTOR (Module 13 - Enterprise Grade)
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "signin", "password", "confirm", "reset",
    "billing", "support", "security"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"
]


def calculate_shannon_entropy(text):
    """
    Detect randomness in domain (phishing domains often auto-generated).
    """
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log2(p) for p in prob])
    return entropy


def analyze_url_phishing(url):

    if not url:
        return "❌ URL required.", "", "", "", ""

    try:
        parsed = urlparse(url)

        if not parsed.scheme:
            url = "http://" + url
            parsed = urlparse(url)

        hostname = parsed.hostname
        if not hostname:
            return "❌ Invalid URL format.", "", "", "", ""

    except:
        return "❌ URL parsing failed.", "", "", "", ""

    risk_score = 0
    findings = []
    technical_breakdown = ""

    # =================================================
    # 1️⃣ LENGTH CHECK
    # =================================================
    if len(url) > 75:
        risk_score += 15
        findings.append("⚠ Excessively long URL (obfuscation technique)")

    # =================================================
    # 2️⃣ MANY SUBDOMAINS
    # =================================================
    subdomains = hostname.split(".")
    if len(subdomains) > 4:
        risk_score += 15
        findings.append("⚠ Multiple subdomains detected (possible deception)")

    # =================================================
    # 3️⃣ IP INSTEAD OF DOMAIN
    # =================================================
    try:
        ipaddress.ip_address(hostname)
        risk_score += 25
        findings.append("🚨 IP address used instead of domain name")
    except:
        pass

    # =================================================
    # 4️⃣ SUSPICIOUS KEYWORDS
    # =================================================
    lower_url = url.lower()
    keyword_hits = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]

    if keyword_hits:
        risk_score += 10 + (5 * len(keyword_hits))
        findings.append(f"⚠ Suspicious keywords detected: {', '.join(keyword_hits)}")

    # =================================================
    # 5️⃣ @ SYMBOL MISUSE
    # =================================================
    if "@" in url:
        risk_score += 20
        findings.append("🚨 '@' symbol used (URL redirection deception)")

    # =================================================
    # 6️⃣ PUNYCODE DETECTION
    # =================================================
    if hostname.startswith("xn--"):
        risk_score += 30
        findings.append("🚨 Punycode domain detected (possible homograph attack)")

    # =================================================
    # 7️⃣ HYPHEN ABUSE
    # =================================================
    if hostname.count("-") >= 3:
        risk_score += 10
        findings.append("⚠ Excessive hyphen usage")

    # =================================================
    # 8️⃣ SUSPICIOUS TLD
    # =================================================
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            risk_score += 15
            findings.append(f"⚠ Suspicious TLD detected: {tld}")
            break

    # =================================================
    # 9️⃣ HTTPS CHECK
    # =================================================
    if parsed.scheme != "https":
        risk_score += 10
        findings.append("⚠ Not using HTTPS")

    # =================================================
    # 🔟 DOMAIN RANDOMNESS (Entropy)
    # =================================================
    domain_core = hostname.replace(".", "")
    entropy = calculate_shannon_entropy(domain_core)

    if entropy > 4.0:
        risk_score += 15
        findings.append("⚠ High domain randomness detected")

    # =================================================
    # RISK CLASSIFICATION
    # =================================================
    if risk_score <= 25:
        level = "🟢 LOW"
    elif risk_score <= 60:
        level = "🟠 MEDIUM"
    else:
        level = "🔴 HIGH"

    # =================================================
    # TECHNICAL REPORT
    # =================================================
    technical_breakdown = f"""
## 🔍 URL Phishing Risk Assessment

**Analyzed URL:** {url}

**Risk Score:** {risk_score}/100  
**Risk Level:** {level}

### Heuristic Findings:
"""

    if findings:
        for f in findings:
            technical_breakdown += f"- {f}\n"
    else:
        technical_breakdown += "- No obvious phishing indicators detected.\n"

    technical_breakdown += f"""

---

### 📊 Structural Analysis

- Hostname: {hostname}
- Subdomain Count: {len(subdomains)-2 if len(subdomains)>=2 else 0}
- Domain Entropy Score: {entropy:.2f}

---

### 🧠 Security Explanation

Phishing URLs rely on:
• Visual deception (homograph / punycode attacks)  
• Excessive subdomains  
• Keyword-based urgency  
• IP-based hosting  
• Obfuscation via long strings  

Always verify:
✔ Domain spelling  
✔ HTTPS certificate  
✔ Official source navigation  
✔ No unusual symbols or redirection  

This module uses heuristic-based scoring.
It does NOT perform reputation lookup.
"""

    return hostname, risk_score, level, entropy, technical_breakdown

# =========================================================
# DIGITAL SIGNATURE DEMO (Module 14)
# =========================================================

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ================================
# Key Generation
# ================================

def generate_rsa_keys():
    """
    Generates RSA 2048-bit key pair.
    Returns PEM formatted private and public keys.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()


# ================================
# Signing Function
# ================================

def sign_message(message, private_pem):
    try:
        if not message or not private_pem:
            return "❌ Message and Private Key required."

        private_key = serialization.load_pem_private_key(
            private_pem.encode(),
            password=None
        )

        signature = private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    except Exception as e:
        return f"❌ Signing failed: {str(e)}"


# ================================
# Verification Function
# ================================

def verify_signature(message, signature_b64, public_pem):
    try:
        if not message or not signature_b64 or not public_pem:
            return "❌ Message, Signature and Public Key required."

        public_key = serialization.load_pem_public_key(
            public_pem.encode()
        )

        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return "✅ Signature VALID — Integrity & Authenticity Verified"

    except InvalidSignature:
        return "🚨 Signature INVALID — Message Tampered or Wrong Public Key"

    except Exception as e:
        return f"❌ Verification failed: {str(e)}"

# =========================================================
# FIREWALL RULE SIMULATOR (Module 15 - Enterprise Logic Engine)
# =========================================================

FIREWALL_RULES = []

def parse_port_rule(port_rule):
    """
    Supports:
    - Single port (22)
    - Range (20-25)
    - Any (*)
    """
    port_rule = str(port_rule).strip()

    if port_rule == "*" or port_rule.lower() == "any":
        return ("any", None)

    if "-" in port_rule:
        start, end = port_rule.split("-")
        return ("range", (int(start), int(end)))

    return ("single", int(port_rule))


def add_firewall_rule(action, src_cidr, port_rule, protocol):
    """
    Adds rule to global rule table.
    Rules evaluated in insertion order.
    """

    try:
        network = ipaddress.ip_network(src_cidr, strict=False)
        port_type, port_value = parse_port_rule(port_rule)

        rule = {
            "action": action.upper(),
            "network": network,
            "port_type": port_type,
            "port_value": port_value,
            "protocol": protocol.upper(),
            "hits": 0
        }

        FIREWALL_RULES.append(rule)

        return f"✅ Rule Added: {action.upper()} | {src_cidr} | {port_rule} | {protocol.upper()}"

    except Exception as e:
        return f"❌ Invalid Rule: {str(e)}"


def clear_firewall_rules():
    FIREWALL_RULES.clear()
    return "🧹 All firewall rules cleared."


def evaluate_packet(src_ip, dest_port, protocol):
    """
    Simulates firewall logic:
    - Top-down evaluation
    - First match wins
    - Default deny if no match
    """

    try:
        ip_obj = ipaddress.ip_address(src_ip)
        dest_port = int(dest_port)
        protocol = protocol.upper()

    except:
        return "❌ Invalid packet parameters.", ""

    trace = "## 🔎 Evaluation Trace\n\n"

    for idx, rule in enumerate(FIREWALL_RULES):

        trace += f"Checking Rule {idx+1} → {rule['action']} | {rule['network']} | "

        # Check IP match
        if ip_obj not in rule["network"]:
            trace += "IP ❌\n"
            continue

        # Check protocol match
        if rule["protocol"] != "ANY" and rule["protocol"] != protocol:
            trace += "Protocol ❌\n"
            continue

        # Check port match
        port_match = False

        if rule["port_type"] == "any":
            port_match = True

        elif rule["port_type"] == "single":
            port_match = (dest_port == rule["port_value"])

        elif rule["port_type"] == "range":
            start, end = rule["port_value"]
            port_match = (start <= dest_port <= end)

        if not port_match:
            trace += "Port ❌\n"
            continue

        # MATCH FOUND
        rule["hits"] += 1
        trace += "MATCH ✅\n"

        decision = "🟢 ALLOWED" if rule["action"] == "ALLOW" else "🔴 BLOCKED"

        explanation = f"""
## 🛡 Firewall Decision

**Source IP:** {src_ip}  
**Destination Port:** {dest_port}  
**Protocol:** {protocol}  

**Matched Rule:** Rule {idx+1}  
**Action:** {rule["action"]}  

### Final Verdict:
{decision}

✔ First-match-wins logic applied.
✔ Rules evaluated top-down.
✔ Real firewall behavior simulated.
"""

        return explanation, trace

    # Default deny
    explanation = f"""
## 🛡 Firewall Decision

No rule matched.

### Final Verdict:
🔴 BLOCKED (Default Deny Policy)

✔ Secure firewalls operate on default deny.
"""

    return explanation, trace


def get_firewall_stats():
    if not FIREWALL_RULES:
        return "No rules configured."

    output = "## 📊 Firewall Rule Statistics\n\n"

    for idx, rule in enumerate(FIREWALL_RULES):
        output += (
            f"Rule {idx+1}: {rule['action']} | "
            f"{rule['network']} | "
            f"{rule['port_type']} | "
            f"{rule['protocol']} | "
            f"Hits: {rule['hits']}\n"
        )

    return output

# =========================================================
# SECURE PASSWORD STORAGE DEMO (Module 16)
# =========================================================

def secure_password_demo(password):
    """
    Demonstrates secure password storage concepts:
    - Plain password
    - Unsalted hash
    - Salted hash
    - Why salting prevents rainbow attacks
    """

    if not password:
        return "", "", "", "", "", ""

    # -------------------------
    # 1️⃣ Plain
    # -------------------------
    plain_output = password

    # -------------------------
    # 2️⃣ Unsalted Hash
    # -------------------------
    unsalted_hash = hashlib.sha256(password.encode()).hexdigest()

    # -------------------------
    # 3️⃣ Salted Hash
    # -------------------------
    salt = os.urandom(16)
    salt_hex = salt.hex()

    salted_hash = hashlib.sha256(
        password.encode() + salt
    ).hexdigest()

    # -------------------------
    # 4️⃣ Simulate Storage Format
    # -------------------------
    storage_format = f"{salt_hex}:{salted_hash}"

    # -------------------------
    # 5️⃣ Demonstration Logic
    # -------------------------
    same_password_note = """
If two users use the SAME password:

Without salt:
→ Hashes are IDENTICAL

With salt:
→ Hashes are DIFFERENT
"""

    # -------------------------
    # 6️⃣ Security Explanation
    # -------------------------
    explanation = f"""
## 🔐 Secure Password Storage Analysis

### 1️⃣ Plain Storage (INSECURE)
Storing raw passwords is catastrophic.
Database breach = instant credential exposure.

---

### 2️⃣ Unsalted Hash
SHA256(password)

• Deterministic  
• Same password → Same hash  
• Vulnerable to rainbow table attacks  

If attacker has precomputed SHA256 hashes of common passwords,
they can instantly reverse weak passwords.

---

### 3️⃣ Salted Hash
SHA256(password + random_salt)

• Each user gets unique salt  
• Same password → Different hashes  
• Rainbow tables become useless  
• Attacker must brute-force each password individually  

Salt MUST be stored alongside hash.
Salt is NOT secret.
Its purpose is uniqueness, not secrecy.

---

### 🚫 Double Hashing Myth
Hashing twice like:
SHA256(SHA256(password))

Does NOT add meaningful protection.
Attackers can precompute double hashes too.

Real security requires:
✔ Salt
✔ Slow hashing (bcrypt / Argon2 / PBKDF2)
✔ High iteration count

---

### 🛡 Production Recommendation
Never use plain SHA256 for passwords.
Use:

• bcrypt  
• Argon2  
• PBKDF2 (100k+ iterations)  

This demo uses SHA256 for educational visibility only.
"""

    security_level = "🟢 SECURE (When Salted Properly)"

    return (
        plain_output,
        unsalted_hash,
        salt_hex,
        salted_hash,
        storage_format,
        explanation,
    )

# =========================================================
# CYBERGUARD ENTERPRISE SOC UI (FINAL WORKING VERSION)
# =========================================================

custom_css = """
/* Top Header Bar */
.gradio-container {
    background-color: #ffffff !important;
}

body {
    background:#ffffff;
    color:#e5e7eb;
    font-family:'Segoe UI',sans-serif;
    margin:0;
}

/* Custom White Top Bar */
.top-banner {
    background:#ffffff;
    color:#0b1220;
    text-align:center;
    padding:20px 0;
    font-size:32px;
    font-weight:700;
    letter-spacing:2px;
    border-bottom:2px solid #e5e7eb;
}

/* Sidebar */
.sidebar {
    background:#0f172a;
    padding:20px;
    min-height:100vh;
    border-right:1px solid #1e293b;
}

.sidebar button {
    width:100%;
    margin-bottom:10px;
    background:#111827;
    color:#e5e7eb;
    border:1px solid #1f2937;
    border-radius:8px;
}

.sidebar button:hover {
    background:#1e293b;
}

/* Main Panel */
.main-panel {
    padding:30px;
}

.header {
    background:linear-gradient(90deg,#1e293b,#0f172a);
    padding:25px;
    border-radius:12px;
    margin-bottom:25px;
    box-shadow:0 0 20px rgba(59,130,246,0.3);
}

.header-row{
    display:flex;
    justify-content:space-between;
    align-items:center;
}

.header h1{
    color:#ffffff;
    font-weight:700;
    letter-spacing:1px;
    text-shadow:0px 0px 10px rgba(59,130,246,0.6);
}

.header p{
    color:#cbd5e1;
    font-size:14px;
}



.student-info{
    text-align:right;
    font-size:14px;
    color:#cbd5e1;
}
"""
# ================= UI Encryption Wrapper =================

def ui_encrypt(text, password, algorithm):
    if not text or not password:
        return "❌ Text & password required", "", ""

    if algorithm == "AES-GCM":
        return aes_gcm_encrypt(text, password)

    elif algorithm == "AES-CBC":
        return aes_cbc_encrypt(text, password)

    elif algorithm == "Fernet":
        cipher, salt = fernet_encrypt(text, password)
        return cipher, salt, "N/A"

    return "❌ Unknown algorithm", "", ""


def ui_decrypt(cipher_text, password, salt, nonce, algorithm):
    if not cipher_text or not password or not salt:
        return "❌ Missing required fields"

    if algorithm == "AES-GCM":
        return aes_gcm_decrypt(cipher_text, password, salt, nonce)

    elif algorithm == "AES-CBC":
        return aes_cbc_decrypt(cipher_text, password, salt, nonce)

    elif algorithm == "Fernet":
        return fernet_decrypt(cipher_text, password, salt)

    return "❌ Unknown algorithm"

# ================= MAIN UI =================

with gr.Blocks(css=custom_css) as demo:

    gr.HTML("<div class='top-banner'> CyberGuard-X: A Unified Enterprise Security Operations & Cyber Defense Simulation Platform</div>")


    with gr.Row():
        gr.Markdown("### DEBUG BUILD VERSION 11 ACTIVE")

        # ===== SIDEBAR =====
        with gr.Column(scale=1, elem_classes="sidebar"):
            gr.Markdown("## 🛡 CYBERGUARD")

            dashboard_btn = gr.Button("📊 Dashboard")
            network_btn = gr.Button("🔍 Network")
            credential_btn = gr.Button("🔐 Credentials")
            integrity_btn = gr.Button("📁 Integrity")
            threat_btn = gr.Button("🚨 Threats")
            crypto_btn = gr.Button("🔐 Crypto Lab")
            cvss_btn = gr.Button("📈 CVSS")
            jwt_btn = gr.Button("🔑 JWT")
            classical_btn = gr.Button("🔐 Classical Cipher")
            subnet_btn = gr.Button("🌐 Subnet")
            http_btn = gr.Button("🌐 HTTP Headers")
            metadata_btn = gr.Button("🖼 Metadata")
            xss_btn = gr.Button("🧪 XSS Simulator")
            url_detector_btn = gr.Button("🔗 URL Detector")
            signature_btn = gr.Button("✍ Digital Signature")
            firewall_btn = gr.Button("🔥 Firewall")
            password_storage_btn = gr.Button("🔒 Password Storage")
            
        # ===== MAIN PANEL =====
        with gr.Column(scale=4, elem_classes="main-panel"):

            gr.HTML("""
                    <div class='header'>
                    <div class='header-row'>
                    <div>
                    <h1>CYBERGUARD SOC CONSOLE</h1>
                    <p>Enterprise Security Operations Platform</p>
                    </div>
                    
                    <div class='student-info'>
                    <p><b>Name:</b> P. TEJENDRA REDDY</p>
                    <p><b>Roll No:</b> CH.EN.U4CYS22060</p>
                    </div>
                    </div>
                    </div>
                    """)

            # DASHBOARD
            dashboard_view = gr.Column(visible=True)
            with dashboard_view:
                gr.Markdown("### Welcome to CyberGuard Enterprise SOC")
                gr.Markdown("All 16 modules operational.")

            # NETWORK
            network_view = gr.Column(visible=False)
            with network_view:
                ip_input = gr.Textbox(label="Target IP", placeholder="Example: 127.0.0.1")
                port_range = gr.Textbox(label="Port Range", value="1-100")
                scan_button = gr.Button("Launch Scan")
                scan_output = gr.Textbox(lines=18, label="Scan Results")
                scan_chart = gr.Plot(label="Scan Summary")

                scan_button.click(
                    run_port_scanner,
                    inputs=[ip_input, port_range],
                    outputs=[scan_output, scan_chart]
                )
                explain_btn = gr.Button("🧠 AI Explain Result")
                llm_explanation = gr.Markdown(
                    label="AI Security Explanation"
                )

                explain_btn.click(
                    lambda x: explain_with_llm("network_scanner", x),
                    inputs=scan_output,
                    outputs=llm_explanation
                )



            # CREDENTIAL
            credential_view = gr.Column(visible=False)
            with credential_view:
                password_box = gr.Textbox(type="password")
                gen_btn = gr.Button("Generate")
                check_btn = gr.Button("Analyze")
                result_md = gr.Markdown()
                history_plot = gr.Plot()

                gen_btn.click(generate_password, outputs=password_box)
                check_btn.click(
                    analyze_password,
                    inputs=password_box,
                    outputs=[result_md, history_plot]
                )
                ai_btn_pw = gr.Button("🧠 AI Explain Result")
                ai_pw = gr.Markdown()

                ai_btn_pw.click(
                    lambda x: explain_with_llm("password_analyzer", x),
                    inputs=result_md,
                    outputs=ai_pw
                )



            # INTEGRITY
            integrity_view = gr.Column(visible=False)
            with integrity_view:
                folder_input = gr.File(file_count="directory")
                baseline_btn = gr.Button("Create Baseline")
                recheck_btn = gr.Button("Recheck")
                integrity_output = gr.Textbox(lines=18)
                integrity_plot = gr.Plot()

                baseline_btn.click(create_baseline,
                                   inputs=folder_input,
                                   outputs=integrity_output)

                recheck_btn.click(check_integrity,
                                  outputs=[integrity_output, integrity_plot])
                ai_btn_integrity = gr.Button("🧠 AI Explain Result")
                ai_integrity = gr.Markdown()

                ai_btn_integrity.click(
                    lambda x: explain_with_llm("integrity_checker", x),
                    inputs=integrity_output,
                    outputs=ai_integrity
                )

            # THREAT
            threat_view = gr.Column(visible=False)
            with threat_view:
                analyze_btn = gr.Button("Analyze Logs")
                alert_output = gr.Textbox(lines=6)
                attack_plot = gr.Plot()
                probability_output = gr.Textbox()
                last_logs_output = gr.Textbox(lines=10)

                analyze_btn.click(
                    analyze_logs_ui,
                    outputs=[
                        alert_output,
                        attack_plot,
                        probability_output,
                        last_logs_output
                    ]
                )
                ai_btn_logs = gr.Button("🧠 AI Explain Result")
                ai_logs = gr.Markdown()

                ai_btn_logs.click(
                    lambda x: explain_with_llm("threat_analyzer", x),
                    inputs=alert_output,
                    outputs=ai_logs
                )

            # ================= CRYPTO =================
            crypto_view = gr.Column(visible=False)
            with crypto_view:

                with gr.Tabs():

                    # Encoding
                    with gr.Tab("Encoding"):
                        text = gr.Textbox(label="Input")
                        algo = gr.Radio(["Base64","Hex","HTML Entities","URL Encode"])
                        out = gr.Textbox()
                        btn = gr.Button("Run Encoding")

                        btn.click(
                            lambda t, a:
                                base64_encode(t) if a == "Base64"
                                else hex_encode(t) if a == "Hex"
                                else html_encode(t) if a == "HTML Entities"
                                else urllib.parse.quote(t) if a == "URL Encode"
                                else "❌ Unsupported encoding",
                            inputs=[text, algo],
                            outputs=out
                        )

                    # Hash
                    with gr.Tab("Hashing"):
                        htxt = gr.Textbox()
                        halgo = gr.Dropdown(
                            ["MD5","SHA-1","SHA-256","SHA-384","SHA-512"],
                            value="SHA-256"
                        )
                        hout = gr.Textbox()
                        hbtn = gr.Button("Generate Hash")
                        hbtn.click(hash_text, [htxt, halgo], hout)

                    # Encryption
                    with gr.Tab("🔒 Encryption"):

                        ptxt = gr.Textbox(label="Plain Text")
                        pwd = gr.Textbox(label="Password", type="password")

                        enc_algo = gr.Radio(
                            ["AES-GCM","AES-CBC","Fernet"],
                            value="AES-GCM"
                        )

                        enc_btn = gr.Button("Encrypt")
                        cipher = gr.Textbox(label="Cipher")
                        salt = gr.Textbox(label="Salt")
                        nonce = gr.Textbox(label="Nonce / IV")

                        enc_btn.click(
                            ui_encrypt,
                            [ptxt, pwd, enc_algo],
                            [cipher, salt, nonce]
                        )

                        dec_btn = gr.Button("Decrypt")
                        dec_out = gr.Textbox(label="Decrypted")

                        dec_btn.click(
                            ui_decrypt,
                            [cipher, pwd, salt, nonce, enc_algo],
                            dec_out
                        )
                        ai_btn_crypto = gr.Button("🧠 AI Explain Result")
                        ai_crypto = gr.Markdown()

                        ai_btn_crypto.click(
                            lambda x: explain_with_llm("crypto_module", x), 
                            inputs=hout,
                            outputs=ai_crypto
                        )
            
            # ================= CVSS =================
            cvss_view = gr.Column(visible=False)
            with cvss_view:
                av = gr.Dropdown(list(AV_VALUES.keys()), label="Attack Vector")
                ac = gr.Dropdown(list(AC_VALUES.keys()), label="Attack Complexity")
                pr = gr.Dropdown(["None","Low","High"], label="Privileges Required")
                ui = gr.Dropdown(list(UI_VALUES.keys()), label="User Interaction")
                scope = gr.Dropdown(["Unchanged","Changed"], label="Scope")
                c = gr.Dropdown(list(CIA_VALUES.keys()), label="Confidentiality")
                i = gr.Dropdown(list(CIA_VALUES.keys()), label="Integrity")
                a = gr.Dropdown(list(CIA_VALUES.keys()), label="Availability")

                calc_btn = gr.Button("Calculate CVSS")

                score = gr.Textbox(label="Base Score")
                severity = gr.Textbox(label="Severity")
                vector = gr.Textbox(label="Vector String")
                explanation = gr.Textbox(lines=6, label="Explanation")

                calc_btn.click(
                    calculate_cvss,
                    inputs=[av, ac, pr, ui, scope, c, i, a],
                    outputs=[score, severity, vector, explanation]
                )
                ai_btn_cvss = gr.Button("🧠 AI Explain CVSS")
                ai_cvss = gr.Markdown()

                ai_btn_cvss.click(
                    lambda x: explain_with_llm("cvss_calculator", x),
                    inputs=explanation,
                    outputs=ai_cvss
                )




            # ================= JWT =================
            jwt_view = gr.Column(visible=False)
            with jwt_view:

                with gr.Tabs():

                    with gr.Tab("ℹ About JWT"):
                        gr.Markdown("""
Header.Payload.Signature  
JWT is Base64URL encoded, NOT encrypted.
""")

                    with gr.Tab("🧪 JWT Analyzer"):
                        jwt_input = gr.Textbox(lines=4)
                        analyze_jwt_btn = gr.Button("Analyze")

                        header_output = gr.JSON()
                        payload_output = gr.JSON()
                        signature_output = gr.Textbox()
                        analysis_output = gr.Markdown()
                        warnings_output = gr.Markdown()

                        analyze_jwt_btn.click(
                            analyze_jwt,
                            inputs=jwt_input,
                            outputs=[
                                header_output,
                                payload_output,
                                signature_output,
                                analysis_output,
                                warnings_output
                            ]
                        )
                        ai_btn_jwt = gr.Button("🧠 AI Explain JWT")
                        ai_jwt = gr.Markdown()

                        ai_btn_jwt.click(
                            lambda x: explain_with_llm("jwt_analyzer", x),
                            inputs=analysis_output,
                            outputs=ai_jwt
                        )


                    with gr.Tab("🧠 Learning Notes"):
                        gr.Markdown("""
✔ HS256 symmetric  
✔ RS256 asymmetric  
✔ exp expiration  
❌ alg=none insecure  
""")

            # ================= CLASSICAL =================
            classical_view = gr.Column(visible=False)
            with classical_view:

                with gr.Tabs():

                    with gr.Tab("🟠 Caesar"):
                        caesar_input = gr.Textbox(label="Input")
                        caesar_shift = gr.Slider(1,25,value=3,label="Shift")
                        enc_btn = gr.Button("Encrypt")
                        dec_btn = gr.Button("Decrypt")
                        brute_btn = gr.Button("Brute Force")
                        out = gr.Textbox(lines=4)
                        steps = gr.Textbox(lines=8)
                        plot = gr.Plot()

                        enc_btn.click(
                            caesar_encrypt,
                            [caesar_input, caesar_shift],
                            [out, steps, plot]
                        )

                        dec_btn.click(
                            caesar_decrypt,
                            [caesar_input, caesar_shift],
                            [out, steps, plot]
                        )

                        brute_btn.click(
                            caesar_bruteforce,
                            caesar_input,
                            out
                        )

                    with gr.Tab("🔵 Vigenère"):
                        vig_input = gr.Textbox(label="Input")
                        vig_key = gr.Textbox(label="Key")
                        enc = gr.Button("Encrypt")
                        dec = gr.Button("Decrypt")
                        out = gr.Textbox(lines=4)
                        steps = gr.Textbox(lines=10)
                        expanded = gr.Textbox()

                        enc.click(
                            vigenere_encrypt,
                            [vig_input, vig_key],
                            [out, steps, expanded]
                        )

                        dec.click(
                            vigenere_decrypt,
                            [vig_input, vig_key],
                            [out, steps, expanded]
                        )

                    with gr.Tab("🧨 OTP Reuse"):
                        p1 = gr.Textbox(label="Plaintext 1")
                        p2 = gr.Textbox(label="Plaintext 2")
                        btn = gr.Button("Simulate Attack")
                        result = gr.Textbox(lines=6)

                        btn.click(
                            otp_reuse_attack,
                            [p1, p2],
                            result
                        )
                        ai_btn_cipher = gr.Button("🧠 AI Explain Cipher")
                        ai_cipher = gr.Markdown()

                        ai_btn_cipher.click(
                            lambda x: explain_with_llm("classical_cipher", x),
                            inputs=result,
                            outputs=ai_cipher
                        )

            # ================= SUBNET =================
            subnet_view = gr.Column(visible=False)
            with subnet_view:
                with gr.Tabs():

                    with gr.Tab("ℹ About"):

                        gr.Markdown("Subnet learning module")
                    
                    with gr.Tab("🧮 Calculator"):

                        subnet_ip = gr.Textbox(
                            label="IPV4 Address",
                            placeholder="192.168.1.10"
                        )

                        subnet_prefix = gr.Slider(
                            0, 32, value=24, step=1,
                            label="CIDR Prefix Length"
                        )

                        subnet_calculate_btn = gr.Button("Calculate Subnet")

                        subnet_result = gr.Markdown()
                        subnet_explanation = gr.Markdown()
                        subnet_security = gr.Markdown()

                        subnet_calculate_btn.click(
                            calculate_subnet,
                            inputs=[subnet_ip, subnet_prefix],
                            outputs=[subnet_result, subnet_explanation, subnet_security]
                        )
                        ai_btn_subnet = gr.Button("🧠 AI Explain Result")
                        ai_subnet = gr.Markdown()

                        ai_btn_subnet.click(
                            lambda x: explain_with_llm("subnet_calculator", x),
                            inputs=subnet_explanation,
                            outputs=ai_subnet
                        )

                        
            # ================= HTTP HEADERS =================
            http_view = gr.Column(visible=False)
            with http_view:
                gr.Markdown("### 🌐 HTTP Header Analyzer")

                http_url = gr.Textbox(
                    label="Target URL"
                )
                http_analyze_btn = gr.Button("Analyze Headers")

                http_headers_output = gr.Textbox(
                    lines=12,
                    label="Response Headers"
                )
                report_output = gr.Markdown()
                status_output = gr.Textbox(label="HTTP Status")
                score_output = gr.Textbox(label="Risk Score")
                level_output = gr.Textbox(label="Risk Level")
                redirect_output = gr.Textbox(lines=6, label="Redirect Chain")

                http_analyze_btn.click(
                    analyze_http_headers,
                    inputs=http_url,
                    outputs=[
                        http_headers_output,
                        report_output,
                        status_output,
                        score_output,
                        level_output,
                        redirect_output
                    ]
                )
                ai_btn_http = gr.Button("🧠 AI Explain Result")
                ai_http = gr.Markdown()

                ai_btn_http.click(
                    lambda x: explain_with_llm("http_header_analyzer", x),
                    inputs=report_output,
                    outputs=ai_http
                )

            # ================= METADATA =================
            metadata_view = gr.Column(visible=False)
            with metadata_view:
                gr.Markdown("### 🖼 File Metadata Analyzer (EXIF)")
                image_input = gr.File(
                    label="Upload Image (JPEG recommended)",
                    file_types=["image"],
                    type="filepath"
                )
                    
                analyze_btn = gr.Button("Analyze Metadata")

                raw_output = gr.Textbox(
                    lines=12,       
                    label="Raw Metadata"
                )

                metadata_report_output = gr.Markdown()

                gps_output = gr.Textbox(
                    lines=4,
                    label="GPS Information"
                )

                risk_level_output = gr.Textbox(label="Risk Level")

                strip_btn = gr.Button("🧹 Strip Metadata")

                clean_image_output = gr.File(label="Download Clean Image")

                analyze_btn.click(
                    analyze_metadata,
                    inputs=image_input,
                    outputs=[
                        raw_output,
                        metadata_report_output,
                        gps_output,
                        risk_level_output
                    ]
                )

                strip_btn.click(
                    strip_metadata,
                    inputs=image_input,
                    outputs=clean_image_output
                )
                ai_btn_meta = gr.Button("🧠 AI Explain Metadata")
                ai_meta = gr.Markdown()

                ai_btn_meta.click(
                    lambda x: explain_with_llm("metadata_analyzer", x),
                    inputs=metadata_report_output,
                    outputs=ai_meta
                )


            # ================= XSS SIMULATOR =================
            xss_view = gr.Column(visible=False)
            with xss_view:

                gr.Markdown("### 🧪 XSS Payload Simulator (Safe Sandbox)")

                gr.Markdown("""
                            This module demonstrates how Cross-Site Scripting (XSS) works.
                            ⚠ This environment is SAFE.  
                            User input is never rendered as executable HTML.
                            """)
                
                xss_input = gr.Textbox(
                    lines=4,
                    label="Enter Payload",
                    placeholder="<script>alert(1)</script>"
                )

                xss_analyze_btn = gr.Button("Analyze Payload")

                raw_display = gr.Textbox(
                    lines=4,
                    label="Raw Input"
                )

                escaped_display = gr.Textbox(
                    lines=4,
                    label="Escaped Output (Safe Rendering)"
                )

                sanitized_display = gr.Textbox(
                    lines=4,
                    label="Sanitized Output"
                )

                xss_report = gr.Markdown()
                xss_risk = gr.Textbox(label="Risk Level")

                xss_analyze_btn.click(
                    analyze_xss_payload,
                    inputs=xss_input,
                    outputs=[
                        raw_display,
                        escaped_display,
                        sanitized_display,
                        xss_report,
                        xss_risk
                    ]
                )

                ai_btn_xss = gr.Button("🧠 AI Explain XSS Risk")
                ai_xss = gr.Markdown()

                ai_btn_xss.click(
                    lambda x: explain_with_llm("xss_simulator", x),
                    inputs=xss_report,
                    outputs=ai_xss
                )


            # ================= URL PHISHING DETECTOR =================
            phishing_view = gr.Column(visible=False)
            
            with phishing_view:
                gr.Markdown("### 🔗 URL Phishing Risk Detector")

                phishing_input = gr.Textbox(
                    label="Enter URL",
                    placeholder="https://secure-login-bank-update.com"
                )

                phishing_analyze_btn = gr.Button("Analyze URL")

                phishing_domain_output = gr.Textbox(label="Extracted Hostname")
                phishing_score_output = gr.Textbox(label="Risk Score")
                phishing_level_output = gr.Textbox(label="Risk Level")
                phishing_entropy_output = gr.Textbox(label="Domain Entropy")
                phishing_report_output = gr.Markdown()

                phishing_analyze_btn.click(
                    analyze_url_phishing,
                    inputs=phishing_input,
                    outputs=[
                        phishing_domain_output,
                        phishing_score_output,
                        phishing_level_output,
                        phishing_entropy_output,
                        phishing_report_output
                    ]
                )

                ai_btn_phishing = gr.Button("🧠 AI Explain Phishing Risk")
                ai_phishing = gr.Markdown()

                ai_btn_phishing.click(
                    lambda x: explain_with_llm("phishing_detector", x),
                    inputs=phishing_report_output,
                    outputs=ai_phishing
                )


            # ================= DIGITAL SIGNATURE ANALYZER =================
            signature_view = gr.Column(visible=False)
            with signature_view:
                gr.Markdown("### ✍ RSA Digital Signature Demonstration")

                gr.Markdown("""
                            This module demonstrates real-world public key digital signatures using:

                            • RSA 2048-bit
                            • SHA-256 hashing 
                            • PSS padding (modern secure standard) 
                            
                            Digital Signature provides:
                            
                            ✔ Integrity
                            ✔ Authentication
                            ✔ Non-repudiation
                            """)
                
                generate_keys_btn = gr.Button("Generate RSA Key Pair")

                private_key_box = gr.Textbox(
                    lines=10,
                    label="Private Key (PEM format)"
                )

                public_key_box = gr.Textbox(
                    lines=8,
                    label="Public Key (PEM format)"
                )

                generate_keys_btn.click(
                    generate_rsa_keys,
                    outputs=[private_key_box, public_key_box]
                )

                gr.Markdown("---")

                message_box = gr.Textbox(
                    lines=4,
                    label="Message to Sign"
                )

                sign_btn = gr.Button("Sign Message")

                signature_output = gr.Textbox(
                    lines=4,
                    label="Generated Signature (Base64)"
                )

                sign_btn.click(
                    sign_message,
                    inputs=[message_box, private_key_box],
                    outputs=signature_output
                )

                verify_btn = gr.Button("Verify Signature")

                verify_output = gr.Textbox(label="Verification Result")

                verify_btn.click(
                    verify_signature,
                    inputs=[message_box, signature_output, public_key_box],
                    outputs=verify_output
                )

                ai_btn_signature = gr.Button("🧠 AI Explain Digital Signature")
                ai_signature = gr.Markdown()

                ai_btn_signature.click(
                    lambda x: explain_with_llm("signature_analyzer", x),
                    inputs=signature_output,
                    outputs=ai_signature
                )

            # ================= FIREWALL RULE SIMULATOR =================
            firewall_view = gr.Column(visible=False)
            with firewall_view:

                gr.Markdown("### 🔥 Firewall Rule Simulator — Enterprise Logic Engine")

                gr.Markdown("""
                            Simulates real firewall behavior:
                            
                            • Top-down rule evaluation
                            • First match wins
                            • CIDR-based IP matching
                            • Port ranges supported
                            • Protocol-aware filtering
                            • Default deny policy
                            """)
                
                # Rule Creation Section
                gr.Markdown("#### ➕ Add Rule")

                fw_action = gr.Dropdown(["ALLOW", "DENY"], label="Action")
                fw_cidr = gr.Textbox(label="Source CIDR (e.g., 192.168.1.0/24)")
                fw_port = gr.Textbox(label="Port (22 OR 20-25 OR *)")
                fw_protocol = gr.Dropdown(["TCP", "UDP", "ANY"], value="TCP", label="Protocol")

                add_rule_btn = gr.Button("Add Rule")
                clear_rules_btn = gr.Button("Clear All Rules")

                rule_status = gr.Textbox()

                add_rule_btn.click(
                    add_firewall_rule,
                    inputs=[fw_action, fw_cidr, fw_port, fw_protocol],
                    outputs=rule_status
                )

                clear_rules_btn.click(
                    clear_firewall_rules,
                    outputs=rule_status
                )

                gr.Markdown("---")

                # Packet Simulation Section
                gr.Markdown("#### 📦 Simulate Packet")

                test_ip = gr.Textbox(label="Source IP")
                test_port = gr.Textbox(label="Destination Port")
                test_protocol = gr.Dropdown(["TCP", "UDP"], value="TCP")

                simulate_btn = gr.Button("Evaluate Packet")

                fw_result = gr.Markdown()
                fw_trace = gr.Markdown()
                fw_stats = gr.Markdown()

                simulate_btn.click(
                    evaluate_packet,
                    inputs=[test_ip, test_port, test_protocol],
                    outputs=[fw_result, fw_trace]
                )

                simulate_btn.click(
                    get_firewall_stats,
                    outputs=fw_stats
                )

                ai_btn_firewall = gr.Button("🧠 AI Explain Firewall Decision")
                ai_firewall = gr.Markdown()

                ai_btn_firewall.click(
                    lambda x: explain_with_llm("firewall_analyzer", x),
                    inputs=fw_result,
                    outputs=ai_firewall
                )

            # ================= PASSWORD STORAGE DEMO =================
            password_storage_view = gr.Column(visible=False)
            with password_storage_view:

                gr.Markdown("### 🔒 Secure Password Storage Demonstration")

                gr.Markdown("""
                            This module demonstrates how modern systems securely store passwords
                            
                            • Plain storage
                            • Unsalted hashing
                            • Salted hashing
                            • Why rainbow tables fail
                            • Why salt must be stored
                            • Why double hashing is meaningless
                            """)
                
                input_password = gr.Textbox(
                    label="Enter Password",
                    placeholder="password123",
                    type="password"
                )

                run_demo_btn = gr.Button("Run Secure Storage Demo")

                plain_box = gr.Textbox(label="Plain Password (Never Store Like This)")
                unsalted_box = gr.Textbox(label="SHA256 (Unsalted)")
                salt_box = gr.Textbox(label="Random Salt (Hex)")
                salted_box = gr.Textbox(label="SHA256 (Salted)")
                storage_box = gr.Textbox(label="Database Storage Format (salt:hash)")

                explanation_box = gr.Markdown()

                run_demo_btn.click(
                    secure_password_demo,
                    inputs=input_password,
                    outputs=[
                        plain_box,
                        unsalted_box,
                        salt_box,
                        salted_box,
                        storage_box,
                        explanation_box
                    ]
                )

                ai_btn_password = gr.Button("🧠 AI Explain Password Storage")
                ai_password = gr.Markdown()

                ai_btn_password.click(
                    lambda x: explain_with_llm("password_storage_demo", x),
                    inputs=explanation_box,
                    outputs=ai_password
                )
                
        # ================= VIEW SWITCHING =================
        def switch(v):
            return [
                gr.update(visible=v=="dashboard"),
                gr.update(visible=v=="network"),
                gr.update(visible=v=="credential"),
                gr.update(visible=v=="integrity"),
                gr.update(visible=v=="threat"),
                gr.update(visible=v=="crypto"),
                gr.update(visible=v=="cvss"),
                gr.update(visible=v=="jwt"),
                gr.update(visible=v=="classical"),
                gr.update(visible=v=="subnet"),
                gr.update(visible=v=="http"),
                gr.update(visible=v=="metadata"),
                gr.update(visible=v=="xss"),
                gr.update(visible=v=="phishing"),
                gr.update(visible=v=="signature"),
                gr.update(visible=v=="firewall"),
                gr.update(visible=v=="password_storage"),
            ]

        buttons = [
            (dashboard_btn,"dashboard"),
            (network_btn,"network"),
            (credential_btn,"credential"),
            (integrity_btn,"integrity"),
            (threat_btn,"threat"),
            (crypto_btn,"crypto"),
            (cvss_btn,"cvss"),
            (jwt_btn,"jwt"),
            (classical_btn,"classical"),
            (subnet_btn,"subnet"),
            (http_btn,"http"),
            (metadata_btn,"metadata"),
            (xss_btn,"xss"),
            (url_detector_btn,"phishing"),
            (signature_btn,"signature"),
            (firewall_btn,"firewall"),
            (password_storage_btn,"password_storage")
        ]

        def make_switch(target):
            def handler():
                return switch(target)
            return handler

        for button,name in buttons:
            button.click(
                lambda n=name: switch(n),
                outputs=[
                    dashboard_view, network_view, credential_view,
                    integrity_view, threat_view, crypto_view,
                    cvss_view, jwt_view, classical_view, subnet_view, 
                    http_view, metadata_view, xss_view, phishing_view, 
                    signature_view, firewall_view, password_storage_view
                ]
            )
    
            

demo.launch(server_name="0.0.0.0", server_port=7860)