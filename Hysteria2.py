#!/usr/bin/env python3
"""
Version: v1.2.0

Description:
This script is designed to add and manage essential functionalities efficiently. 
It serves as a foundational tool that can be expanded and enhanced in future updates 
to meet evolving requirements.

Author: @xenonNet
Contact: t.me/Xenon

If you find this script useful, consider giving it a star on GitHub and supporting our work.
"""
import os, sys, subprocess, re, time
from datetime import datetime, timedelta
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except:
    print("cryptography not installed. pip3 install cryptography")
    sys.exit(1)
try:
    import yaml
except:
    print("PyYAML not installed. pip3 install pyyaml")
    sys.exit(1)

# ANSI color codes
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
ORANGE = "\033[38;5;208m"
LIGHTBLUE = "\033[96m"

# Default paths and variables
DEFAULT_LOCAL_COMPOSE = "/etc/opt/marzneshin/docker-compose.yml"
DEFAULT_REMOTE_COMPOSE = "/root/marznode/compose.yml"
DEFAULT_CERT_PATH = "/var/lib/marznode/certs"
DEFAULT_MARZNODE_DIR = "/var/lib/marznode"
DEFAULT_HYSTERIA_FILE = os.path.join(DEFAULT_MARZNODE_DIR, "hysteria.yaml")
ACME_HOME = os.path.expanduser("~/.acme.sh")
GEOFOLDER = os.path.join(DEFAULT_MARZNODE_DIR, "geofiles")

# Updated ACL lists (GeoIP and Geosite categories)
NEW_GEOIP = [
    "geoip:ir", "geoip:private", "geoip:arvancloud", "geoip:derakcloud", "geoip:iranserver",
    "geoip:parspack", "geoip:cloudflare", "geoip:google", "geoip:amazon", "geoip:microsoft",
    "geoip:bing", "geoip:github", "geoip:facebook", "geoip:twitter", "geoip:telegram",
    "geoip:oracle", "geoip:digitalocean", "geoip:linode", "geoip:openai", "geoip:phishing",
    "geoip:malware"
]
NEW_GEOSITE = [
    "geosite:ir", "geosite:ads", "geosite:category-ads-all", "geosite:malware",
    "geosite:phishing", "geosite:cryptominers", "geosite:social", "geosite:nsfw"
]

def run_quiet_command(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        print(RED+"Error while running: "+cmd+RESET)

def run_marzneshin_restart():
    print(GREEN+"Restart process started, please wait..." + RESET, flush=True)
    start_time = time.time()
    p = subprocess.Popen("marzneshin restart", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.stdout:
        while True:
            line = p.stdout.readline()
            if not line: break
            text = line.decode(errors="replace")
            if "Press CTRL+C to quit" in text or "Uvicorn running on" in text:
                p.terminate()
                break
    p.wait()
    elapsed = time.time() - start_time
    print(GREEN+"Restarting was successful, Redirecting to the main menu. Took {:.2f} seconds.".format(elapsed)+RESET)

def install_prerequisites():
    run_quiet_command("apt-get update -y")
    run_quiet_command("apt-get install -y curl socat nano")
    r = subprocess.run("docker compose version", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        run_quiet_command("apt-get install -y docker-compose-plugin")

def install_acme_sh():
    if not os.path.isdir(ACME_HOME):
        run_quiet_command("curl https://get.acme.sh | sh")
        run_quiet_command(ACME_HOME+"/acme.sh --set-default-ca --server letsencrypt")

def get_lets_encrypt_cert():
    install_prerequisites()
    install_acme_sh()
    domain = input(GREEN+"Enter your domain: "+RESET).strip()
    email = input(GREEN+"Enter your email for Let's Encrypt: "+RESET).strip()
    run_quiet_command(ACME_HOME+"/acme.sh --register-account -m "+email)
    run_quiet_command(ACME_HOME+"/acme.sh --issue -d "+domain+" --standalone")
    os.makedirs(DEFAULT_CERT_PATH, exist_ok=True)
    run_quiet_command(ACME_HOME+"/acme.sh --installcert -d "+domain+" --key-file "+DEFAULT_CERT_PATH+"/private.key --fullchain-file "+DEFAULT_CERT_PATH+"/cert.crt")
    print(GREEN+"SSL certificate issued."+RESET)
    print(YELLOW+"Paths:"+RESET)
    print("  private.key => "+DEFAULT_CERT_PATH+"/private.key")
    print("  cert.crt    => "+DEFAULT_CERT_PATH+"/cert.crt")

def generate_self_signed_cert():
    os.makedirs(DEFAULT_CERT_PATH, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Fake Cert Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, u"FakeSelfSigned")
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
           .public_key(private_key.public_key()).serial_number(x509.random_serial_number())\
           .not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow()+timedelta(days=3650))\
           .sign(private_key, hashes.SHA256())
    key_path = os.path.join(DEFAULT_CERT_PATH, "private.key")
    crt_path = os.path.join(DEFAULT_CERT_PATH, "cert.crt")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(GREEN+"Self-signed certificate generated."+RESET)
    print(YELLOW+"Files:"+RESET)
    print("  "+key_path)
    print("  "+crt_path)

def download_hysteria_config():
    os.makedirs(DEFAULT_MARZNODE_DIR, exist_ok=True)
    run_quiet_command("curl -L https://github.com/marzneshin/marznode/raw/master/hysteria.yaml -o "+DEFAULT_HYSTERIA_FILE)

def set_hysteria_tls_paths():
    if not os.path.exists(DEFAULT_CERT_PATH+"/cert.crt") or not os.path.exists(DEFAULT_CERT_PATH+"/private.key"):
        print(RED+"No SSL certificate found. Generate or obtain an SSL certificate first."+RESET)
        return False
    if not os.path.exists(DEFAULT_HYSTERIA_FILE):
        print(RED+"No hysteria.yaml found."+RESET)
        return False
    with open(DEFAULT_HYSTERIA_FILE, "r", encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
        except:
            print(RED+"Error parsing hysteria.yaml"+RESET)
            return False
    if not config: config = {}
    if "tls" not in config: config["tls"] = {}
    config["tls"]["cert"] = DEFAULT_CERT_PATH+"/cert.crt"
    config["tls"]["key"] = DEFAULT_CERT_PATH+"/private.key"
    with open(DEFAULT_HYSTERIA_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, sort_keys=False)
    return True

def enable_hysteria(compose_file):
    download_hysteria_config()
    if not set_hysteria_tls_paths():
        return
    if not os.path.exists(compose_file):
        print(RED+"Compose file not found."+RESET)
        return
    with open(compose_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    hysteria_envs = ['      HYSTERIA_EXECUTABLE_PATH: "/usr/local/bin/hysteria"\n',
                     '      HYSTERIA_CONFIG_PATH: "/var/lib/marznode/hysteria.yaml"\n',
                     '      HYSTERIA_ENABLED: "True"\n']
    new_lines = []
    in_env = False
    added = False
    for line in lines:
        new_lines.append(line)
        if re.search(r"^\s*environment\s*:", line):
            in_env = True
            continue
        if in_env:
            if re.search(r"^\s*(volumes|image|services|command|network_mode|restart)\s*:", line):
                if not any("HYSTERIA_ENABLED" in l for l in lines):
                    new_lines[-1:-1] = hysteria_envs
                    added = True
                in_env = False
                continue
    if not any("environment:" in l for l in lines):
        new_lines.append("    environment:\n")
        new_lines.extend(hysteria_envs)
        added = True
    elif in_env:
        if not any("HYSTERIA_ENABLED" in l for l in lines):
            new_lines.append("\n")
            new_lines.extend(hysteria_envs)
            added = True
    if added:
        with open(compose_file, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    run_quiet_command("docker compose -f " + compose_file + " down")
    run_quiet_command("docker compose -f " + compose_file + " up -d")
    run_marzneshin_restart()

def disable_hysteria(compose_file):
    if not os.path.exists(compose_file):
        print(RED+"Compose file not found."+RESET)
        return
    with open(compose_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        if "HYSTERIA_EXECUTABLE_PATH" in line: continue
        if "HYSTERIA_CONFIG_PATH" in line: continue
        if "HYSTERIA_ENABLED" in line: continue
        new_lines.append(line)
    with open(compose_file, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    run_quiet_command("docker compose -f " + compose_file + " down")
    run_quiet_command("docker compose -f " + compose_file + " up -d")
    run_marzneshin_restart()

def is_blocked(config, item):
    if "acl" in config and "inline" in config["acl"]:
        for rule in config["acl"]["inline"]:
            if rule.strip() == "reject(" + item + ")":
                return True
    return False

def toggle_block(config, item):
    if "acl" not in config:
        config["acl"] = {"inline": []}
    if "inline" not in config["acl"]:
        config["acl"]["inline"] = []
    rule = "reject(" + item + ")"
    if rule in config["acl"]["inline"]:
        config["acl"]["inline"].remove(rule)
        return False
    else:
        config["acl"]["inline"].append(rule)
        return True

def pad_ansi(text, width):
    raw = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)
    padding = width - len(raw)
    return text + " " * padding

def acl_combined_table_manage(config):
    max_rows = max(len(NEW_GEOSITE), len(NEW_GEOIP))
    while True:
        rows = []
        for i in range(max_rows):
            left = ""
            right = ""
            if i < len(NEW_GEOSITE):
                status = "Blocked" if is_blocked(config, NEW_GEOSITE[i]) else "Choose"
                left = f"{i+1}: {NEW_GEOSITE[i]} ({GREEN+'Choose'+RESET if status=='Choose' else RED+'Blocked'+RESET})"
            if i < len(NEW_GEOIP):
                status = "Blocked" if is_blocked(config, NEW_GEOIP[i]) else "Choose"
                right = f"{i+1}: {NEW_GEOIP[i]} ({GREEN+'Choose'+RESET if status=='Choose' else RED+'Blocked'+RESET})"
            rows.append((left, right))
        def strip_ansi(s):
            return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s)
        col1_width = max((len(strip_ansi(r[0])) for r in rows), default=10)
        col2_width = max((len(strip_ansi(r[1])) for r in rows), default=10)
        top = "┌" + "─"*(col1_width+2) + "┬" + "─"*(col2_width+2) + "┐"
        header = "│ " + "Geosite".ljust(col1_width+2) + "│ " + "GeoIP".ljust(col2_width+2) + "│"
        sep = "├" + "─"*(col1_width+2) + "┼" + "─"*(col2_width+2) + "┤"
        bottom = "└" + "─"*(col1_width+2) + "┴" + "─"*(col2_width+2) + "┘"
        print(top)
        print(header)
        print(sep)
        for left, right in rows:
            print("│ " + pad_ansi(left, col1_width+2) + "│ " + pad_ansi(right, col2_width+2) + "│")
        print(bottom)
        user_input = input(MAGENTA+"Enter toggles (e.g. 1,2) or 0 for back: "+RESET).strip()
        if user_input == "0":
            break
        tokens = [x.strip() for x in user_input.split(",") if x.strip()]
        for token in tokens:
            try:
                num = int(token)
                if num <= len(NEW_GEOSITE):
                    new_status = toggle_block(config, NEW_GEOSITE[num-1])
                    status_str = "Blocked" if new_status else "Choose"
                    print((RED if new_status else GREEN) + f"{NEW_GEOSITE[num-1]} is now {status_str}." + RESET)
                elif num <= len(NEW_GEOIP):
                    new_status = toggle_block(config, NEW_GEOIP[num-1])
                    status_str = "Blocked" if new_status else "Choose"
                    print((RED if new_status else GREEN) + f"{NEW_GEOIP[num-1]} is now {status_str}." + RESET)
                else:
                    print(RED+"Invalid number: "+token+RESET)
            except:
                print(RED+"Invalid token: "+token+RESET)
    if "acl" in config:
        config["acl"]["geoip"] = os.path.join(GEOFOLDER, "geoip.dat")
        config["acl"]["geosite"] = os.path.join(GEOFOLDER, "geosite.dat")

def manage_acl(config):
    acl_combined_table_manage(config)

def dns_menu(config):
    while True:
        print("\n"+GREEN+"[0]"+RESET+" Back")
        print(GREEN+"[1]"+RESET+" google -> 8.8.8.8:53")
        print(GREEN+"[2]"+RESET+" adguard -> 94.140.14.14:53")
        print(GREEN+"[3]"+RESET+" cloudflare_simple -> 1.1.1.1:53")
        print(GREEN+"[4]"+RESET+" cloudflare_family_block_malware -> 1.1.1.2:53")
        print(GREEN+"[5]"+RESET+" cloudflare_family_block_malware_and_adult -> 1.1.1.3:53")
        print(GREEN+"[6]"+RESET+" Delete DNS resolver rule")
        sel = input(MAGENTA+"Select: "+RESET).strip()
        if sel == "0":
            break
        elif sel == "1":
            addr = "8.8.8.8:53"
        elif sel == "2":
            addr = "94.140.14.14:53"
        elif sel == "3":
            addr = "1.1.1.1:53"
        elif sel == "4":
            addr = "1.1.1.2:53"
        elif sel == "5":
            addr = "1.1.1.3:53"
        elif sel == "6":
            if "resolver" in config: del config["resolver"]
            print(GREEN+"DNS resolver rule deleted."+RESET)
            break
        else:
            print(RED+"Invalid selection."+RESET)
            continue
        to = input(GREEN+"Enter DNS timeout in seconds (e.g. 4): "+RESET).strip()
        if not to.isdigit(): to = "4"
        config["resolver"] = {"type": "udp", "udp": {"addr": addr, "timeout": to+"s"}}
        print(GREEN+"DNS resolver updated."+RESET)
        break

def show_config_table(config):
    rows = [
        ("Listening Port", config.get("listen", "Not Set")),
        ("sniGuard", config.get("tls", {}).get("sniGuard", "dns-san")),
        ("Obfuscation", "ENABLED" if "obfs" in config else "DISABLED"),
        ("Bandwidth (up/down)", (config.get("bandwidth", {}).get("up", "Not Set") + " / " + config.get("bandwidth", {}).get("down", "Not Set")) if "bandwidth" in config else "Not Set"),
        ("Ignore Client Bandwidth", "True" if config.get("ignoreClientBandwidth", False) else "False"),
        ("DNS Resolver", config.get("resolver", {}).get("udp", {}).get("addr", "Not Set") if "resolver" in config else "Not Set")
    ]
    colored_rows = []
    for param, val in rows:
        if val == "Not Set":
            colored_val = ORANGE + val + RESET
        elif param == "sniGuard" and val.lower() == "disable":
            colored_val = ORANGE + val + RESET
        elif param == "Obfuscation":
            colored_val = GREEN + val + RESET if val == "ENABLED" else RED + val + RESET
        elif param == "Ignore Client Bandwidth":
            colored_val = GREEN + "True" + RESET if val == "True" else RED + "False" + RESET
        elif param == "DNS Resolver" and val != "Not Set":
            colored_val = LIGHTBLUE + val + RESET
        else:
            colored_val = val
        colored_rows.append((param, colored_val))
    left_width = max(len(param) for param, _ in colored_rows)
    right_width = max(len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', val)) for _, val in colored_rows)
    left_width = max(left_width, len("Parameter"))
    right_width = max(right_width, len("Value"))
    left_width += 2
    right_width += 2
    top = "┌" + "─"*(left_width+2) + "┬" + "─"*(right_width+2) + "┐"
    header = "│ " + "Parameter".ljust(left_width) + " │ " + "Value".ljust(right_width) + " │"
    sep = "├" + "─"*(left_width+2) + "┼" + "─"*(right_width+2) + "┤"
    bottom = "└" + "─"*(left_width+2) + "┴" + "─"*(right_width+2) + "┘"
    print(top)
    print(header)
    print(sep)
    for param, val in colored_rows:
        print("│ " + pad_ansi(param, left_width) + " │ " + pad_ansi(val, right_width) + " │")
    print(bottom)

def manage_hysteria2_config():
    if not os.path.exists(DEFAULT_HYSTERIA_FILE):
        print(RED+"No hysteria.yaml found. Enable Hysteria first."+RESET)
        return
    with open(DEFAULT_HYSTERIA_FILE, "r", encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
        except:
            print(RED+"Error parsing hysteria.yaml"+RESET)
            return
    if not config: config = {}
    if "listen" not in config: config["listen"] = ":4443"
    if "tls" not in config: config["tls"] = {}
    while True:
        print("\n" + BLUE + "Manage Hysteria2 Configuration" + RESET)
        print(GREEN + "Default Parameters:" + RESET)
        show_config_table(config)
        print(GREEN + "[1]" + RESET + " Change listening port")
        print(GREEN + "[2]" + RESET + " Change sniGuard")
        print("————————————————————————————————————————————")
        print(GREEN + "[3]" + RESET + " Disable/Enable obfuscation")
        print("————————————————————————————————————————————")
        print(GREEN + "[4]" + RESET + " Set Bandwidth limit")
        print(GREEN + "[5]" + RESET + " Toggle ignoreClientBandwidth")
        print(YELLOW + "- Note: You can only use one option at a time." + RESET)
        print("————————————————————————————————————————————")
        print(GREEN + "[6]" + RESET + " DNS Resolver options")
        print(GREEN + "[7]" + RESET + " Apply changes & Reload Marzneshin")
        print(GREEN + "[8]" + RESET + " Manage ACL / Block Traffic")
        print(GREEN + "[9]" + RESET + " Return to main menu")
        choice = input(MAGENTA + "Select: " + RESET).strip()
        if choice == "1":
            p = input(GREEN + "Enter new listening port (e.g. 4443): " + RESET).strip()
            if p.isdigit(): config["listen"] = ":" + p
        elif choice == "2":
            print(GREEN + "1) strict" + RESET)
            print(GREEN + "2) disable" + RESET)
            print(GREEN + "3) dns-san" + RESET)
            c = input(GREEN + "Select sniGuard: " + RESET).strip()
            if c == "1":
                config["tls"]["sniGuard"] = "strict"
            elif c == "2":
                config["tls"]["sniGuard"] = "disable"
            else:
                config["tls"]["sniGuard"] = "dns-san"
        elif choice == "3":
            if "obfs" in config:
                del config["obfs"]
                print(GREEN + "Obfuscation disabled." + RESET)
            else:
                pw = input(GREEN + "Enter obfuscation password: " + RESET).strip()
                if pw:
                    config["obfs"] = {"type": "salamander", "salamander": {"password": pw}}
                    print(GREEN + "Obfuscation enabled." + RESET)
        elif choice == "4":
            if "bandwidth" in config:
                del config["bandwidth"]
                print(GREEN + "Bandwidth limit removed." + RESET)
            else:
                up = input(GREEN + "Set upload limit (e.g. 1 gbps, 500 kbps): " + RESET).strip()
                down = input(GREEN + "Set download limit: " + RESET).strip()
                if up and down:
                    config["bandwidth"] = {"up": up, "down": down}
                    config["ignoreClientBandwidth"] = False
                    print(GREEN + "Bandwidth limit set." + RESET)
        elif choice == "5":
            v = not config.get("ignoreClientBandwidth", False)
            if v and "bandwidth" in config:
                del config["bandwidth"]
            config["ignoreClientBandwidth"] = v
            print(GREEN + "ignoreClientBandwidth toggled." + RESET)
        elif choice == "6":
            dns_menu(config)
        elif choice == "7":
            with open(DEFAULT_HYSTERIA_FILE, "w", encoding="utf-8") as fw:
                yaml.dump(config, fw, sort_keys=False)
            c = choose_compose_path()
            if os.path.exists(c):
                run_quiet_command("docker compose -f " + c + " down")
                run_quiet_command("docker compose -f " + c + " up -d")
                run_marzneshin_restart()
                print(GREEN + "All changes applied." + RESET)
            else:
                print(RED + "Compose file not found." + RESET)
        elif choice == "8":
            manage_acl(config)
        elif choice == "9":
            break
        else:
            print(RED + "Invalid selection." + RESET)

def choose_compose_path():
    print("\n" + BLUE + "Which Docker Compose file?" + RESET)
    print(GREEN + "[1]" + RESET + " Local node: " + DEFAULT_LOCAL_COMPOSE)
    print(GREEN + "[2]" + RESET + " Remote node: " + DEFAULT_REMOTE_COMPOSE)
    print(GREEN + "[3]" + RESET + " Custom path")
    c = input(MAGENTA + "Select: " + RESET).strip()
    if c == "1":
        return DEFAULT_LOCAL_COMPOSE
    if c == "2":
        return DEFAULT_REMOTE_COMPOSE
    if c == "3":
        return input(GREEN + "Enter path: " + RESET).strip()
    return DEFAULT_LOCAL_COMPOSE

def restart_marzneshin():
    run_marzneshin_restart()

def main_menu():
    while True:
        print("\n" + BLUE + "Marzneshin/Marznode - Hysteria2 Manager" + RESET)
        print("————————————————————————————————————————————")
        print(GREEN + " by @XenonNet" + RESET)
        print("————————————————————————————————————————————")
        print(GREEN + " 0" + RESET + ". Exit")
        print("————————————————————————————————————————————")
        print(GREEN + " 1" + RESET + ". Generate Self-Signed SSL")
        print(GREEN + " 2" + RESET + ". Obtain Let's Encrypt SSL")
        print("————————————————————————————————————————————")
        print(GREEN + " 3" + RESET + ". Enable Hysteria2")
        print(GREEN + " 4" + RESET + ". Disable Hysteria2")
        print("————————————————————————————————————————————")
        print(GREEN + " 5" + RESET + ". Manage Hysteria2 Config")
        print(GREEN + " 6" + RESET + ". Restart Marzneshin")
        print("————————————————————————————————————————————")
        c = input(MAGENTA + "Select: " + RESET).strip()
        if c == "0":
            sys.exit(0)
        elif c == "1":
            generate_self_signed_cert()
        elif c == "2":
            get_lets_encrypt_cert()
        elif c == "3":
            f = choose_compose_path()
            enable_hysteria(f)
        elif c == "4":
            f = choose_compose_path()
            disable_hysteria(f)
        elif c == "5":
            manage_hysteria2_config()
        elif c == "6":
            restart_marzneshin()
        else:
            print(RED + "Invalid selection." + RESET)

if __name__=="__main__":
    main_menu()
