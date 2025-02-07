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
import os, sys, subprocess, re, time, json
from datetime import datetime, timedelta
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception as e:
    print("cryptography not installed. pip3 install cryptography")
    sys.exit(1)
try:
    import yaml
except Exception as e:
    print("PyYAML not installed. pip3 install pyyaml")
    sys.exit(1)

# ANSI color codes
RESET    = "\033[0m"
RED      = "\033[91m"
GREEN    = "\033[92m"
YELLOW   = "\033[93m"
BLUE     = "\033[94m"
MAGENTA  = "\033[95m"
CYAN     = "\033[36m"  # For extra info (e.g., URL)
ORANGE   = "\033[38;5;208m"
LIGHTBLUE= "\033[96m"

# Default paths and variables
DEFAULT_LOCAL_COMPOSE   = "/etc/opt/marzneshin/docker-compose.yml"
DEFAULT_REMOTE_COMPOSE  = "/root/marznode/compose.yml"
DEFAULT_CERT_PATH       = "/var/lib/marznode/certs"
DEFAULT_MARZNODE_DIR    = "/var/lib/marznode"
DEFAULT_HYSTERIA_FILE   = os.path.join(DEFAULT_MARZNODE_DIR, "hysteria.yaml")
ACME_HOME               = os.path.expanduser("~/.acme.sh")
GEOFOLDER               = os.path.join(DEFAULT_MARZNODE_DIR, "geofiles")

# Port hopping configuration
NFTABLES_TABLE          = "hysteria_porthopping"
PORT_HOP_CONFIG         = os.path.join(DEFAULT_MARZNODE_DIR, "hysteria_porthopping.json")

# Outbounds configuration – all settings will be merged directly into hysteria.yaml
DEFAULT_OUTBOUNDS_CONFIG = os.path.join(DEFAULT_MARZNODE_DIR, "outbounds.yaml")

# Updated ACL lists for inline management (for simple toggling)
NEW_GEOIP   = [
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

### Utility Function ###
def pad_ansi(text, width):
    raw = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)
    padding = width - len(raw)
    return text + " " * padding

### General Functions ###
def run_quiet_command(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(RED+"Error while running: "+cmd+RESET)

def run_marzneshin_restart():
    print(GREEN+"Restart process started, please wait..." + RESET, flush=True)
    start_time = time.time()
    p = subprocess.Popen("marzneshin restart", shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
    r = subprocess.run("docker compose version", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    email  = input(GREEN+"Enter your email for Let's Encrypt: "+RESET).strip()
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
    run_quiet_command("curl -L https://github.com/Marzneshin/marznode/raw/master/hysteria.yaml -o "+DEFAULT_HYSTERIA_FILE)

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
    config["tls"]["key"]  = DEFAULT_CERT_PATH+"/private.key"
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

### ACL Management (Inline) ###
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

### Combined ACL Table Manager (Inline) ###
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
    if not os.path.exists(GEOFOLDER):
        print(YELLOW+"Geofiles folder not found at " + GEOFOLDER + RESET)
        choice = input(GREEN+"Do you want to download geoip.dat and geosite.dat now? (y/n): " + RESET).strip().lower()
        if choice == "y":
            os.makedirs(GEOFOLDER, exist_ok=True)
            run_quiet_command("wget https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geoip.dat -O " + os.path.join(GEOFOLDER, "geoip.dat"))
            run_quiet_command("wget https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geosite.dat -O " + os.path.join(GEOFOLDER, "geosite.dat"))
            print(GREEN+"Geo files downloaded." + RESET)
        else:
            print(RED+"Geo files are required for ACL management. Returning." + RESET)
            return
    acl_combined_table_manage(config)

### Port Hopping Manager ###
def ensure_nft_table():
    try:
        subprocess.check_output(f"nft list table inet {NFTABLES_TABLE}", shell=True, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        run_quiet_command(f"nft add table inet {NFTABLES_TABLE}")
    try:
        subprocess.check_output(f"nft list chain inet {NFTABLES_TABLE} prerouting", shell=True, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        run_quiet_command(f"nft add chain inet {NFTABLES_TABLE} prerouting '{{ type nat hook prerouting priority 0 ; }}'")

def get_nft_rules():
    ensure_nft_table()
    try:
        output = subprocess.check_output(f"nft list table inet {NFTABLES_TABLE}", shell=True, text=True, stderr=subprocess.DEVNULL)
        return output.strip()
    except subprocess.CalledProcessError:
        return ""

def list_port_hopping_rules():
    rules = get_nft_rules()
    if not rules:
        print("\n🔍 No port hopping rules set.")
    else:
        lines = rules.split("\n")
        data = []
        for line in lines:
            if "dport" in line and "redirect to" in line:
                parts = line.split()
                try:
                    port_range = parts[parts.index("dport") + 1]
                    redirect_port = parts[parts.index("to") + 1]
                    data.append([port_range, redirect_port])
                except:
                    continue
        if data:
            print("\nCurrent Port Hopping Rules:")
            print("┌" + "─"*20 + "┬" + "─"*20 + "┐")
            print("│ " + "Port Range".ljust(18) + "│ " + "Redirect Port".ljust(18) + "│")
            print("├" + "─"*20 + "┼" + "─"*20 + "┤")
            for pr, rp in data:
                print("│ " + pr.ljust(18) + "│ " + rp.ljust(18) + "│")
            print("└" + "─"*20 + "┴" + "─"*20 + "┘")
        else:
            print("\n🔍 No port hopping rules set.")

def add_port_range(port_range, hysteria_port):
    ensure_nft_table()
    rule = f"nft add rule inet {NFTABLES_TABLE} prerouting iifname eth0 udp dport {port_range} counter redirect to :{hysteria_port}"
    os.system(rule)
    print(f"✅ Added port range {port_range} -> {hysteria_port}")

def remove_port_range():
    rules = get_nft_rules()
    if not rules:
        print("\n🔍 No port hopping rules set.")
        return
    list_port_hopping_rules()
    port_range = input("\nEnter the port range to delete (e.g., 20000-50000, or 0 to cancel): ").strip()
    if port_range == "0":
        print("Cancelled deletion.")
        return
    rule = f"nft delete rule inet {NFTABLES_TABLE} prerouting iifname eth0 udp dport {port_range}"
    os.system(rule)
    print(f"❌ Removed port range {port_range}")

def reset_port_hopping_rules():
    os.system(f"nft flush table inet {NFTABLES_TABLE}")
    print("🗑 All port hopping rules have been reset.")

def load_port_hop_config():
    if os.path.exists(PORT_HOP_CONFIG):
        try:
            with open(PORT_HOP_CONFIG, "r") as f:
                return json.load(f)
        except Exception as e:
            print(RED+"Error loading port hopping config: "+str(e)+RESET)
            return {}
    else:
        return {}

def save_port_hop_config(config):
    try:
        with open(PORT_HOP_CONFIG, "w") as f:
            json.dump(config, f, indent=4)
        print(GREEN+"Configuration updated successfully." + RESET)
    except Exception as e:
        print(RED+"Error saving config: "+str(e)+RESET)

def set_hop_interval(interval):
    if interval < 5:
        print("⚠️ hopInterval cannot be less than 5 seconds. Setting to 5s.")
        interval = 5
    config = load_port_hop_config()
    config["hopInterval"] = f"{interval}s"
    save_port_hop_config(config)

def show_current_port_hopping_settings():
    print("\n=== Current Port Hopping Settings ===")
    rules = get_nft_rules()
    if rules and "redirect to" in rules:
        ph_status = GREEN + "Enabled" + RESET
    else:
        ph_status = RED + "Disabled" + RESET
    list_port_hopping_rules()
    config = load_port_hop_config()
    hop_interval = config.get("hopInterval", "Not Set")
    print(f"\nPort Hopping: {ph_status}")
    print(f"Hop Interval: {BLUE}{hop_interval}{RESET}")

def port_hopping_manager():
    show_current_port_hopping_settings()
    while True:
        print("\n=== Hysteria 2 Port Hopping Manager ===")
        print(GREEN + "[1]" + RESET + " Add Port Range")
        print(GREEN + "[2]" + RESET + " Remove Port Range")
        print(GREEN + "[3]" + RESET + " Reset All Port Hopping Rules")
        print(GREEN + "[4]" + RESET + " Set Hop Interval")
        print(GREEN + "[5]" + RESET + " Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            port_range = input("Enter port range (e.g., 20000-50000, or 0 to cancel): ").strip()
            if port_range == "0":
                print("Cancelled adding port range.")
                continue
            main_port = None
            if os.path.exists(DEFAULT_HYSTERIA_FILE):
                try:
                    with open(DEFAULT_HYSTERIA_FILE, "r") as f:
                        conf = yaml.safe_load(f)
                    if conf and "listen" in conf:
                        main_port = conf["listen"].lstrip(":")
                except Exception as e:
                    print(RED+"Error loading Hysteria config: "+str(e)+RESET)
            if not main_port:
                main_port = "443"
                print(YELLOW+"Hysteria main port not found in config. Defaulting to 443." + RESET)
            add_port_range(port_range, main_port)
        elif choice == "2":
            remove_port_range()
        elif choice == "3":
            reset_port_hopping_rules()
        elif choice == "4":
            try:
                interval = int(input("Enter hop interval in seconds (min 5s, or 0 to cancel): ").strip())
                if interval == 0:
                    print("Cancelled setting hop interval.")
                    continue
                set_hop_interval(interval)
            except:
                print(RED+"Invalid interval."+RESET)
        elif choice == "5":
            break
        else:
            print(RED+"Invalid choice. Try again."+RESET)

### Outbounds and ACL Management ###
def load_outbounds_config(path=DEFAULT_OUTBOUNDS_CONFIG):
    if not os.path.exists(path):
        config = {"outbounds": [], "acl": {"inline": []}}
        save_outbounds_config(config, path)
        return config
    with open(path, "r") as f:
        try:
            config = yaml.safe_load(f)
            if config is None:
                config = {"outbounds": [], "acl": {"inline": []}}
            if "outbounds" not in config:
                config["outbounds"] = []
            if "acl" not in config or "inline" not in config["acl"]:
                config["acl"] = {"inline": []}
            return config
        except Exception as e:
            print("Error loading config:", e)
            sys.exit(1)

def save_outbounds_config(config, path=DEFAULT_OUTBOUNDS_CONFIG):
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    print(GREEN+"Configuration saved to", path, RESET)

def print_outbounds_table(config):
    outbounds = config.get("outbounds", [])
    acl_rules = config.get("acl", {}).get("inline", [])
    # Use regex to count ACL occurrences for each outbound name.
    def outbound_used(name):
        count = 0
        pattern = re.compile(r'^\s*' + re.escape(name) + r'\s*\(', re.IGNORECASE)
        for rule in acl_rules:
            if pattern.match(rule):
                count += 1
        return f"Yes ({count} ACL)" if count > 0 else "not"
    idx_width    = 4
    name_width   = 20
    type_width   = 12
    values_width = 40
    acl_width    = 14
    total_width = idx_width + name_width + type_width + values_width + acl_width + 6
    border = "+" + "-"*(total_width-2) + "+"
    print("\n" + border)
    header = f"|{'Idx'.center(idx_width)}|{'Outbound Name'.center(name_width)}|{'Type'.center(type_width)}|{'Values'.center(values_width)}|{'ACL'.center(acl_width)}|"
    print(header)
    print(border)
    if not outbounds:
        empty_row = f"|{'':^{idx_width}}|{'No outbounds configured'.center(name_width+type_width+values_width+acl_width+4)}|"
        print(empty_row)
    else:
        for idx, ob in enumerate(outbounds):
            ob_name = ob.get("name", "Unnamed")
            ob_type = ob.get("type", "unknown")
            values_str = ""
            if ob_type.lower() == "socks5":
                socks = ob.get("socks5", {})
                addr = socks.get("addr", "")
                username = socks.get("username", "")
                password = socks.get("password", "")
                if ":" in addr:
                    ip, port = addr.split(":", 1)
                    addr_str = f"{GREEN}{ip}{RESET}:{BLUE}{port}{RESET}"
                else:
                    addr_str = f"{GREEN}{addr}{RESET}"
                creds = ""
                if username or password:
                    creds = f" | {MAGENTA}{username}:{password}{RESET}"
                values_str = f"{addr_str}{creds}"
            elif ob_type.lower() == "http":
                http = ob.get("http", {})
                url = http.get("url", "")
                values_str = f"URL: {CYAN}{url}{RESET}"
            elif ob_type.lower() == "direct":
                values_str = "No extra settings"
            else:
                values_str = str(ob)
            acl_used_val = outbound_used(ob_name)
            row = f"|{str(idx).center(idx_width)}|{ob_name.center(name_width)}|{(ORANGE+ob_type+RESET).center(type_width)}|{values_str.center(values_width)}|{acl_used_val.center(acl_width)}|"
            print(row)
    print(border)

def add_outbound(config):
    print("\nAdding a new outbound. (Enter 0 at any prompt to cancel.)")
    ob_type = input("Enter outbound type (direct, socks5, http): ").strip().lower()
    if ob_type == "0":
        print("Cancelled adding outbound.")
        return
    name = input("Enter a name for this outbound: ").strip()
    if name == "0":
        print("Cancelled adding outbound.")
        return
    new_ob = {"name": name, "type": ob_type}
    if ob_type == "socks5":
        addr = input("Enter SOCKS5 address (IP:port): ").strip()
        if addr == "0":
            print("Cancelled adding outbound.")
            return
        username = input("Enter username (leave blank if none, 0 to cancel): ").strip()
        if username == "0":
            print("Cancelled adding outbound.")
            return
        password = input("Enter password (leave blank if none, 0 to cancel): ").strip()
        if password == "0":
            print("Cancelled adding outbound.")
            return
        new_ob["socks5"] = {"addr": addr, "username": username, "password": password}
    elif ob_type == "http":
        url = input("Enter HTTP proxy URL (e.g., http://username:password@host:port): ").strip()
        if url == "0":
            print("Cancelled adding outbound.")
            return
        insecure_input = input("Is it insecure? (yes/no, 0 to cancel): ").strip().lower()
        if insecure_input == "0":
            print("Cancelled adding outbound.")
            return
        insecure = insecure_input == "yes"
        new_ob["http"] = {"url": url, "insecure": insecure}
    elif ob_type == "direct":
        pass
    else:
        print("Unsupported outbound type.")
        return
    config.setdefault("outbounds", []).append(new_ob)
    print("Outbound added.")

def delete_outbound(config):
    outbounds = config.get("outbounds", [])
    if not outbounds:
        print("No outbounds to delete.")
        return
    print_outbounds_table(config)
    inp = input("Enter the index of the outbound to delete (or 0 to cancel): ").strip()
    if inp == "0":
        print("Cancelled deletion.")
        return
    try:
        idx = int(inp)
        if 0 <= idx < len(outbounds):
            deleted = outbounds.pop(idx)
            print(f"Deleted outbound: {deleted.get('name', 'Unnamed')}")
        else:
            print("Invalid index.")
    except Exception as e:
        print("Error:", e)

def set_acl_rule(config):
    print("\n\033[96mSetting ACL rule(s).\033[0m")
    print("\033[97mYou can enter multiple rules separated by commas.\033[0m")
    print("\033[97mExamples:\033[0m")
    print("  \033[92mgermany\033[0m(\033[94mgeosite:ir\033[0m)")
    print("  \033[92mgermany\033[0m(\033[94mgeoip:ir\033[0m)")
    print("  \033[92mdirect\033[0m(\033[94mgeosite:google\033[0m)")
    print("  \033[91mreject\033[0m(\033[94mgeosite:facebook\033[0m)")
    print("  \033[91mreject\033[0m(\033[94mgeosite:google@ads\033[0m)")
    print("  \033[91mreject\033[0m(\033[93mall\033[0m, \033[95mudp/443\033[0m)")
    print("  \033[92mdirect\033[0m(\033[93mall\033[0m, \033[95mtcp/80\033[0m)")
    print("  \033[92mgermany\033[0m(\033[93mall\033[0m, \033[95mudp/53\033[0m)")
    print("  \033[92mwarp\033[0m(\033[94mgeosite:openai\033[0m),\033[92mNetherlands\033[0m(\033[94mgeosite:ir\033[0m)")

    rules_input = input("Enter rule pattern(s): - For back to the previous, please enter 0. ").strip()
    if rules_input == "0":
        print("Cancelled setting ACL rule(s).")
        return
    rules = [r.strip() for r in rules_input.split(",") if r.strip()]
    config.setdefault("acl", {}).setdefault("inline", []).extend(rules)
    print("ACL rule(s) added.")

def reset_all_acl(config):
    confirm = input("Are you sure you want to reset all ACL rules? (yes/no, 0 to cancel): ").strip().lower()
    if confirm == "0" or confirm != "yes":
        print("Reset cancelled.")
        return
    config.setdefault("acl", {})["inline"] = []
    print("All ACL rules have been reset.")

def reset_all_outbounds(config):
    confirm = input("Are you sure you want to reset all outbounds? (yes/no, 0 to cancel): ").strip().lower()
    if confirm == "0" or confirm != "yes":
        print("Reset cancelled.")
        return
    config["outbounds"] = []
    print("All outbounds have been reset.")

def reset_all_outbounds_and_acl(config):
    confirm = input("Are you sure you want to reset all ACL rules and outbounds? (yes/no, 0 to cancel): ").strip().lower()
    if confirm == "0" or confirm != "yes":
        print("Reset cancelled.")
        return
    config["outbounds"] = []
    config.setdefault("acl", {})["inline"] = []
    print("All ACL rules and outbounds have been reset.")

def apply_outbounds_to_hysteria():
    if not os.path.exists(DEFAULT_HYSTERIA_FILE):
        print(RED+"Hysteria config file not found."+RESET)
        return
    try:
        with open(DEFAULT_HYSTERIA_FILE, "r", encoding="utf-8") as f:
            hysteria_config = yaml.safe_load(f)
    except Exception as e:
        print(RED+"Error loading Hysteria config: "+str(e)+RESET)
        return
    if not hysteria_config:
        hysteria_config = {}
    out_config = load_outbounds_config()
    # Merge outbounds:
    outbounds = out_config.get("outbounds", [])
    if not any(ob.get("type", "").lower() == "direct" for ob in outbounds):
        outbounds.append({"name": "direct", "type": "direct"})
    else:
        non_direct = [ob for ob in outbounds if ob.get("type", "").lower() != "direct"]
        directs = [ob for ob in outbounds if ob.get("type", "").lower() == "direct"]
        outbounds = non_direct + directs
    hysteria_config["outbounds"] = outbounds

    # Merge ACL:
    acl_inline = out_config.get("acl", {}).get("inline", [])
    if not acl_inline or acl_inline[-1] != "direct(all)":
        acl_inline.append("direct(all)")
    new_acl = {
        "inline": acl_inline,
        "geoip": os.path.join(GEOFOLDER, "geoip.dat"),
        "geosite": os.path.join(GEOFOLDER, "geosite.dat")
    }
    hysteria_config["acl"] = new_acl

    # Add geofiles section.
    hysteria_config["geofiles"] = {
        "geoip": os.path.join(GEOFOLDER, "geoip.dat"),
        "geosite": os.path.join(GEOFOLDER, "geosite.dat")
    }
    try:
        with open(DEFAULT_HYSTERIA_FILE, "w", encoding="utf-8") as f:
            yaml.dump(hysteria_config, f, sort_keys=False)
        print(GREEN+"Outbounds and ACL rules applied to Hysteria config." + RESET)
    except Exception as e:
        print(RED+"Error saving Hysteria config: "+str(e)+RESET)

def manage_outbounds_config():
    config = load_outbounds_config()
    print_outbounds_table(config)
    while True:
        print(GREEN+"[0]"+RESET+" Return to previous menu")
        print(GREEN+"[1]"+RESET+" Add outbound")
        print(GREEN+"[2]"+RESET+" Delete outbound")
        print(GREEN+"[3]"+RESET+" Set ACL rule")
        print(GREEN+"[4]"+RESET+" Reset all ACL rules")
        print(GREEN+"[5]"+RESET+" Reset all outbounds")
        print(GREEN+"[6]"+RESET+" Reset all ACL rules and outbounds")
        print(GREEN+"[7]"+RESET+" Save and Apply (merge to Hysteria config) & Exit")
        choice = input("Select an option (0-7): ").strip()
        if choice == "0":
            break
        elif choice == "1":
            add_outbound(config)
        elif choice == "2":
            delete_outbound(config)
        elif choice == "3":
            set_acl_rule(config)
        elif choice == "4":
            reset_all_acl(config)
        elif choice == "5":
            reset_all_outbounds(config)
        elif choice == "6":
            reset_all_outbounds_and_acl(config)
        elif choice == "7":
            save_outbounds_config(config)
            apply_outbounds_to_hysteria()
            break
        else:
            print("Invalid choice, please try again.")
        print_outbounds_table(config)

### Hysteria2 Management Menu ###
def show_config_table_main(config):
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
            colored_val = GREEN + val + RESET if val=="ENABLED" else RED + val + RESET
        elif param == "Ignore Client Bandwidth":
            colored_val = GREEN + "True" + RESET if val=="True" else RED + "False" + RESET
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
        show_config_table_main(config)
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
        print(GREEN + "[9]" + RESET + " Port Hopping Manager")
        print(GREEN + "[10]" + RESET + " Manage Outbounds and ACL Rules")
        print(GREEN + "[11]" + RESET + " Return to main menu")
        choice = input(MAGENTA + "Select: " + RESET).strip()
        if choice == "1":
            p = input(GREEN + "Enter new listening port (e.g. 4443, or 0 to cancel): " + RESET).strip()
            if p == "0":
                continue
            if p.isdigit():
                config["listen"] = ":" + p
        elif choice == "2":
            print(GREEN + "1) strict" + RESET)
            print(GREEN + "2) disable" + RESET)
            print(GREEN + "3) dns-san" + RESET)
            c = input(GREEN + "Select sniGuard (or 0 to cancel): " + RESET).strip()
            if c == "0":
                continue
            if c == "1":
                config["tls"]["sniGuard"] = "strict"
            elif c == "2":
                config["tls"]["sniGuard"] = "disable"
            else:
                config["tls"]["sniGuard"] = "dns-san"
        elif choice == "3":
            print(GREEN + "[1] Enable obfuscation" + RESET)
            print(GREEN + "[2] Disable obfuscation" + RESET)
            sub = input(MAGENTA + "Select (or 0 to cancel): " + RESET).strip()
            if sub == "0":
                continue
            if sub == "1":
                pw = input(GREEN + "Enter obfuscation password (or 0 to cancel): " + RESET).strip()
                if pw == "0":
                    continue
                if pw:
                    config["obfs"] = {"type": "salamander", "salamander": {"password": pw}}
                    print(GREEN + "Obfuscation enabled with password set." + RESET)
                else:
                    print(RED + "No password provided. Obfuscation not enabled." + RESET)
            elif sub == "2":
                if "obfs" in config:
                    del config["obfs"]
                    print(GREEN + "Obfuscation disabled." + RESET)
                else:
                    print(YELLOW + "Obfuscation is already disabled." + RESET)
            else:
                print(RED + "Invalid selection." + RESET)
        elif choice == "4":
            if "bandwidth" in config:
                del config["bandwidth"]
                print(GREEN + "Bandwidth limit removed." + RESET)
            else:
                up = input(GREEN + "Set upload limit (e.g. 1 gbps, 500 kbps, or 0 to cancel): " + RESET).strip()
                if up == "0":
                    continue
                down = input(GREEN + "Set download limit (or 0 to cancel): " + RESET).strip()
                if down == "0":
                    continue
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
            port_hopping_manager()
        elif choice == "10":
            manage_outbounds_config()
        elif choice == "11":
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

if __name__ == "__main__":
    main_menu()
