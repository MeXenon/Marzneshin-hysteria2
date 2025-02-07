# Marzneshin/Marznode - Hysteria2 Manager by @XenonNet

A Python script to manage SSL certificates and Hysteria2 configurations for Marzneshin/Marznode.

**Features:**
- **SSL Management:** Generate a self‐signed (10‑year) certificate or obtain a Let's Encrypt certificate.
- **Hysteria2 Configuration:** Enable/disable Hysteria2 via Docker Compose and interactively adjust or apply settings:
listening port
sniGuard
obfuscation
bandwidth limits
DNS resolver
manage ACL / Block Traffic
Outbounds and ACL related
etc
...
- **Restart Functionality:** Automatically detect live logs during restart and display elapsed time.

**Requirements:**
- OS: Ubuntu (or any OS with Python 3.x)
- Dependencies: cryptography, PyYAML, curl, socat, nano, Docker Compose (or docker‑compose‑plugin)

**Installation:**
- Install system dependencies and required Python packages.
- Clone the repository and run the script:
<pre> git clone https://github.com/MeXenon/Marzneshin-hysteria2.git</pre>
  <pre> cd Marzneshin-hysteria2 && chmod +x Hysteria2.py && ./Hysteria2.pp</pre>

Or just run it straightly with:

```cd Marzneshin-hysteria2  ```

```python3 Hysteria2.py```

**Usage:**
Follow the interactive menus to manage SSL and Hysteria2 configurations.

**License:** MIT
