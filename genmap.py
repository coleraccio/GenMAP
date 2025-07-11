import os
import sys
import subprocess
import re
import json
import getpass
from datetime import datetime
from rich.console import Console
from pyfiglet import Figlet

# Initialize console
console = Console()
sudo_password = None

# **Timestamped File Naming**
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# **Print the Banner**
def print_banner():
    fig = Figlet(font="slant")
    banner = fig.renderText("genMAP")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold green]GenMAP: Advanced Network Reconnaissance for Pentesters[/bold green]")
    console.print(f"[yellow]Created by: K3strelSec | Version: 3.0.0[/yellow]")
    console.print("[bold bright_red]---------------------------------------------------[/bold bright_red]")
    console.print("[bold cyan]Key:")
    console.print("[red]Red - Open Ports[/red]")
    console.print("[blue]Blue - Service Information[/blue]")
    console.print("[green]Green - OS Details[/green]")
    console.print("[yellow]Yellow - Vulnerabilities[/yellow]")
    console.print("[white]White - General Info[/white]")
    console.print("[purple]Purple - Active Directory / Domain Info[/purple]")
    console.print("")
    console.print("[bold bright_magenta]---------------------------------------------------[/bold bright_magenta]")

# **Colorization Function**
def colorize_output(output):
    patterns = {
        "open_ports": r"(\d+)/(tcp|udp)\s+open",
        "service_info": r"(Service Info:.*|http-server-header:.*|http-title:.*)",
        "os_details": r"(OS details|Running|CPE:.*): (.+)",
        "vulnerabilities": r"(CVE-\d{4}-\d+|exploit|vuln|potentially vulnerable)",
        "active_directory": r"(Active Directory|Domain Controller|Kerberos|SMB|LDAP|FQDN)"
    }
    for key, pattern in patterns.items():
        color = {
            "open_ports": "red", "service_info": "blue", "os_details": "green",
            "vulnerabilities": "yellow", "active_directory": "purple"
        }[key]
        output = re.sub(pattern, lambda x: f"[{color}]{x.group()}[/{color}]", output)
    return output

# **Save Scan Results**
import os

def save_results(target, output, scan_type):
    timestamp = get_timestamp()

    # Create a `scans/` directory if it doesn’t exist
    base_dir = "scans"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    # Create a subdirectory for the target IP
    target_dir = os.path.join(base_dir, target)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # Save scan results inside the IP-specific directory
    filename = os.path.join(target_dir, f"genMAP_{scan_type}_scan_{target}_{timestamp}.txt")
    with open(filename, "w") as f:
        f.write(output)

    console.print(f"\n[bold cyan]Scan saved to: {filename}[/bold cyan]")


# **Scan Menu**
def scan_menu():
    console.print("\n[bold cyan]Select a scan mode:[/bold cyan]")
    console.print("[1] Basic TCP Scan")
    console.print("[2] Aggressive TCP Scan")
    console.print("[3] Silent TCP Scan (Stealth)")
    console.print("[4] UDP Scan")
    console.print("[5] Vulnerability Scan")
    console.print("[6] Full Enumeration (TCP + UDP + Vuln)")
    console.print("[7] Custom Nmap Scan")
    choice = console.input("\n[bold yellow]Enter your choice: [/bold yellow]").strip()
    return choice

# **Run TCP Scan**
def run_tcp_scan(target, aggressive=False, stealth=False, full_enum=False):
    global sudo_password
    if not sudo_password:
        console.print("\n[bold yellow]Please enter your sudo password for this scan:[/bold yellow]")
        sudo_password = getpass.getpass("Sudo Password: ")

    if aggressive:
        cmd = ["nmap", "-A", "-T4", "-p-", target]
    elif stealth:
        cmd = ["nmap", "-sS", "-T2", "-Pn", "-p-", "-f", "--mtu", "16", "--scan-delay", "5s", "--randomize-hosts", target]
    else:
        cmd = ["nmap", "-sS", "-T4", "-p-", "-O", "-sV", "-sC", target]

    execute_scan(target, cmd, "tcp", full_enum=full_enum)  # Pass `full_enum`

# **Run UDP Scan**
def run_udp_scan(target, full_enum=False):
    cmd = ["nmap", "-sU", "--top-ports", "200", "-T4", target]
    execute_scan(target, cmd, "udp", full_enum=full_enum)  # Pass `full_enum`


# **Run Vulnerability Scan**
def run_vuln_scan(target, full_enum=False):
    cmd = ["nmap", "-sV", "--script=vuln,vulners,http-enum,smb-enum-shares,rdp-enum-encryption", target]
    execute_scan(target, cmd, "vuln", full_enum=full_enum)  # Pass `full_enum`

# **Run Custom Scan**
def run_custom_scan(target, custom_args):
    cmd = ["nmap"] + custom_args.split() + [target]
    execute_scan(target, cmd, "custom")

# **Execute Scan, Parse Results, and Provide Exploitation Tips**
def execute_scan(target, cmd, scan_type, full_enum=False):
    global sudo_password
    if not sudo_password:
        console.print("\n[bold yellow]Please enter your sudo password for this scan:[/bold yellow]")
        sudo_password = getpass.getpass("Sudo Password: ")

    console.print(f"\n[bold green]Running {scan_type.upper()} Scan: {' '.join(cmd)}[/bold green]")

    process = subprocess.Popen(["sudo", "-S"] + cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    process.stdin.write(sudo_password + "\n")
    process.stdin.flush()

    output_lines = []
    for line in iter(process.stdout.readline, ''):
        output_lines.append(line)

    process.stdout.close()
    process.wait()
    output = "".join(output_lines)

    console.print(f"\n[bold blue]Raw Data ({scan_type.upper()} Scan Output):[/bold blue]")
    console.print(colorize_output(output))

    save_results(target, output, scan_type)

    # Ensure parsed results are displayed every time
    parsed_data = parse_results(output)

    (
        open_ports, vulnerabilities, os_details, device_type, service_info,
        active_directory, general_info, smb_info, ssl_info, firewall_info, traceroute_info
    ) = parsed_data

    console.print("\n[bold cyan]Parsed Results:[/bold cyan]")
    console.print(f"[red]Open Ports:[/red] {', '.join([f'{p[0]}/{p[1]} ({p[2]})' for p in open_ports]) if open_ports else 'None'}")
    console.print(f"[green]OS Details:[/green] {os_details}")
    console.print(f"[blue]Service Info:[/blue] {', '.join(service_info) if service_info else 'None'}")
    console.print(f"[purple]Active Directory:[/purple] {', '.join(active_directory) if active_directory else 'None'}")
    console.print(f"[yellow]Vulnerabilities:[/yellow] {', '.join(vulnerabilities) if vulnerabilities else 'None'}")
    console.print(f"[white]General Info:[/white] {', '.join(general_info) if general_info else 'None'}")

    if smb_info:
        console.print("\n[bold magenta]SMB Security Information:[/bold magenta]")
        for key, value in smb_info.items():
            console.print(f"[magenta]{key}:[/magenta] {value}")

    if ssl_info:
        console.print("\n[bold cyan]SSL/TLS Information:[/bold cyan]")
        for key, value in ssl_info.items():
            console.print(f"[cyan]{key}:[/cyan] {value}")

    if firewall_info:
        console.print("\n[bold red]Firewall Detection:[/bold red]")
        for info in firewall_info:
            console.print(f"[red]{info}[/red]")

    if traceroute_info:
        console.print("\n[bold yellow]Traceroute Information:[/bold yellow]")
        for hop in traceroute_info:
            console.print(f"[yellow]{hop}[/yellow]")

    generate_exploitation_tips(open_ports, vulnerabilities, general_info)

    # If running Full Enumeration, continue with the next scan automatically
    if full_enum and scan_type == "tcp":
        console.print("\n[bold cyan]TCP Scan Complete. Starting UDP Scan...[/bold cyan]")
        run_udp_scan(target, full_enum=True)
    elif full_enum and scan_type == "udp":
        console.print("\n[bold cyan]UDP Scan Complete. Starting Vulnerability Scan...[/bold cyan]")
        run_vuln_scan(target, full_enum=True)
    elif full_enum and scan_type == "vuln":
        console.print("\n[bold cyan]Full Enumeration Completed![/bold cyan]")

    # Only prompt if NOT in Full Enumeration mode
    if not full_enum:
        next_step = console.input("\n[bold cyan]Do you want to continue with another scan? (y/n): [/bold cyan]").strip().lower()
        if next_step == "y":
            new_choice = scan_menu()
            handle_scan_choice(new_choice, target)


# **Handle Scan Choice**
def handle_scan_choice(choice, target, full_enum=False):
    global sudo_password
    if not sudo_password:
        console.print("\n[bold yellow]Please enter your sudo password for this scan:[/bold yellow]")
        sudo_password = getpass.getpass("Sudo Password: ")

    if choice == "1":
        run_tcp_scan(target)
    elif choice == "2":
        run_tcp_scan(target, aggressive=True)
    elif choice == "3":
        run_tcp_scan(target, stealth=True)
    elif choice == "4":
        run_udp_scan(target)
    elif choice == "5":
        run_vuln_scan(target)
    elif choice == "6":  # Fix Full Enumeration
        console.print("\n[bold cyan]Running Full Enumeration: TCP + UDP + Vulnerability Scan[/bold cyan]")
        run_tcp_scan(target, full_enum=True)  # Pass `full_enum=True` to skip prompts
    elif choice == "7":
        custom_cmd = console.input("[bold yellow]Enter your custom Nmap command (without 'nmap'): [/bold yellow]").strip()
        run_custom_scan(target, custom_cmd)
    else:
        console.print("[bold red]Invalid choice. Please try again.[/bold red]")

# **Parse Results**
def parse_results(output):
    open_ports = re.findall(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", output)
    vulnerabilities = list(set(re.findall(r"CVE-\d{4}-\d+", output)))  # Remove duplicates

    # Capture OS details
    os_details_match = re.search(r"(OS details|Running): (.+)", output)
    os_guess_match = re.search(r"Running \(JUST GUESSING\): (.+)", output)
    os_cpe_match = re.search(r"CPE: (cpe:/o:[a-z]+:[a-z_]+)", output)

    if os_details_match:
        os_details = os_details_match.group(2)
    elif os_guess_match:
        os_details = f"Guessed: {os_guess_match.group(1)}"
    elif os_cpe_match:
        os_details = os_cpe_match.group(1)
    else:
        os_details = "Unknown OS"

    # Capture Service Info
    service_info = list(set(re.findall(r"(Service Info: .+|http-server-header: .+|http-title: .+|OS CPE: .+)", output)))

    # Capture Active Directory-related data
    active_directory = list(set(re.findall(r"(Active Directory|Domain Controller|Kerberos|SMB|LDAP|FQDN|NTLM)", output)))

    # Additional general information categories
    general_info = []
    indicators = {
        "File Exposure": [r"(index of /|directory listing|filetype|file)"],
        "Credentials": [r"(password|username|credentials|hash|login|admin)"],
        "Sensitive Files": [r"(robots.txt|sitemap.xml|exposed|backup|config|db|.pem|.key)"],
        "Internal IPs": [r"(\d+\.\d+\.\d+\.\d+)"],
        "Web Tech": [r"(PHP|WordPress|Drupal|Joomla|Apache|Tomcat|Node.js)"],
        "Miscellaneous": [r"(Public Key|Certificate|TLS|SSL|DNS|Docker|Kubernetes)"]
    }

    for category, patterns in indicators.items():
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                general_info.append(f"{category}: {', '.join(set(matches))}")

    # **Extract SMB Security Information**
    smb_info = {}
    smb_match = re.findall(r"(smb2-security-mode|smb2-time):\s*(.*)", output, re.IGNORECASE)
    for key, value in smb_match:
        smb_info[key] = value

    # **Extract SSL/TLS Information**
    ssl_info = {}
    ssl_match = re.findall(r"(TLSv1\.\d|SSLv\d) enabled", output)
    if ssl_match:
        ssl_info["Enabled Protocols"] = ", ".join(ssl_match)

    # **Extract Firewall Detection**
    firewall_info = []
    firewall_patterns = [
        r"Nmap done: 0 IP addresses",
        r"(Host seems down|filtered)",
        r"Blocked by firewall"
    ]
    for pattern in firewall_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            firewall_info.append(pattern)

    # **Extract Traceroute Info**
    traceroute_info = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+\d+.\d+ ms", output)

    return (
        open_ports, vulnerabilities, os_details, "Unknown Device", service_info,
        active_directory, general_info, smb_info, ssl_info, firewall_info, traceroute_info
    )

# **Fully Expanded attack_methods**
def generate_exploitation_tips(open_ports, vulnerabilities, general_info):
    recommendations = []

    attack_methods = {
        21: "FTP detected. Try `ftp <ip>`, anonymous login, brute-force (`hydra`).",
        22: "SSH detected. Try key-based attacks, brute-force (`hydra`, `patator`).",
        23: "Telnet detected. Try weak credentials, sniffing (`tcpdump`), MITM attacks.",
        25: "SMTP detected. Check for Open Relay (`Metasploit smtp_version`).",
        53: "DNS detected. Try zone transfer (`dig axfr @<ip>`), enumerate subdomains (`dnsenum`).",
        67: "DHCP detected. Rogue DHCP possible (`dhcpstarv`).",
        69: "TFTP detected. Check for open directory listing (`tftp <ip>`).",
        80: "HTTP detected. Run `gobuster`, check for SQL Injection, LFI, RCE (`sqlmap`).",
        110: "POP3 detected. Try brute-force (`hydra`).",
        111: "RPCBind detected. Try `rpcinfo -p <ip>`, `showmount -e <ip>`.",
        119: "NNTP (Usenet) detected. Try authentication bypass (`telnet <ip> 119`).",
        123: "NTP detected. Check for amplification attack (`ntpq -c rv <ip>`).",
        135: "MSRPC detected. Use `rpcdump.py` from Impacket.",
        137: "NetBIOS detected. Try `nmblookup -A <ip>` to list NetBIOS names.",
        139: "SMB detected. Check for anonymous login, null sessions (`enum4linux`, `smbclient`).",
        143: "IMAP detected. Try brute-force (`hydra`), inspect emails.",
        161: "SNMP detected. Try `snmpwalk -v1 -c public <ip>` for enumeration.",
        389: "LDAP detected. Try anonymous bind (`ldapsearch -x -h <ip>`).",
        443: "HTTPS detected. Look for SSL vulnerabilities (`sslscan`, `testssl.sh`).",
        445: "SMB detected. Test for EternalBlue (`Metasploit ms17_010`), password spray.",
        512: "Rexec detected. Try `rsh <ip>`, check `.rhosts` files.",
        513: "Rlogin detected. Try `.rhosts` trust abuse.",
        514: "Rsh detected. Possible remote command execution.",
        873: "RSYNC detected. Check for open directory (`rsync --list-only <ip>::`).",
        902: "VMware detected. Check for guest-to-host escape exploits.",
        1080: "SOCKS proxy detected. Possible open relay attack.",
        1433: "MSSQL detected. Try default credentials (`sa` user), enumerate databases (`nmap --script ms-sql*`).",
        1521: "Oracle DB detected. Try `odat.py` for database attacks.",
        1723: "PPTP VPN detected. Check for MS-CHAPv2 vulnerabilities.",
        2049: "NFS detected. Try `showmount -e <ip>` to list shares.",
        2181: "Zookeeper detected. Try `echo srvr | nc <ip> 2181`.",
        2375: "Docker API detected. Check for unauthenticated access (`curl http://<ip>:2375/version`).",
        3306: "MySQL detected. Try `mysql -u root -h <ip>`, check for weak credentials.",
        3389: "RDP detected. Try brute-force (`xfreerdp`), exploit (`BlueKeep`).",
        3632: "DistCC detected. Try remote command execution (`nmap --script distcc-cve2004-2687`).",
        4444: "Metasploit detected. Possible Meterpreter shell running (`nc -nv <ip> 4444`).",
        5000: "Docker Registry detected. Check for open access (`curl -X GET http://<ip>:5000/v2/_catalog`).",
        5432: "PostgreSQL detected. Try `psql -h <ip> -U postgres`, check for weak passwords.",
        5900: "VNC detected. Try password cracking (`hydra -P rockyou.txt -t 4 -s 5900 <ip> vnc`).",
        5985: "WinRM detected. Check for admin access (`evil-winrm -i <ip> -u <user> -p <password>`).",
        6379: "Redis detected. Check for unauthenticated access (`redis-cli -h <ip> ping`).",
        6667: "IRC detected. Check for open proxy (`nmap --script irc-unrealircd-backdoor`).",
        7001: "WebLogic detected. Check for deserialization vulnerabilities.",
        8000: "Common Web App detected. Run `gobuster`, check for admin panels.",
        8080: "Common Proxy/Web App detected. Test for open proxy abuse.",
        8443: "Alternative HTTPS detected. Look for misconfigurations.",
        8888: "Jupyter Notebook detected. Check for open access (`http://<ip>:8888/tree`).",
        9000: "PHP-FPM detected. Possible remote code execution (`CVE-2019-11043`).",
        9200: "Elasticsearch detected. Check for unauthenticated API access (`curl -X GET <ip>:9200/_cluster/health`).",
        11211: "Memcached detected. Try amplification attacks (`memcrashed`).",
        27017: "MongoDB detected. Try `mongo --host <ip>` to check for unauthenticated access.",
        50000: "SAP Management Console detected. Check for vulnerabilities (`nmap --script sap* -p 50000 <ip>`).",
    }

    # Fix: Unpack only the first two values and ignore the service name
    for port_tuple in open_ports:
        port = int(port_tuple[0])  # Extract only the port number
        if port in attack_methods:
            recommendations.append(attack_methods[port])

    # Check for CVE vulnerabilities found in the scan
    for vuln in vulnerabilities:
        recommendations.append(f"Possible exploit available for `{vuln}`. Check ExploitDB: https://www.exploit-db.com/search?cve={vuln}")

    # Print Exploitation Recommendations
    console.print("\n[bold cyan]Exploitation Recommendations:[/bold cyan]")
    for rec in recommendations:
        console.print(f"[bold yellow]- {rec}[/bold yellow]")

    return recommendations
    
# **Main Function**
def main():
    print_banner()
    target = console.input("[bold yellow]Enter Target IP or domain: [/bold yellow]").strip()

    if not target:
        console.print("[bold red]Error: No target entered![/bold red]")
        return

    choice = scan_menu()
    handle_scan_choice(choice, target)

if __name__ == "__main__":
    main()
