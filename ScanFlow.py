#!/usr/bin/env python3
# ScanFlow.py — Interactive Nmap automation tool (debugged)
# Author: Harsh Katiyar (adapted)
# Usage: python3 ScanFlow.py

import platform
import subprocess
import sys

# ===== Colors =====
NC = '\033[0m'
BOLD = '\033[1m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
CYAN = '\033[36m'
WHITE = '\033[37m'

# ===== Banner =====
def print_banner():
    art = r"""

 _______  _______  _______  _        _______  _        _______          
(  ____ \(  ___  )(  ____ \( (    /|(  ____ \( \      (  ___  )|\     /|
| (    \/| (   ) || (    \/|  \  ( || (    \/| (      | (   ) || )   ( |
| (_____ | (___) || |      |   \ | || (__    | |      | |   | || | _ | |
(_____  )|  ___  || |      | (\ \) ||  __)   | |      | |   | || |( )| |
      ) || (   ) || |      | | \   || (      | |      | |   | || || || |
/\____) || )   ( || (____/\| )  \  || )      | (____/\| (___) || () () |
\_______)|/     \|(_______/|/    )_)|/       (_______/(_______)(_______)
                                                                        

    
             Interactive Nmap Automation —  SCANFLOW
    """
    print(f"{CYAN}{art}{NC}")
    print(f"{BOLD}{GREEN}Author:{NC} Harsh Katiyar    {BOLD}{GREEN}Tool:{NC} ScanFlow\n")

# ===== Helpers =====
def check_command(cmd):
    if platform.system().lower() == 'windows':
        check = subprocess.run(['where', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        check = subprocess.run(['which', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check.returncode != 0:
        print(f"{RED}{cmd} is required but not installed or not in PATH. Aborting.{NC}")
        sys.exit(1)

def display_menu(prompt, options):
    print(f"\n{CYAN}{prompt}{NC}")
    for i, opt in enumerate(options, 1):
        print(f"{BLUE}{i}. {opt}{NC}")
    while True:
        choice = input("Choose an option number (or press Enter to skip): ").strip()
        if choice == '':
            return None
        if not choice.isdigit():
            print(f"{RED}Invalid input. Enter a number or press Enter to skip.{NC}")
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            return options[idx]
        else:
            print(f"{RED}Choice out of range.{NC}")

def ask_input(prompt, required=False):
    while True:
        v = input(prompt).strip()
        if v or not required:
            return v
        print(f"{RED}This value is required.{NC}")

def append_arg_to_cmd(cmd_list, arg):
    """Safely append an argument which may contain spaces (split into tokens)."""
    if not arg:
        return
    if isinstance(arg, (list, tuple)):
        cmd_list.extend(arg)
    elif isinstance(arg, str):
        # simple splitting on spaces is fine for our constructed args
        parts = arg.split()
        cmd_list.extend(parts)
    else:
        cmd_list.append(str(arg))

# ===== Main flow =====
def main():
    print_banner()
    check_command('nmap')

    # 1) Target Specification
    target_opts = [
        "Scan a single IP",
        "Scan specific IPs (space separated)",
        "Scan a range of IPs (e.g., 192.168.1.1-254)",
        "Scan a domain (hostname)",
        "Scan using CIDR notation (e.g., 192.168.1.0/24)",
        "Scan targets from a file (-iL file.txt)",
        "Exclude listed hosts (--exclude host1,host2)"
    ]
    target_choice = display_menu("Target Specification", target_opts)
    target_arg = None
    if target_choice == "Scan a single IP":
        target_arg = ask_input("Enter the IP address: ", required=True)
    elif target_choice == "Scan specific IPs (space separated)":
        target_arg = ask_input("Enter IPs separated by space: ", required=True)
    elif target_choice == "Scan a range of IPs (e.g., 192.168.1.1-254)":
        target_arg = ask_input("Enter IP range: ", required=True)
    elif target_choice == "Scan a domain (hostname)":
        target_arg = ask_input("Enter domain/hostname: ", required=True)
    elif target_choice == "Scan using CIDR notation (e.g., 192.168.1.0/24)":
        target_arg = ask_input("Enter CIDR: ", required=True)
    elif target_choice == "Scan targets from a file (-iL file.txt)":
        path = ask_input("Enter path to file (one target per line): ", required=True)
        target_arg = "-iL " + path
    elif target_choice == "Exclude listed hosts (--exclude host1,host2)":
        ex = ask_input("Enter hosts to exclude (comma-separated): ", required=True)
        target_arg = "--exclude " + ex
    else:
        # If skipped, ask basic target
        target_arg = ask_input("Enter target (IP/hostname/CIDR or -iL file): ", required=True)

    # 2) Host Discovery (each flag separate)
    host_opts = [
        "-sL: List Scan - simply list targets to scan",
        "-sn: Ping Scan - disable port scan",
        "-Pn: Treat all hosts as online -- skip host discovery",
        "-PS[portlist]: TCP SYN discovery",
        "-PA[portlist]: TCP ACK discovery",
        "-PU[portlist]: UDP discovery",
        "-PY[portlist]: SCTP discovery",
        "-PE: ICMP echo request",
        "-PP: ICMP timestamp request",
        "-PM: ICMP netmask request",
        "-PO[protocol list]: IP Protocol Ping",
        "-n: Never do DNS resolution",
        "-R: Always resolve DNS",
        "--dns-servers <serv1,serv2...>",
        "--system-dns",
        "--traceroute"
    ]
    host_choice = display_menu("Host Discovery", host_opts)
    host_arg = None
    if host_choice:
        if host_choice.startswith("-PS"):
            ports = ask_input("Enter ports for -PS (comma-separated, e.g., 80,443) or press Enter for default: ")
            host_arg = "-PS" + ports if ports else "-PS"
        elif host_choice.startswith("-PA"):
            ports = ask_input("Enter ports for -PA (comma-separated) or press Enter: ")
            host_arg = "-PA" + ports if ports else "-PA"
        elif host_choice.startswith("-PU"):
            ports = ask_input("Enter ports for -PU (comma-separated) or press Enter: ")
            host_arg = "-PU" + ports if ports else "-PU"
        elif host_choice.startswith("-PY"):
            ports = ask_input("Enter ports for -PY (comma-separated) or press Enter: ")
            host_arg = "-PY" + ports if ports else "-PY"
        elif host_choice.startswith("-PO"):
            protos = ask_input("Enter protocol numbers for -PO (comma-separated, e.g., 1,2) or press Enter: ")
            host_arg = "-PO" + protos if protos else "-PO"
        elif host_choice.startswith("--dns-servers"):
            ds = ask_input("Enter DNS servers (comma-separated): ", required=True)
            host_arg = f"--dns-servers {ds}"
        elif host_choice == "--system-dns":
            host_arg = "--system-dns"
        elif host_choice == "--traceroute":
            host_arg = "--traceroute"
        elif host_choice.startswith("-PE") or host_choice.startswith("-PP") or host_choice.startswith("-PM"):
            host_arg = host_choice.split(":")[0].split()[0]
        else:
            # simple flags like -sL, -sn, -Pn, -n, -R
            host_arg = host_choice.split(":")[0].split()[0]

    # 3) Scan Techniques
    scan_opts = [
        "-sS: TCP SYN scan (default)",
        "-sT: TCP connect scan (non-root users)",
        "-sU: UDP scan",
        "-sA: TCP ACK scan",
        "-sW: TCP Window scan",
        "-sM: TCP Maimon scan",
        "-sN: TCP Null scan (no flags)",
        "-sF: TCP FIN scan",
        "-sX: TCP Xmas scan (FIN,PSH,URG)",
        "--scanflags <flags>: Customize TCP scan flags",
        "-sI <zombie host[:probeport]>: Idle (zombie) scan",
        "-sY: SCTP INIT scan",
        "-sZ: SCTP COOKIE-ECHO scan",
        "-sO: IP protocol scan",
        "-b <FTP relay host>: FTP bounce scan"
    ]
    scan_choice = display_menu("Scan Techniques", scan_opts)
    scan_arg = None
    if scan_choice:
        if "--scanflags" in scan_choice:
            flags = ask_input("Enter custom TCP flags (comma-separated, e.g., SYN,ACK,FIN): ", required=True)
            scan_arg = f"--scanflags {flags}"
        elif "-sI" in scan_choice:
            zombie = ask_input("Enter zombie host[:probeport] (e.g., zhost:80): ", required=True)
            scan_arg = f"-sI {zombie}"
        elif "-b" in scan_choice:
            ftp = ask_input("Enter FTP relay host: ", required=True)
            scan_arg = f"-b {ftp}"
        else:
            scan_arg = scan_choice.split(":")[0].split()[0]

    # 4) Port Specification
    port_opts = [
        "-p <port ranges>: Only scan specified ports",
        "--exclude-ports <port ranges>: Exclude specified ports",
        "-F: Fast mode (fewer ports)",
        "-r: Sequential scan (don't randomize)",
        "--top-ports <number>: Scan <number> most common ports",
        "--port-ratio <ratio>: Scan ports more common than <ratio>"
    ]
    port_choice = display_menu("Port Specification", port_opts)
    port_arg = None
    if port_choice:
        if port_choice.startswith("-p " ) or port_choice.startswith("-p"):
            pr = ask_input("Enter port ranges (e.g., 22,80,443 or 1-65535): ", required=True)
            port_arg = f"-p {pr}"
        elif "--exclude-ports" in port_choice:
            ex = ask_input("Enter ports to exclude: ", required=True)
            port_arg = f"--exclude-ports {ex}"
        elif port_choice.startswith("--top-ports"):
            n = ask_input("Enter number of top ports: ", required=True)
            port_arg = f"--top-ports {n}"
        elif port_choice.startswith("--port-ratio"):
            r = ask_input("Enter port ratio (e.g., 0.05): ", required=True)
            port_arg = f"--port-ratio {r}"
        else:
            port_arg = port_choice.split(":")[0].split()[0]

    # 5) Service & Version Detection
    svc_opts = [
        "No version detection",
        "-sV: Probe open ports to determine service/version info",
        "--version-intensity <level>: 0 (light) to 9 (try all probes)",
        "--version-light: Limit to most likely probes (intensity ~2)",
        "--version-all: Try every single probe (intensity 9)",
        "--version-trace: Show detailed version scan activity"
    ]
    svc_choice = display_menu("Service & Version Detection", svc_opts)
    svc_arg = None
    if svc_choice:
        if "--version-intensity" in svc_choice:
            level = ask_input("Enter intensity level (0-9): ", required=True)
            svc_arg = f"--version-intensity {level}"
        elif "--version-light" in svc_choice:
            svc_arg = "--version-light"
        elif "--version-all" in svc_choice:
            svc_arg = "--version-all"
        elif "--version-trace" in svc_choice:
            svc_arg = "--version-trace"
        elif "-sV" in svc_choice:
            svc_arg = "-sV"

    # 6) Script Scanning (NSE)
    script_opts = [
        "No script scanning",
        "-sC: Equivalent to --script=default",
        "--script=<Lua scripts>: Comma-separated list (dirs, files, categories)",
        "--script-args=<n1=v1,[n2=v2,...]>: Provide arguments to scripts",
        "--script-args-file=<filename>: Provide NSE script args in a file",
        "--script-trace: Show all data sent/received for scripts",
        "--script-updatedb: Update the script database",
        "--script-help=<Lua scripts>: Show help about scripts/categories"
    ]
    script_choice = display_menu("Script Scanning (NSE)", script_opts)
    script_arg = None
    if script_choice:
        if script_choice.startswith("-sC"):
            script_arg = "-sC"
        elif "--script=" in script_choice:
            scripts = ask_input("Enter script names/categories or paths (comma-separated): ", required=True)
            script_arg = f"--script={scripts}"
        elif "--script-args=" in script_choice:
            args = ask_input("Enter script args (n1=v1,n2=v2,..): ", required=True)
            script_arg = f"--script-args={args}"
        elif "--script-args-file" in script_choice:
            fname = ask_input("Enter script args filename: ", required=True)
            script_arg = f"--script-args-file={fname}"
        elif "--script-trace" in script_choice:
            script_arg = "--script-trace"
        elif "--script-updatedb" in script_choice:
            script_arg = "--script-updatedb"
        elif "--script-help" in script_choice:
            s = ask_input("Enter scripts/categories for help (comma-separated): ", required=True)
            script_arg = f"--script-help={s}"

    # 7) OS Detection
    os_opts = [
        "No OS detection",
        "-O: Enable OS detection",
        "--osscan-limit: Limit OS detection to promising targets",
        "--osscan-guess: Guess OS more aggressively",
        "--max-os-tries <num>"
    ]
    os_choice = display_menu("OS Detection", os_opts)
    os_arg = None
    if os_choice:
        if "--max-os-tries" in os_choice:
            mt = ask_input("Enter max number of tries: ", required=True)
            os_arg = f"--max-os-tries {mt}"
        elif "--osscan-limit" in os_choice:
            os_arg = "--osscan-limit"
        elif "--osscan-guess" in os_choice:
            os_arg = "--osscan-guess"
        elif "-O" in os_choice:
            os_arg = "-O"

    # 8) Timing & Performance
    timing_opts = [
        "No timing/performance options",
        "-T0: Paranoid",
        "-T1: Sneaky",
        "-T2: Polite",
        "-T3: Normal (default)",
        "-T4: Aggressive",
        "-T5: Insane",
        "--min-hostgroup <size>",
        "--max-hostgroup <size>",
        "--min-parallelism <numprobes>",
        "--max-parallelism <numprobes>",
        "--min-rtt-timeout <time>",
        "--max-rtt-timeout <time>",
        "--initial-rtt-timeout <time>",
        "--max-retries <tries>",
        "--host-timeout <time>",
        "--scan-delay <time>",
        "--max-scan-delay <time>",
        "--min-rate <pps>",
        "--max-rate <pps>"
    ]
    timing_choice = display_menu("Timing and Performance", timing_opts)
    timing_arg = None
    if timing_choice:
        if timing_choice.startswith("-T"):
            timing_arg = timing_choice.split(":")[0]
        elif "--min-hostgroup" in timing_choice:
            v = ask_input("Enter min hostgroup size: ", required=True)
            timing_arg = f"--min-hostgroup {v}"
        elif "--max-hostgroup" in timing_choice:
            v = ask_input("Enter max hostgroup size: ", required=True)
            timing_arg = f"--max-hostgroup {v}"
        elif "--min-parallelism" in timing_choice:
            v = ask_input("Enter min parallelism (num probes): ", required=True)
            timing_arg = f"--min-parallelism {v}"
        elif "--max-parallelism" in timing_choice:
            v = ask_input("Enter max parallelism (num probes): ", required=True)
            timing_arg = f"--max-parallelism {v}"
        elif "--min-rtt-timeout" in timing_choice:
            v = ask_input("Enter min RTT timeout (e.g., 100ms,1s): ", required=True)
            timing_arg = f"--min-rtt-timeout {v}"
        elif "--max-rtt-timeout" in timing_choice:
            v = ask_input("Enter max RTT timeout (e.g., 1s,5s): ", required=True)
            timing_arg = f"--max-rtt-timeout {v}"
        elif "--initial-rtt-timeout" in timing_choice:
            v = ask_input("Enter initial RTT timeout (e.g., 500ms): ", required=True)
            timing_arg = f"--initial-rtt-timeout {v}"
        elif "--max-retries" in timing_choice:
            v = ask_input("Enter max retries: ", required=True)
            timing_arg = f"--max-retries {v}"
        elif "--host-timeout" in timing_choice:
            v = ask_input("Enter host timeout (e.g., 30s,5m): ", required=True)
            timing_arg = f"--host-timeout {v}"
        elif "--scan-delay" in timing_choice:
            v = ask_input("Enter scan delay (e.g., 200ms): ", required=True)
            timing_arg = f"--scan-delay {v}"
        elif "--max-scan-delay" in timing_choice:
            v = ask_input("Enter max scan delay (e.g., 5s): ", required=True)
            timing_arg = f"--max-scan-delay {v}"
        elif "--min-rate" in timing_choice:
            v = ask_input("Enter min rate (pps): ", required=True)
            timing_arg = f"--min-rate {v}"
        elif "--max-rate" in timing_choice:
            v = ask_input("Enter max rate (pps): ", required=True)
            timing_arg = f"--max-rate {v}"

    # 9) Firewall/IDS Evasion
    evas_opts = [
        "No evasion",
        "-f: Fragment packets",
        "--mtu <val>: fragment with MTU",
        "-D <decoy1,decoy2[,ME]>: Cloak scan with decoys",
        "-S <IP>: Spoof source IP",
        "-e <iface>: Use network interface",
        "-g/--source-port <port>: Use source port",
        "--proxies <url1,url2...>: Use HTTP/SOCKS4 proxies",
        "--data <hex string>",
        "--data-string <string>",
        "--data-length <num>",
        "--ip-options <options>",
        "--ttl <val>",
        "--spoof-mac <mac/prefix/vendor>",
        "--badsum"
    ]
    evas_choice = display_menu("Firewall/IDS Evasion", evas_opts)
    evas_arg = None
    if evas_choice:
        if evas_choice.startswith("-f"):
            evas_arg = "-f"
        elif "--mtu" in evas_choice:
            v = ask_input("Enter MTU value (numeric): ", required=True)
            evas_arg = f"--mtu {v}"
        elif evas_choice.startswith("-D"):
            v = ask_input("Enter decoy IPs (comma-separated, use ME for your IP): ", required=True)
            evas_arg = f"-D {v}"
        elif evas_choice.startswith("-S"):
            v = ask_input("Enter spoofed source IP: ", required=True)
            evas_arg = f"-S {v}"
        elif evas_choice.startswith("-e"):
            v = ask_input("Enter interface (e.g., eth0): ", required=True)
            evas_arg = f"-e {v}"
        elif "--source-port" in evas_choice or evas_choice.startswith("-g"):
            v = ask_input("Enter source port number: ", required=True)
            evas_arg = f"--source-port {v}"
        elif "--proxies" in evas_choice:
            v = ask_input("Enter proxies (comma-separated URL list): ", required=True)
            evas_arg = f"--proxies {v}"
        elif "--data " in evas_choice or "--data<" in evas_choice:
            v = ask_input("Enter hex string payload: ", required=True)
            evas_arg = f"--data {v}"
        elif "--data-string" in evas_choice:
            v = ask_input("Enter ASCII payload string: ", required=True)
            evas_arg = f'--data-string "{v}"'
        elif "--data-length" in evas_choice:
            v = ask_input("Enter data length (numeric): ", required=True)
            evas_arg = f"--data-length {v}"
        elif "--ip-options" in evas_choice:
            v = ask_input("Enter IP options: ", required=True)
            evas_arg = f"--ip-options {v}"
        elif "--ttl" in evas_choice:
            v = ask_input("Enter TTL value: ", required=True)
            evas_arg = f"--ttl {v}"
        elif "--spoof-mac" in evas_choice:
            v = ask_input("Enter MAC or vendor prefix: ", required=True)
            evas_arg = f"--spoof-mac {v}"
        elif "--badsum" in evas_choice:
            evas_arg = "--badsum"

    # 10) Output Options
    out_opts = [
        "No output options",
        "-oN <file>: Normal output",
        "-oX <file>: XML output",
        "-oS <file>: s|<rIpt kIddi3 format",
        "-oG <file>: Grepable output",
        "-oA <basename>: All main formats",
        "-v/-vv: Increase verbosity",
        "-d/-dd: Increase debugging",
        "--reason: Show why a port is in a particular state",
        "--open: Only show open ports",
        "--packet-trace: Show all packets sent/received",
        "--iflist: Print host interfaces and routes",
        "--append-output: Append to output files",
        "--resume <filename>: Resume aborted scan",
        "--noninteractive: Disable interactive runtime prompts",
        "--stylesheet <path/URL>: XSL for XML -> HTML",
        "--webxml: Reference stylesheet from Nmap.Org",
        "--no-stylesheet: Prevent XSL association"
    ]
    out_choice = display_menu("Output Options", out_opts)
    out_args = []
    if out_choice:
        if out_choice.startswith("-oN"):
            f = ask_input("Enter filename for normal output: ", required=True)
            out_args += ["-oN", f]
        elif out_choice.startswith("-oX"):
            f = ask_input("Enter filename for XML output: ", required=True)
            out_args += ["-oX", f]
        elif out_choice.startswith("-oS"):
            f = ask_input("Enter filename for s| output: ", required=True)
            out_args += ["-oS", f]
        elif out_choice.startswith("-oG"):
            f = ask_input("Enter filename for grepable output: ", required=True)
            out_args += ["-oG", f]
        elif out_choice.startswith("-oA"):
            b = ask_input("Enter base filename for all outputs: ", required=True)
            out_args += ["-oA", b]
        elif out_choice.startswith("-v"):
            lvl = ask_input("Enter verbosity level (1 for -v, 2 for -vv): ", required=True)
            if lvl.isdigit() and int(lvl) >= 1:
                out_args.append("-" + "v" * int(lvl))
            else:
                out_args.append("-v")
        elif out_choice.startswith("-d"):
            lvl = ask_input("Enter debug level (1 for -d, 2 for -dd): ", required=True)
            if lvl.isdigit() and int(lvl) >= 1:
                out_args.append("-" + "d" * int(lvl))
            else:
                out_args.append("-d")
        elif "--reason" in out_choice:
            out_args.append("--reason")
        elif "--open" in out_choice:
            out_args.append("--open")
        elif "--packet-trace" in out_choice:
            out_args.append("--packet-trace")
        elif "--iflist" in out_choice:
            out_args.append("--iflist")
        elif "--append-output" in out_choice:
            out_args.append("--append-output")
        elif "--resume" in out_choice:
            f = ask_input("Enter filename to resume from: ", required=True)
            out_args += ["--resume", f]
        elif "--noninteractive" in out_choice:
            out_args.append("--noninteractive")
        elif "--stylesheet" in out_choice:
            p = ask_input("Enter stylesheet path or URL: ", required=True)
            out_args += ["--stylesheet", p]
        elif "--webxml" in out_choice:
            out_args.append("--webxml")
        elif "--no-stylesheet" in out_choice:
            out_args.append("--no-stylesheet")

    # 11) Miscellaneous options
    misc_opts = [
        "No misc options",
        "-6: Enable IPv6 scanning",
        "-A: Enable OS detection, version detection, script scanning, and traceroute",
        "--datadir <dirname>: Specify custom Nmap data file location",
        "--send-eth: Send using raw ethernet frames",
        "--send-ip: Send using raw IP packets",
        "--privileged: Assume user is privileged",
        "--unprivileged: Assume user lacks raw socket privileges",
        "-V: Print version number",
        "-h: Print help summary page"
    ]
    misc_choice = display_menu("Miscellaneous Options", misc_opts)
    misc_arg = None
    if misc_choice:
        if misc_choice.startswith("-6"):
            misc_arg = "-6"
        elif misc_choice.startswith("-A"):
            misc_arg = "-A"
        elif "--datadir" in misc_choice:
            d = ask_input("Enter datadir path: ", required=True)
            misc_arg = f"--datadir {d}"
        elif "--send-eth" in misc_choice:
            misc_arg = "--send-eth"
        elif "--send-ip" in misc_choice:
            misc_arg = "--send-ip"
        elif "--privileged" in misc_choice:
            misc_arg = "--privileged"
        elif "--unprivileged" in misc_choice:
            misc_arg = "--unprivileged"
        elif "-V" in misc_choice:
            misc_arg = "-V"
        elif "-h" in misc_choice:
            misc_arg = "-h"

    # Build final command (flags first in the requested category order; target(s) last)
    cmd = ["nmap"]

    # Append options in the requested order:
    # (host discovery) -> (scan techniques) -> (port spec) -> (service/version) ->
    # (script scan) -> (os detection) -> (timing) -> (firewall/ids evasion) -> (output) -> (misc) -> target
    for opt in [host_arg, scan_arg, port_arg, svc_arg, script_arg, os_arg, timing_arg, evas_arg]:
        append_arg_to_cmd(cmd, opt)

    # output args already a list
    if out_args:
        cmd.extend(out_args)

    # misc arg last before target
    append_arg_to_cmd(cmd, misc_arg)

    # Finally add target(s)
    # target_arg may be "-iL file" or a single token or multiple tokens
    if target_arg:
        append_arg_to_cmd(cmd, target_arg)

    # Print final command for review
    print(f"\n{GREEN}{BOLD}Final nmap command:{NC} {' '.join(cmd)}\n")

    # Confirm run
    run = ask_input("Run this scan now? (y/n): ", required=True).lower()
    if run != 'y':
        print(f"{YELLOW}Scan cancelled by user.{NC}")
        return

    # Execute
    try:
        print(f"{CYAN}Executing...{NC}\n")
        subprocess.run(cmd, text=True)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Scan interrupted by user.{NC}")
    except Exception as e:
        print(f"{RED}Error executing nmap: {e}{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}User aborted.{NC}")
        sys.exit(0)