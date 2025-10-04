from typing import List, Dict, Any
import subprocess, socket, shlex
from urllib.parse import urlparse
from datetime import datetime

def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()

def run_command(cmd: List[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = proc.stdout.strip()
        if out:
            return out
        err = proc.stderr.strip()
        if err:
            return f"[stderr] {err}"
        return "[no output]"
    except Exception as e:
        return f"[error] {e}"

def extract_hostname_or_ip(url_or_host: str) -> str:
    try:
        socket.inet_aton(url_or_host)
        return url_or_host
    except Exception:
        pass
    parsed = urlparse(url_or_host if "://" in url_or_host else f"//{url_or_host}", scheme="http")
    host = parsed.hostname or url_or_host
    return host

def resolve_ipv4(hostname: str) -> str:
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        if not infos:
            raise socket.gaierror(f"No IPv4 address found for {hostname}")
        return infos[0][4][0]
    except Exception:
        return socket.gethostbyname(hostname)
def summarize_output(step: str, output: str) -> str:
    if not output or output.strip() in ("[no output]",):
        return "No output"
    try:
        if step == "PING":
            for line in output.splitlines():
                if "avg" in line:
                    return line.strip()
            return output.splitlines()[-1].strip()
        elif step == "WHOIS":
            org, country = None, None
            for line in output.splitlines():
                if line.startswith("OrgName:"):
                    org = line.split(":", 1)[1].strip()
                if line.startswith("Country:"):
                    country = line.split(":", 1)[1].strip()
            return f"{org or 'Unknown'} ({country or 'N/A'})"
        elif step == "GEOIPLOOKUP":
            return output.splitlines()[0].strip() if output else "No geo info"
        elif step == "DIG_REVERSE":
            ptrs = [l.split()[-1] for l in output.splitlines() if "PTR" in l]
            return ", ".join(ptrs) if ptrs else "No PTR record"
        elif step == "DIG_SHORT":
            return output.strip() or "No result"
        elif step == "MTR":
            lines = output.splitlines()
            return lines[-1].strip() if lines else "No hops"
        elif step == "NMAP":
            open_ports = [l.strip() for l in output.splitlines() if "open" in l]
            return "; ".join(open_ports[:5]) + (" ..." if len(open_ports) > 5 else "") if open_ports else "No open ports"
        elif step == "SSLSCAN":
            lines = [l.strip() for l in output.splitlines() if l.strip().startswith("TLSv")]
            return ", ".join(lines) if lines else "No TLS info"
        elif step == "AMASS":
            return "Amass needs correct subcommand (intel/enum/etc.)"
        else:
            return output.splitlines()[0][:200]
    except Exception:
        return output[:200]
def analyze_url_and_collect_logs(url_or_host: str) -> Dict[str, Any]:
    tools_results: Dict[str, Any] = {}
    logs: List[Dict[str, str]] = []
    try:
        host = extract_hostname_or_ip(url_or_host)
        logs.append({"timestamp": _now_iso(), "step": "EXTRACT_HOST", "output": f"Extracted host: {host}"})
    except Exception as e:
        logs.append({"timestamp": _now_iso(), "step": "EXTRACT_HOST", "output": f"Failed to extract host: {e}"})
        return {"ip": None, "logs": logs}
    try:
        ip = resolve_ipv4(host)
        logs.append({"timestamp": _now_iso(), "step": "RESOLVE_IP", "output": f"Resolved IPv4: {ip}"})
    except Exception as e:
        logs.append({"timestamp": _now_iso(), "step": "RESOLVE_IP", "output": f"DNS resolution failed: {e}"})
        return {"ip": None, "logs": logs}
    tools_results["domain"] = host
    tools_results["ip"] = ip
    def run_tool(step_name: str, cmd_list: List[str], timeout: int = 30):
        cmd_str = " ".join(shlex.quote(p) for p in cmd_list)
        logs.append({"timestamp": _now_iso(), "step": step_name, "output": f"Running: {cmd_str}"})
        result = run_command(cmd_list, timeout=timeout)
        logs.append({"timestamp": _now_iso(), "step": step_name + "_RESULT", "output": result})
        tools_results[step_name.lower()] = summarize_output(step_name, result)
    run_tool("PING", ["ping", "-c", "4", ip], timeout=10)
    run_tool("WHOIS", ["whois", ip], timeout=20)
    run_tool("GEOIPLOOKUP", ["geoiplookup", ip], timeout=8)
    try:
        rdns = socket.gethostbyaddr(ip)[0]
        logs.append({"timestamp": _now_iso(), "step": "REVERSE_DNS_SOCKET", "output": f"Reverse DNS (socket): {rdns}"})
        tools_results["reverse_dns"] = rdns
    except Exception as e:
        logs.append({"timestamp": _now_iso(), "step": "REVERSE_DNS_SOCKET", "output": f"No reverse DNS record found: {e}"})
        tools_results["reverse_dns"] = None
    run_tool("DIG_REVERSE", ["dig", "-x", ip], timeout=8)
    run_tool("DIG_SHORT", ["dig", "+short", ip], timeout=6)
    run_tool("MTR", ["mtr", "--report", "--report-cycles", "10", ip], timeout=40)
    run_tool("NMAP", ["nmap", "-sV", "-O", "-Pn", ip], timeout=120)
    run_tool("SSLSCAN", ["sslscan", ip], timeout=40)
    run_tool("AMASS", ["amass", "intel", "-addr", ip], timeout=30)
    tools_results["logs"] = logs
    tools_results["timestamp"] = _now_iso()
    return tools_results
