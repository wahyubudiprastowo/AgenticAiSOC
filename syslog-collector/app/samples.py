from datetime import datetime, timezone
_NOW = datetime.now(timezone.utc).strftime("%Y-%m-%d"); _TIME = datetime.now(timezone.utc).strftime("%H:%M:%S")
SAMPLE_SCENARIOS = {
    "vpn_bruteforce": {"description": "Repeated failed VPN logins then success", "lines": (
        [f'date={_NOW} time={_TIME} type=utm subtype=vpn srcip=185.220.101.7 dstip=10.10.1.5 user=vpn_user{i} action=denied msg="authentication failure"' for i in range(1, 8)]
        + [f'date={_NOW} time={_TIME} type=utm subtype=vpn srcip=185.220.101.7 dstip=10.10.1.5 user=vpn_user1 action=allowed msg="login attempt succeeded after multiple failures"'])},
    "malware_download": {"description": "Fortigate AV block", "lines": [
        f'date={_NOW} time={_TIME} type=utm subtype=virus srcip=10.10.1.44 dstip=91.234.36.55 virus=Trojan.GenericKD.71234567 action=blocked msg="virus detected in http download"']},
    "port_scan": {"description": "Port scan", "lines": [
        f'date={_NOW} time={_TIME} type=utm subtype=ips srcip=45.155.205.20 dstip=10.10.2.10 action=blocked msg="TCP port scan detected"' for _ in range(5)]},
    "linux_ssh_bruteforce": {"description": "SSH bruteforce", "lines": [
        f'{_NOW}T{_TIME}Z server01 sshd[2231]: Failed password for invalid user admin from 103.85.24.9 port 51122 ssh2' for _ in range(6)]},
    "ddos_attack": {"description": "Fortigate DoS sensor SYN flood", "lines": [
        f'date={_NOW} time={_TIME} type=utm subtype=dos srcip=198.51.100.{i} dstip=10.10.1.1 attack="tcp_syn_flood" action=blocked msg="denial of service attack blocked"' for i in range(1, 20)]},
    "sql_injection": {"description": "Fortigate WAF SQL injection block", "lines": [
        f'date={_NOW} time={_TIME} type=utm subtype=waf srcip=203.0.113.55 dstip=10.10.3.10 attack="SQL.Injection.Union.Select" action=blocked msg="web attack blocked: OR 1=1 UNION SELECT"']},
}
