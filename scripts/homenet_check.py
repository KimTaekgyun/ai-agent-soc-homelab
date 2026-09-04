#!/usr/bin/env python3
"""HOME_NET vs 실제 WAN IP 비교. 불일치 시 Discord 경고.
CT 100 (suricata-ids)에서 cron으로 실행."""

import json
import os
import re
import urllib.request

SURICATA_YAML = "/etc/suricata/suricata.yaml"
STATE_FILE = "/var/tmp/homenet_check.state"
# 웹훅은 코드에 박지 말 것 — 환경 파일에서 읽는다
ENV_FILE = "/etc/soc-monitor.env"

IP_SERVICES = [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
]

def load_webhook():
    with open(ENV_FILE) as f:
        for line in f:
            if line.startswith("DISCORD_WEBHOOK_URL="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError("DISCORD_WEBHOOK_URL not found in env file")

def get_wan_ip():
    for url in IP_SERVICES:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                    return ip
        except Exception:
            continue  # 다음 서비스로 폴백
    return None

def get_homenet_ip():
    with open(SURICATA_YAML) as f:
        for line in f:
            m = re.match(r'\s*HOME_NET:\s*"?\[?([\d.]+)/\d+', line)
            if m:
                return m.group(1)
    return None

def send_discord(webhook, msg):
    data = json.dumps({
        "username": "SOC Monitor",
        "content": msg,
    }).encode()
    req = urllib.request.Request(
        webhook, data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "soc-monitor/1.0",
        },
    )
    urllib.request.urlopen(req, timeout=10)

def read_state():
    try:
        with open(STATE_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def write_state(s):
    with open(STATE_FILE, "w") as f:
        f.write(s)

def main():
    webhook = load_webhook()
    wan_ip = get_wan_ip()
    homenet_ip = get_homenet_ip()

    if wan_ip is None:
        # 외부 조회 전부 실패 = 인터넷 문제일 수 있음. 
        # 여기서 Discord 전송도 어차피 실패하므로 조용히 종료.
        return

    if homenet_ip is None:
        if read_state() != "yaml_error":
            send_discord(webhook,
                "[WARN] suricata.yaml에서 HOME_NET 파싱 실패. 수동 확인 필요.")
            write_state("yaml_error")
        return

    if wan_ip != homenet_ip:
        state = f"mismatch:{wan_ip}"
        if read_state() != state:  # 같은 불일치로 반복 알림 방지
            send_discord(webhook,
                f"[ALERT] WAN IP 변경 감지\n"
                f"- 현재 WAN IP: {wan_ip}\n"
                f"- HOME_NET 설정: {homenet_ip}\n"
                f"- 영향: ET 룰 매칭 불가 상태. suricata.yaml HOME_NET 갱신 후 "
                f"suricata 재시작 필요.")
            write_state(state)
    else:
        if read_state() != "ok":
            if read_state().startswith("mismatch"):
                send_discord(webhook, f"[OK] HOME_NET 일치 복구됨 ({wan_ip})")
            write_state("ok")

if __name__ == "__main__":
    main()
