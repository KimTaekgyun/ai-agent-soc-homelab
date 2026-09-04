import os
import requests
import json
from datetime import datetime

ES_HOST = "http://<TS_IP_ES>:9200"
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")

def get_recent_alerts(minutes=60, size=20):
    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "suricata.eve.alert.signature"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "@timestamp", "source.ip", "destination.ip",
            "source.port", "destination.port",
            "suricata.eve.alert.signature",
            "suricata.eve.alert.category",
            "event.severity",
            "source.geo.country_iso_code",
            "destination.geo.country_iso_code"
        ]
    }
    resp = requests.get(f"{ES_HOST}/filebeat-*/_search",
                        json=query,
                        headers={"Content-Type": "application/json"})
    hits = resp.json().get("hits", {}).get("hits", [])

    alerts = []
    for h in hits:
        src = h["_source"]
        alerts.append({
            "timestamp": src.get("@timestamp"),
            "src_ip": src.get("source", {}).get("ip"),
            "dst_ip": src.get("destination", {}).get("ip"),
            "src_port": src.get("source", {}).get("port"),
            "dst_port": src.get("destination", {}).get("port"),
            "signature": src.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature"),
            "category": src.get("suricata", {}).get("eve", {}).get("alert", {}).get("category"),
            "severity": src.get("event", {}).get("severity"),
            "src_country": src.get("source", {}).get("geo", {}).get("country_iso_code"),
            "dst_country": src.get("destination", {}).get("geo", {}).get("country_iso_code"),
        })
    return alerts


def summarize_alerts(alerts):
    if not alerts:
        return "최근 alert 없음"

    lines = []
    lines.append(f"**🔍 SOC Alert 요약 — {datetime.now().strftime('%Y-%m-%d %H:%M')}**")
    lines.append(f"총 alert 수: {len(alerts)}")

    # Severity 분포
    sev_count = {}
    for a in alerts:
        s = a["severity"]
        sev_count[s] = sev_count.get(s, 0) + 1
    sev_labels = {1: "🔴 높음", 2: "🟠 중간", 3: "🟡 낮음"}
    sev_parts = [f"{sev_labels.get(s, f'Sev {s}')}: {sev_count[s]}건" for s in sorted(sev_count.keys())]
    lines.append(f"Severity: {', '.join(sev_parts)}")

    # Signature 상위 5개
    sig_count = {}
    for a in alerts:
        sig = a["signature"]
        sig_count[sig] = sig_count.get(sig, 0) + 1
    lines.append("")
    lines.append("**상위 Signature:**")
    for sig, count in sorted(sig_count.items(), key=lambda x: -x[1])[:5]:
        lines.append(f"  • `{sig}` — {count}건")

    # 외부 IP 국가
    country_count = {}
    for a in alerts:
        c = a.get("src_country") or "Unknown"
        country_count[c] = country_count.get(c, 0) + 1
    if country_count:
        lines.append("")
        lines.append("**Source 국가:**")
        for c, count in sorted(country_count.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"  • {c}: {count}건")

    return "\n".join(lines)


def send_discord(message):
    """Discord webhook으로 메시지 전송"""
    # Discord 메시지 2000자 제한
    if len(message) > 1900:
        message = message[:1900] + "\n... (truncated)"

    payload = {"content": message}
    resp = requests.post(DISCORD_WEBHOOK, json=payload)
    if resp.status_code == 204:
        print("[+] Discord 전송 성공")
    else:
        print(f"[-] Discord 전송 실패: {resp.status_code} {resp.text}")


def console_report(alerts):
    """터미널 출력용 리포트"""
    if not alerts:
        print("최근 alert 없음")
        return

    print(f"\n{'='*60}")
    print(f"SOC Alert 요약 — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}")
    print(f"총 alert 수: {len(alerts)}")

    sev_count = {}
    for a in alerts:
        s = a["severity"]
        sev_count[s] = sev_count.get(s, 0) + 1
    print(f"\nSeverity 분포:")
    for s in sorted(sev_count.keys()):
        label = {1: "높음", 2: "중간", 3: "낮음"}.get(s, "기타")
        print(f"  Severity {s} ({label}): {sev_count[s]}건")

    sig_count = {}
    for a in alerts:
        sig = a["signature"]
        sig_count[sig] = sig_count.get(sig, 0) + 1
    print(f"\n상위 시그니처:")
    for sig, count in sorted(sig_count.items(), key=lambda x: -x[1])[:10]:
        print(f"  [{count}건] {sig}")

    country_count = {}
    for a in alerts:
        c = a.get("src_country") or "Unknown"
        country_count[c] = country_count.get(c, 0) + 1
    print(f"\nSource 국가:")
    for c, count in sorted(country_count.items(), key=lambda x: -x[1]):
        print(f"  {c}: {count}건")

    print(f"\n{'='*60}")


if __name__ == "__main__":
    import sys

    print("ES에서 최근 alert 가져오는 중 ...")
    alerts = get_recent_alerts(minutes=1440)

    # 터미널 출력
    console_report(alerts)

    # --discord 옵션으로 Discord 전송
    if "--discord" in sys.argv:
        msg = summarize_alerts(alerts)
        send_discord(msg)
