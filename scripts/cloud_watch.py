#!/usr/bin/env python3
"""cloud_watch.py — 클라우드 감사 로그 무력화 탐지 (2026-10-20, 클라우드 룰 1)
대상: CloudTrail StopLogging / DeleteTrail (ATT&CK T1562.008)
- LLM 없이 결정적으로 판정: 판단이 필요 없는 확실한 신호라 비용·지연 없이 즉시 알림
- cron 15분 주기 (watcher 6시간 주기와 분리. 수집 지연 실측 약 10분)
- 조회 기준은 이벤트 시각(@timestamp)이 아니라 ES 도착 시각(event.ingested):
  전달이 늦게 와도 '새로 들어온 것'은 놓치지 않음
- 같은 이벤트(event.id)는 한 번만 알림 (state 파일)
환경변수: DRY_RUN=1 이면 Discord 대신 화면 출력, WINDOW_MIN 으로 조회 구간 변경(기본 30)
"""
import json, os, time
from watcher import load_webhook, es_search, send_discord, dig

ACTIONS = ["StopLogging", "DeleteTrail"]
WINDOW_MIN = int(os.environ.get("WINDOW_MIN", "30"))   # 15분 주기 + 겹침
DRY_RUN = os.environ.get("DRY_RUN") == "1"
STATE_FILE = os.path.expanduser("~/soc-triage/cloud_watch_state.json")
KEEP_SEC = 2 * 24 * 3600

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_state(st):
    with open(STATE_FILE, "w") as f:
        json.dump(st, f)

def fetch():
    body = {
        "size": 50,
        "sort": [{"event.ingested": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"term": {"event.dataset": "aws.cloudtrail"}},
            {"term": {"event.provider": "cloudtrail.amazonaws.com"}},
            {"terms": {"event.action": ACTIONS}},
            {"range": {"event.ingested": {"gte": f"now-{WINDOW_MIN}m"}}},
        ]}},
    }
    return [h["_source"] for h in es_search(body)["hits"]["hits"]]

def fmt(s):
    return (f"[CLOUD ALERT] CloudTrail 로그 {dig(s,'event','action')} ({dig(s,'event','outcome')})\n"
            f"- 주체: {dig(s,'user','name')} ({dig(s,'aws','cloudtrail','user_identity','type')})\n"
            f"- 출발지: {dig(s,'source','address')} / 리전: {dig(s,'cloud','region')}\n"
            f"- 이벤트 시각(UTC): {s.get('@timestamp')} / SIEM 도착: {dig(s,'event','ingested')}\n"
            f"- ATT&CK: T1562.008 (클라우드 로그 비활성화)\n"
            f"- 확인: 본인 작업인가? 아니면 즉시 StartLogging, 해당 자격증명 비활성화, 같은 주체의 다른 활동 조회")

def main():
    now = time.time()
    st = {k: v for k, v in load_state().items() if now - v < KEEP_SEC}
    try:
        events = fetch()
    except Exception as e:
        print(f"[ERROR] {time.strftime('%m-%d %H:%M:%S')} ES 조회 실패: {e}")  # ES 장애는 watcher 데드맨이 알림
        return
    new = 0
    for s in events:
        key = dig(s, "event", "id") or f"{s.get('@timestamp')}|{dig(s,'event','action')}"
        if key in st:
            continue
        msg = fmt(s)
        if DRY_RUN:
            print(msg + "\n")
        else:
            send_discord(load_webhook(), msg)
            st[key] = now   # 실제로 보낸 것만 기록
        new += 1
    if not DRY_RUN:
        save_state(st)
    print(f"[INFO] {time.strftime('%m-%d %H:%M:%S')} window={WINDOW_MIN}m found={len(events)} new={new} dry_run={DRY_RUN}")

if __name__ == "__main__":
    main()
