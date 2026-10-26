#!/usr/bin/env python3
"""
eval_replay.py — 같은 alert 묶음을 '도구 없음'과 '조사 도구'로 각각 돌려 결과를 파일로 남긴다.
Discord로 보내지 않고, watcher_state.json(쿨다운·일일 상한)도 건드리지 않는다.
(수동 실행이 다음 cron의 pass를 낮추던 문제를 피하려고 watcher를 직접 돌리지 않음)

사용:
  1) 표본 목록 CSV(헤더: ts,sid,src_ip)로 ES에서 alert를 다시 꺼내 묶음 파일 생성
       python3 eval_replay.py build sample.csv batch.json
  2) 세 방식으로 실행
       python3 eval_replay.py run batch.json out/
     → out/A0_no_memory_no_tools.txt, out/A_memory_no_tools.txt, out/B_memory_tools.txt, out/summary.json
  A0 실행 동안만 ~/.hermes/memories/MEMORY.md를 잠시 치웠다가 되돌린다(cron 시각 앞뒤 15분은 실행 거부).
  토큰 사용량은 Anthropic 콘솔의 요청별 사용량에서 두 실행 시각으로 확인한다.

같은 묶음을 쓰는 이유: 입력이 다르면 차이가 도구 때문인지 입력 때문인지 구분할 수 없다.
"""
import csv, json, os, sys, time
sys.path.insert(0, os.path.expanduser("~/soc-triage"))
import watcher  # noqa: E402  (같은 폴더의 watcher.py: fetch 필드·프롬프트·Hermes 호출을 그대로 재사용)


def build(csv_path, out_path):
    batch, missing = [], []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            body = {"size": 1, "query": {"bool": {"filter": [
                {"term": {"suricata.eve.alert.signature_id": int(row["sid"])}},
                {"term": {"source.ip": row["src_ip"]}},
                {"range": {"@timestamp": {"gte": f"{row['ts']}||-2m", "lte": f"{row['ts']}||+2m"}}},
            ]}}}
            hits = watcher.es_search(body)["hits"]["hits"]
            if not hits:
                missing.append(row)
                continue
            s = hits[0]["_source"]
            d = watcher.dig
            batch.append({
                "ts": s.get("@timestamp"), "sid": d(s, "suricata", "eve", "alert", "signature_id"),
                "signature": d(s, "suricata", "eve", "alert", "signature") or "",
                "severity": d(s, "event", "severity") or 3,
                "category": d(s, "suricata", "eve", "alert", "category") or "",
                "src_ip": d(s, "source", "ip"), "src_geo": d(s, "source", "geo", "country_iso_code"),
                "dest_ip": d(s, "destination", "ip"), "dest_port": d(s, "destination", "port"),
                "flow_id": d(s, "suricata", "eve", "flow_id"),
            })
    json.dump(batch, open(out_path, "w"), ensure_ascii=False, indent=1)
    print(f"묶음 {len(batch)}건 저장, ES에서 못 찾은 표본 {len(missing)}건 (ILM 30일 삭제 여부 확인)")
    for m in missing:
        print("  missing:", m)


MEMORY = os.path.expanduser("~/.hermes/memories/MEMORY.md")
MEMORY_OFF = MEMORY + ".eval-off"
CRON_HOURS_UTC = (0, 6, 12, 18)   # watcher cron 0 */6 * * *


def near_cron(margin_min=15):
    """기억을 치운 동안 cron watcher가 돌면 운영 리포트가 기억 없이 나간다 → 그 시간대엔 실행 거부."""
    t = time.gmtime()
    mins = t.tm_hour * 60 + t.tm_min
    return any(abs(mins - h * 60) <= margin_min or abs(mins - h * 60 - 1440) <= margin_min
               for h in CRON_HOURS_UTC)


def run(batch_path, out_dir):
    """세 갈래: 기억·도구 효과를 나누려면 하나씩만 바꿔야 한다.
      A0 기억X 도구X (10-22까지의 방식) / A 기억O 도구X (기억의 효과) / B 기억O 도구O (조사 도구의 효과)"""
    if near_cron():
        sys.exit("cron 실행 시각(UTC 0·6·12·18시) 앞뒤 15분이라 중단. A0 동안 기억 파일을 치우기 때문")
    if os.path.exists(MEMORY_OFF):
        sys.exit(f"{MEMORY_OFF}가 남아 있음. 이전 실행이 비정상 종료됐을 수 있으니 직접 되돌린 뒤 실행")
    batch = json.load(open(batch_path))
    os.makedirs(out_dir, exist_ok=True)
    summary = {}
    for name, memory, tools in (("A0_no_memory_no_tools", False, False),
                                ("A_memory_no_tools", True, False),
                                ("B_memory_tools", True, True)):
        watcher.TRIAGE_TOOLS = tools
        moved = False
        try:
            if not memory:
                os.rename(MEMORY, MEMORY_OFF)   # 파일은 444지만 이름 변경은 폴더 권한이라 가능
                moved = True
            t0 = time.time()
            started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            report = watcher.llm_triage(batch)
        finally:
            if moved:
                os.rename(MEMORY_OFF, MEMORY)   # 실패해도 반드시 되돌림
        summary[name] = {"started_utc": started, "seconds": round(time.time() - t0, 1),
                         "alerts": len(batch), "memory": memory, "tools": tools}
        open(os.path.join(out_dir, name + ".txt"), "w").write(report)
        print(name, summary[name])
    assert os.path.exists(MEMORY) and not os.path.exists(MEMORY_OFF), "기억 파일 복구 확인 필요"
    json.dump(summary, open(os.path.join(out_dir, "summary.json"), "w"), indent=1)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "build":
        build(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "run":
        run(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
