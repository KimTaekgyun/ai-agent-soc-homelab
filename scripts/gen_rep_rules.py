#!/usr/bin/env python3
"""ET 평판 룰(들어오는 방향)을 '집 -> 명단'(나가는 방향)으로 뒤집어 local-rep.rules를 만든다.
명단 하나당 룰 2개 (10-21 rev2):
  A) ICMP 외 전부: flow:to_server + ip_proto:!1
  B) ICMP: itype:8 (ping 요청)만
  이유: 10-20 오탐 - 밖에서 온 GRE에 공유기가 ICMP 오류로 응답한 것이 'to_server'로 잡힘.
       Suricata가 GRE와 그 ICMP 응답을 한 연결로 묶지 못함. ICMP 오류(type 3, 11 등)는 항상 응답이라 제외.
SID: A = ET SID - 1,400,000(평판) / - 1,300,000(COMPROMISED), B = A + 10,000
  평판 A 1000000~1003999, B 1010000~1013999 / COMPROMISED A 1200000~1200999, B 1210000~1210999
suricata-update 후 다시 실행할 것. 2026-10-19 자작 룰 1, 10-20 COMPROMISED, 10-21 ICMP 분리."""
import os, re, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/var/lib/suricata/rules/suricata.rules"
DST = sys.argv[2] if len(sys.argv) > 2 else "/etc/suricata/rules/local-rep.rules"
RANGES = [(2400000, 2403999, 1400000), (2500000, 2500999, 1300000)]
ICMP_OFFSET = 10000
MIN_LISTS = 300  # 명단(ET 룰)이 이보다 적게 뽑히면 원본 형식이 바뀐 것 -> 기존 파일 유지

pat = re.compile(r'^alert ip \[([^\]]+)\] any -> \$HOME_NET any \(msg:"([^"]+)";.*?sid:(\d+);')
sid_re = re.compile(r'^alert .*sid:(\d+);')
COMMON = 'threshold: type limit, track by_dst, count 1, seconds 3600; classtype:bad-unknown;'

def offset(sid):
    for lo, hi, off in RANGES:
        if lo <= sid <= hi:
            return off
    return None

out, n_lists, n_range, n_ip, per = [], 0, 0, 0, {}
with open(SRC, encoding="utf-8", errors="replace") as f:
    for line in f:
        m0 = sid_re.match(line)
        if not m0 or offset(int(m0.group(1))) is None:
            continue
        n_range += 1
        m = pat.match(line)
        if not m:
            print(f"[WARN] 형식 불일치, 건너뜀: {line[:120]}", file=sys.stderr)
            continue
        ips, msg, sid = m.group(1), m.group(2), int(m.group(3))
        off = offset(sid); base = sid - off
        per[off] = per.get(off, 0) + 1
        n_lists += 1
        n_ip += ips.count(",") + 1
        out.append(f'alert ip $HOME_NET any -> [{ips}] any (msg:"LOCAL Outbound to IP listed in {msg}"; '
                   f'flow:to_server; ip_proto:!1; {COMMON} sid:{base}; rev:2;)')
        out.append(f'alert icmp $HOME_NET any -> [{ips}] any (msg:"LOCAL Outbound ICMP echo to IP listed in {msg}"; '
                   f'itype:8; {COMMON} sid:{base + ICMP_OFFSET}; rev:1;)')

print(f"범위 내 ET 룰 {n_range}개 중 명단 {n_lists}개 → 룰 {len(out)}개 (평판 {per.get(1400000,0)}, COMPROMISED {per.get(1300000,0)}), IP/대역 {n_ip}개")
if n_lists < MIN_LISTS:
    sys.exit(f"[ERROR] 명단 {n_lists}개 < {MIN_LISTS} - 기존 {DST} 유지, 중단")

tmp = DST + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write("# 자동 생성: /root/soc/gen_rep_rules.py (직접 수정 금지, 다시 생성됨)\n")
    f.write("\n".join(out) + "\n")
os.replace(tmp, DST)
print(f"저장: {DST}")
