#!/bin/bash
# 매일 ET 룰 갱신 → 자작 평판 룰 재생성 → 문법 검사 → 재시작 (2026-10-20)
# 어느 단계든 실패하면 멈춤(set -e): 돌고 있는 Suricata는 이전 룰로 계속 동작
set -e
echo "=== $(date '+%F %T')"
suricata-update 2>&1 | grep -E "Writing rules|Error|Warning" || true
python3 /root/soc/gen_rep_rules.py
suricata -T -c /etc/suricata/suricata.yaml > /tmp/update_t.log 2>&1
systemctl restart suricata
sleep 40
grep "rules successfully loaded" /var/log/suricata/suricata.log | tail -1
