---
name: alert-triage
description: "Triage Suricata IDS alerts from Elasticsearch. Query recent alerts, classify severity, map to MITRE ATT&CK with explicit source attribution, and summarize findings. Send results to Discord."
version: 1.3.0
author: taekgyun
platforms: [linux]
---

# SOC Alert Triage

Analyze Suricata IDS alerts stored in Elasticsearch and provide security triage.

## When to Use

- User asks to analyze, triage, or review IDS/Suricata alerts
- User asks about recent network security events or threats
- User mentions SOC, alert analysis, or MITRE ATT&CK mapping
- User asks "what alerts do we have" or similar
- User asks to send alert report to Discord

## Procedure

1. Load the MITRE ATT&CK mapping reference:
   - Read `references/mitre-mapping.md` in this skill directory
   - This table is **operator-defined, NOT official ET ruleset metadata**. It documents the
     rationale and limitations behind each mapping. Read the rationale, not just the technique ID.
   - Mapping source priority. Always label the source in the output:
     1. `[ET 룰셋 태그]` — alert data contains `mitre_technique_id` from rule metadata.
        Use it verbatim. Never override it with inference.
     2. `[운영자 정의]` — the signature pattern exists in `references/mitre-mapping.md`
     3. `[추론 기반]` — neither of the above. LLM inference. Lowest confidence.
   - Before raising severity, check the "상향 판단 조건" documented for that mapping.
     Only escalate when those conditions are actually met.
   - Respect the documented limitations. Do not claim a technique this sensor cannot observe
     (see the coverage table at the end of `references/mitre-mapping.md`).

2. Query Elasticsearch for recent Suricata alerts:
```bash
   curl -s 'http://<TS_IP_ES>:9200/filebeat-*/_search' \
     -H 'Content-Type: application/json' \
     -d '{
       "size": 50,
       "sort": [{"@timestamp": "desc"}],
       "query": {
         "bool": {
           "must": [
             {"term": {"event.kind": "alert"}}
           ]
         }
       },
       "_source": ["@timestamp", "suricata.eve.alert.signature", "suricata.eve.alert.metadata", "event.severity", "suricata.eve.alert.category", "source.ip", "source.geo.country_iso_code", "destination.ip", "source.port", "destination.port", "network.protocol"]
     }'
```
   - Severity lives at `event.severity` (ECS), not `suricata.eve.alert.severity`.
     The Filebeat Suricata module renames it. Verified 2026-09-01.
   - `suricata.eve.alert.metadata` may contain `mitre_technique_id` for rules that carry the tag.
     Currently 0 documents in this environment have it, but query it anyway so official tags
     are picked up automatically once such a rule fires.

3. Parse the JSON results and group alerts by signature and severity.

4. For each unique alert type, assess:
   - Check `mitre_technique_id` in the alert metadata first. If present, use it.
   - Otherwise match against the operator-defined mapping table.
   - Is it likely a true positive or false positive?
   - What is the recommended action?

5. Classify severity:
   - **Critical**: Active exploitation, C2 communication, data exfiltration
   - **High**: Successful scanning, brute force, known CVE triggers
   - **Medium**: Suspicious but inconclusive traffic patterns
   - **Low/Info**: Benign anomalies, protocol violations, DHCP noise

6. Present results:
   - Summary table: Signature | Count | Severity | Verdict | MITRE ATT&CK | Mapping Source | Action
   - "Mapping Source" column: one of `[ET 룰셋 태그]`, `[운영자 정의]`, `[추론 기반]`
   - Detailed analysis for Medium severity and above only
   - Output in Korean

7. Send results to Discord:
   - Send the SAME full analysis from step 6 to the Discord webhook
   - Do NOT create a separate shortened summary
   - Do NOT use emoji icons in any output (terminal or Discord)
   - If the message exceeds 2000 characters, split into multiple sequential messages at natural section breaks
   - The webhook URL is stored in `/etc/soc-monitor.env` as `DISCORD_WEBHOOK_URL`.
     Never hardcode it. Load it first:
```bash
     source /etc/soc-monitor.env
     curl -H "Content-Type: application/json" \
       -d '{"content": "<MESSAGE CHUNK>"}' \
       "$DISCORD_WEBHOOK_URL"
```
   - Confirm HTTP 204 response for each chunk
   - Only send to Discord when the user explicitly asks

## Pitfalls

- Most alerts at severity 3 are false positives (DHCP truncated options, TCPv4 invalid checksum,
  IKEv2 invalid proposal). Do not escalate these without corroborating evidence.
- **HOME_NET is a single public IP (/32), not a private range.** The sensor sits outside NAT on the
  ISP segment. Every alert therefore has the same destination IP, and individual internal hosts
  cannot be distinguished. Do not attempt per-host attribution.
- The public IP is dynamic and rotates. Do not treat a specific address as a fixed identifier.
- Traffic addressed to neighboring hosts on the same ISP segment is also captured.
  If the destination is not the monitored public IP, classify it as neighbor-directed traffic
  and lower the suspicion level.
- Elasticsearch index pattern is `filebeat-*`. Do not query other indices.
- The ES instance has no authentication (xpack.security=false).
- Do NOT invent MITRE ATT&CK mappings. If the signature is not in the reference table and you are
  not confident, mark it as "미분류" rather than guessing.
- `GPL ATTACK_RESPONSE id check returned root` also fires on the operator's own test traffic
  (testmyids.com). Check the source and timing before declaring a compromise.
- Discord message limit is 2000 characters. Split rather than truncate.

## Verification

- Confirm Elasticsearch is reachable: `curl -s http://<TS_IP_ES>:9200/_cluster/health`
- Confirm alert data exists: check that the query returns hits with `hits.total.value > 0`
- Confirm Discord webhook works: check for HTTP 204 response after sending
- Cross-reference any suspicious external IPs with threat intelligence if available
