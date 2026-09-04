---
name: alert-triage
description: "Triage Suricata IDS alerts from Elasticsearch. Query recent alerts, classify severity, map to MITRE ATT&CK, and summarize findings. Send results to Discord."
version: 1.2.0
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
   - Read `references/mitre-mapping.md` in this skill directory for the signature-to-ATT&CK mapping table
   - Use this table as the primary mapping source; only use LLM inference for signatures not in the table
   - When using LLM inference, mark the mapping as "추론 기반"

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
       "_source": ["@timestamp", "suricata.eve.alert.signature", "suricata.eve.alert.severity", "suricata.eve.alert.category", "source.ip", "destination.ip", "source.port", "destination.port", "network.protocol"]
     }'
```

3. Parse the JSON results and group alerts by signature and severity.

4. For each unique alert type, assess:
   - Match against the MITRE ATT&CK mapping table first
   - Is it likely a true positive or false positive?
   - What is the recommended action?

5. Classify severity:
   - **Critical**: Active exploitation, C2 communication, data exfiltration
   - **High**: Successful scanning, brute force, known CVE triggers
   - **Medium**: Suspicious but inconclusive traffic patterns
   - **Low/Info**: Benign anomalies, protocol violations, DHCP noise

6. Present results:
   - Summary table: Signature | Count | Severity | Verdict | MITRE ATT&CK | Mapping Source | Action
   - "Mapping Source" column: "테이블" (from reference) or "추론" (LLM inference)
   - Detailed analysis for Medium severity and above only
   - Output in Korean

7. Send results to Discord:
   - Send the SAME full analysis from step 6 to the Discord webhook
   - Do NOT create a separate shortened summary
   - Do NOT use emoji icons in any output (terminal or Discord)
   - If the message exceeds 2000 characters, split into multiple sequential messages at natural section breaks
   - Use this command for each message chunk:
```bash
     curl -H "Content-Type: application/json" \
       -d '{"content": "<MESSAGE CHUNK>"}' \
       "https://discord.com/api/webhooks/<id>/<token>"
```
   - Confirm HTTP 204 response for each chunk
   - Only send to Discord when the user explicitly asks
## Pitfalls

- Most alerts at severity 3 are false positives (DHCP truncated options, TCPv4 invalid checksum, IKEv2 invalid proposal). Do not escalate these without corroborating evidence.
- HOME_NET is 192.168.1.0/24. External IPs outside this range are not necessarily malicious.
- Elasticsearch index pattern is `filebeat-*`. Do not query other indices.
- The ES instance has no authentication (xpack.security=false).
- Do NOT invent MITRE ATT&CK mappings. If the signature is not in the reference table and you are not confident, mark as "미분류".
- Discord message limit is 2000 characters. Truncate or split if necessary.

## Verification

- Confirm Elasticsearch is reachable: `curl -s http://<TS_IP_ES>:9200/_cluster/health`
- Confirm alert data exists: check that the query returns hits with `hits.total.value > 0`
- Confirm Discord webhook works: check for HTTP 204 response after sending
- Cross-reference any suspicious external IPs with threat intelligence if available
