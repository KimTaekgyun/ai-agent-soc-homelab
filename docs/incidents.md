# 사고·장애 기록

시각은 KST. 집 공인 IP는 `HOME_IP`, 내부 주소와 외부 출발지 IP는 일부를 가렸다.

## 목록

| 사례 | 기간 | 무엇이 일어났나 | 배운 점 |
|---|---|---|---|
| A. 수집기 S3 403 | 2026-10 초 | AWS 수집기의 S3 접근 403을 권한 부족으로 오판해 정책을 수정했으나 해결 안 됨 → 정책 시뮬레이터로 권한 정상 확인 → CloudTrail 원본에서 실패 요청이 `accountId: anonymous`(서명 없는 요청)임을 찾아 자격증명 로딩 방식으로 원인 특정 → Filebeat 키스토어로 전환 | 403을 권한 부족으로 단정하지 말고, 실패한 요청의 주체부터 감사 로그로 확인 |
| B. ES 조회 상한 | 10-10 | watcher 주기를 6시간으로 늘린 뒤 ES 조회 상한(500)에 걸려 6시간 분량 alert의 약 67%가 조용히 버려짐 | 조용한 누락은 "딱 떨어지는 숫자"로 드러난다 |
| C. LLM 전송 상한 | 10월 | 1층 필터를 통과한 alert의 59%가 LLM 분석 없이 넘어감 | 상한은 "넘치지 않게"가 아니라 "넘치면 알리게" |
| D. Realtek 명령 주입 시도 | 10-12 | 아래 상세 | UDP와 TCP에서 "응답 0"의 무게가 다르다 |
| E. 잊혀진 포트포워딩 3개 | 10-15 | 아래 상세 | 설정은 기억이 아니라 화면으로 확인 |
| F. 룰셋 미갱신 | 10월 | 자작 룰 작업 중 ET 룰셋이 두 달간 갱신되지 않은 것을 발견 → 단독 변경으로 갱신(추가 1,000 / 삭제 94 / 변경 7,245룰), 매일 자동 갱신(실패 시 중단). 전후 24시간: 평판 alert를 일으킨 룰 217 → 311개(일별 스캔량 변동은 배제 못 함) | 탐지 품질은 룰을 만드는 것보다 유지하는 데서 갈린다 |
| G. 분석 서버 이전 | 10-20 | 오라클 → AWS EC2. 임시 SSH → Tailscale 접속 확인 → 재부팅 후 재확인 → 인바운드 0 → 양쪽 끝단 검증 순으로 노출 최소화 | 닫았다고 말하지 말고 닫힌 걸 검증 |
| H. 자작 룰 첫 실전 오탐 | 10-20 | 평판 아웃바운드 룰 첫 alert. 같은 순간 해당 IP가 집으로 GRE를 보냈고 공유기가 ICMP 오류로 응답 → Suricata가 프로토콜이 다른 응답을 같은 연결로 묶지 못해 "집이 시작한 연결"로 판단 → 룰을 ICMP 외 / ping 요청으로 분리(rev 2) | 운영 데이터가 설계의 빈틈을 찾아준다. 룰은 배포가 끝이 아니라 시작 |

---

## 사례 D. Realtek 익스플로잇 시도 트리아지 (2026-10-12)

### 타임라인

| 시각 | 무엇 | 근거 |
|---|---|---|
| 10-12 02:09:00 | 외부 IP(45.135.x.x) → HOME_IP 9034/udp 패킷 1개. sid 2044008(Realtek SDK CVE-2021-35394, 등급 1)과 sid 2400006(Spamhaus, 등급 2) 동시 발화 | alert 2건, 같은 `flow_id` |
| 10-12 02:09:50 | 같은 연결의 flow 기록 종료(`timeout`) | flow 기록 |
| 10-12 03:00 | watcher 실행. Spamhaus 쪽은 1층에서 제외, Realtek 쪽은 LLM으로 → "높음" 판정, "9034/tcp"로 기재 | Discord 리포트 |
| 10-12 14:39~48 | flow 확인 → alert 원문 확인 → 전후 1시간 집계 | 아래 조사 |

### 질문과 답

1. **응답이 나갔나?** 아니오. 나간 패킷 0, ICMP 응답도 없음
2. **그것만으로 종결 가능한가?** 아니오. UDP라 handshake 없이 첫 패킷에 공격 내용이 이미 도착했고, 명령 주입은 응답 없이 실행될 수 있음
3. **공격 뒤 집에서 새로운 행동이 생겼나?** 전후 비교상 없음
4. **패킷을 받을 수 있었던 장비는?** 센서에는 목적지가 공인 IP로만 보이지만, 들어오는 패킷의 수신 장비는 공유기 규칙표가 정함. 당시 규칙에 9034가 없고 DMZ도 꺼져 있었음 → 도착할 수 있었던 곳은 공유기 자신뿐. 응답·ICMP가 0이라 듣지 않았거나 조용히 버린 것으로 보임
   - NAT 바깥 센서의 "내부 기기 구분 불가" 한계는 주로 나가는 트래픽에 해당. 들어오는 트래픽은 센서 로그와 공유기 설정을 맞춰서 수신 장비를 좁힐 수 있음

### 조사 D-1. flow 기록 (KQL, 10-12 02:00 ~ 02:30)

```
source.ip : "<공격 IP>" or destination.ip : "<공격 IP>"
```

결과 3건(alert 2, flow 1). flow 핵심 필드: `network.transport: udp`, `source.packets: 1`, `source.bytes: 370`, **`destination.packets: 0`, `destination.bytes: 0`**, `flow.reason: timeout`. 양방향 질의인데 3건뿐이므로 ICMP 응답도 없음.

### 조사 D-2. alert 원문

- 두 alert의 `flow_id`가 같음 → 같은 패킷에 룰 2개가 걸림
- sid 2044008 메타데이터: `confidence: High`, `CISA_KEV`, `attack_target: Networking_Equipment`
- 페이로드 필드 없음 → eve에 페이로드 기록이 꺼져 있어 주입 명령 확인 불가

### 조사 D-3. 집 출발 트래픽 목록 조회 (시행착오)

집 출발 alert·http·fileinfo를 1시간 범위로 조회 → 3,926건. 평소 규모를 모르는 상태에서 목록 조회는 쓸모가 없어 집계로 전환.

### 조사 D-4. 전후 1시간 비교 (ES|QL)

```
FROM filebeat-*
| WHERE @timestamp >= TO_DATETIME("2026-10-11T16:09:00Z") AND @timestamp < TO_DATETIME("2026-10-11T18:09:00Z")
| WHERE source.ip == TO_IP("<HOME_IP>")
| WHERE suricata.eve.event_type IN ("alert", "http", "fileinfo") OR destination.port == 69
| EVAL period = CASE(@timestamp < TO_DATETIME("2026-10-11T17:09:00Z"), "1_before", "2_after")
| STATS n = COUNT(*) BY period, suricata.eve.event_type, rule.name
| SORT rule.name, period
| LIMIT 100
```

ES|QL도 Kibana 화면 시간 범위로 한 번 더 걸러지므로 화면 범위를 전후 2시간으로 넓혀야 함(처음엔 좁게 둬서 `1_before`가 안 나왔음).

| 항목 | 전 1시간 | 후 1시간 |
|---|---|---|
| STUN Binding Request | 2,504 | 2,597 |
| Go HTTP 클라이언트 룰 2종 (각각) | 420 | 425 |
| `http` 전체 | 434 | 439 |
| `http` 중 Go 클라이언트 외 | 14 | 14 |
| ipify 조회 (TLS / DNS) | 6 / 12 | 6 / 12 |
| Applayer wrong direction | 5 | 22 |
| TFTP, fileinfo, 처음 보는 룰 | 0 | 0 |

공격 뒤에만 나타난 유형 없음. Applayer 5 → 22는 스트림 이상 계열이라 공격 행동 지표로 보지 않음(평소 변동 폭은 미확인).

### 판정과 한계

- **판정:** 침해 시도, 침해 징후 없음. 무차별 봇 살포로 추정
- **한계:** 페이로드 미기록, HTTPS 후속 통신과 공격 후 1시간 밖은 미확인, 공유기 칩셋이 Realtek SDK 기반인지 미확인
- **LLM 검증:** LLM이 "9034/tcp"라고 썼으나 실제 UDP. watcher가 프로토콜 필드를 LLM에 보내지 않아서 생긴 추정값

---

## 사례 E. 잊혀진 포트포워딩 노출 발견과 봉쇄 (2026-10-15)

### 발견 경위

사례 D의 표적(공유기)을 확인하려고 관리 화면을 열었다가 "원격 관리 포트 사용" 표시를 보고, 포트포워드 설정 화면에서 사용자 규칙 3개를 확인했다. 사례 D 조사 당시에는 "포트포워딩 없음"을 기억에 의존해 판단했었다.

| 규칙 | 프로토콜 | 외부 포트 | 노출된 것 |
|---|---|---|---|
| 공유기 관리자 | TCP | 4301 | 공유기 관리 페이지 |
| proxmox | TCP | 8006 | Proxmox 관리 화면 |
| proxmox 100번 | TCP | 222 | SSH (내부 주소는 예전 기기, 현재 기기 없음) |
| UPnP: tailscale-portmap | UDP | (자동) | Tailscale 연결 보조. 정상, 유지 |

- 만든 이유: Tailscale을 쓰기 전, "원격 접속하려면 포트포워딩을 해야 한다"고 생각해서 설정함
- 근본 원인: 원격 접속 방식을 Tailscale로 바꾼 뒤 예전 경로를 정리하지 않음. 자산(공유기 설정)을 주기적으로 점검하는 절차가 없었음

### 봉쇄

- 사용자 규칙 3개 삭제. Tailscale로 원격 접속이 되므로 잃는 기능 없음
- 순서: 조사보다 봉쇄를 먼저 함. 규칙을 지워도 ES 로그는 남으므로 조사에 지장 없음

### 조사 E-1. 포트별 접근 집계 (ES|QL, 최근 30일)

```
FROM filebeat-*
| WHERE @timestamp >= NOW() - 30 days
| WHERE destination.ip == TO_IP("<HOME_IP>") AND destination.port IN (4301, 8006, 222)
| WHERE suricata.eve.event_type == "flow"
| STATS flows = COUNT(*), sources = COUNT_DISTINCT(source.ip), answered = SUM(CASE(destination.packets > 0, 1, 0)), max_bytes_back = MAX(destination.bytes) BY destination.port
```

| 포트 | 연결 | 출발지 | 응답 나간 연결 | 최대 응답 바이트 |
|---|---|---|---|---|
| 222 | 145 | 97 | 145 | 258 |
| 8006 | 136 | 90 | 136 | 344 |
| 4301 | 160 | 148 | 159 | 2,635 |

SSH는 암호화 협상만 해도 1KB를 넘고, HTTPS는 서버 인증서만 해도 보통 1KB를 넘는다. 222·8006은 로그인 단계에 가지 못한 것으로 판단(바이트 기준은 추정). 4301은 페이지 하나 크기라 추가 조사.

### 조사 E-2. 4301 HTTP 요청 내용 (ES|QL, 최근 30일)

```
FROM filebeat-*
| WHERE @timestamp >= NOW() - 30 days
| WHERE destination.ip == TO_IP("<HOME_IP>") AND destination.port == 4301
| WHERE suricata.eve.event_type == "http"
| STATS n = COUNT(*), sources = COUNT_DISTINCT(source.ip) BY http.request.method, url.original, http.response.status_code
| SORT n DESC
| LIMIT 50
```

| 요청 | 건수 = 출발지 수 | 응답 |
|---|---|---|
| GET / | 35 | 200 |
| GET /favicon.ico | 19 | 404 |
| GET /sse, /mcp, /mcp/, /api/mcp | 15, 15, 15, 14 | 404 |
| RDP 접속 요청이 HTTP로 파싱됨 | 1 | 없음 |

**POST 0건** → 로그인 시도 없음. 모든 줄에서 건수 = 출발지 수 → 한 IP가 한 번씩 온 무차별 스캔. MCP(AI 에이전트 도구 서버) 경로를 찾는 스캔이 이 포트에서 관찰됨.

### 판정과 한계

- **판정:** 30일 기록 안에서 침입 흔적 없음
- **한계:** HTTP 요청 기록 114건 vs 연결 160건(나머지는 요청 없이 끊은 것으로 추정). 30일 이전 기록은 ILM으로 삭제되어 노출 기간 전체는 확인 불가. 호스트 쪽 로그(Proxmox 접속 기록 등)는 보지 않음

### 후속 조치

- 공유기 원격 관리 해제, 관리자 비밀번호 변경
- 공유기 펌웨어 업그레이드 후 원격 관리·DMZ 꺼짐, Tailscale 장비 접속 재확인
