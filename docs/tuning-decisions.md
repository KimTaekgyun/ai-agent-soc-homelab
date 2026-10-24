# ET Open 튜닝 결정표 (1회차, 2026-10-15 ~ 10-16)

대상: Suricata ET Open 룰셋, 30일 alert(2026-09-15 ~ 10-15) 상위 룰.
건수는 30일 기준, 방향은 집 공인 IP 기준(out = 집 → 밖, in = 밖 → 집).

## 요약

- 30일 alert 약 430만 건 중 99% 가까이가 **SOC 자신의 구성 요소**(Tailscale, 공인 IP 감시 스크립트)가 만든 것
- **실제 변경 1건: Tailscale 중계 서버(DERP) 대상 alert 억제(suppress)** — 룰 4개(2016149, 2016150, 2024897, 2060251). 룰은 계속 돌고, DERP IP 88개에 대해서만 alert를 남기지 않음
  - 억제 전 7일: 4개 룰 1,096,008건, **전부 DERP 대상(그 외 0건)** → 하루 약 15만 건
  - **20시간 재측정:** 억제 전 7일(168시간) vs 억제 후 20.1시간
    - 4개 룰: 시간당 6,531건 → **0건**
    - 나머지 룰: 시간당 293건 → 277건 (센서·파이프라인 정상, 다른 탐지는 그대로)
    - 전체: 하루 약 16.4만 건 → 약 6,700건, **95.9% 감소**
    - 주의: 같은 날 전원 재시작·GRO 재설정이 겹침 → 나머지 룰의 작은 변화는 원인 단정 안 함. 억제 효과는 4개 룰만으로 판단
  - 억제 후 이 4개 룰에서 alert가 나오면 = Tailscale이 아닌 STUN/Go 통신이라는 신호
- 끈(disable) 룰: 0개. 나머지는 근거와 재검토 조건을 남기고 유지
- **watcher 1층 필터를 이름 일부 매칭 → SID 범위로 변경 (10-17)**
  - 이유: 이름 매칭은 같은 단어가 든 진짜 위협 룰까지 버림(미탐), 룰 이름이 바뀌면 조용히 안 먹음
  - 발견: 패턴 8개 중 5개(dhcp, ikev2, checksum, tcp option invalid, header length too small)는 등급 3 룰에만 걸림 → watcher는 등급 2 이하만 가져오므로 **원래 아무 일도 안 하던 코드**. 실제로 거르던 건 평판 3종뿐
  - 범위: Spamhaus 2400000~2400999, Dshield 2402000~2402999, CINS 2403300~2403999. 근거: 센서의 `suricata.rules`에서 2400000~2403999엔 이 3종만 존재(Spamhaus 68개, Dshield 1개, CINS 299개)
  - 30일 데이터로는 Spamhaus 34개, CINS 276개만 울림 → 울린 SID만 적었다면 나머지는 놓쳤을 것. 그래서 룰 파일과 대조
  - SID를 못 읽으면 통과(보이는 쪽으로 실패). 단점: 범위 밖 번호로 같은 계열이 추가되면 watcher로 넘어옴(낭비지만 미탐은 아님)
  - 검증: 같은 6시간 alert 1,435건에 옛/새 필터 적용 → 둘 다 FP 1,404건, 차이 0건
- 찾은 빈칸: 평판 룰은 들어오는 방향만 봄 → **집 → 평판 나쁜 IP 방향은 ET Open이 보지 않음** (자작 룰 1의 출발점)
- 저장 비용 근거: ES 인덱스 전체 30일 14.1GB, 디스크 사용 34%(10-15)

## 결정표

| SID | 룰 | 30일 건수 | 등급 | 방향 | 출처 | 결정 | 근거 | 재검토 조건 |
|---|---|---|---|---|---|---|---|---|
| 2016149 | ET INFO STUN Binding Request | 1,806,475 | 3 | out | Tailscale DERP. 7일치 전부가 DERP 88개 대상 | **DERP 목적지만 억제** (`track by_dst`) | 알려진 정상 관리 인프라의 소음. 룰은 유지해서 DERP가 아닌 STUN은 계속 alert | DERP 목록이 바뀌면 갱신(`tailscale debug derp-map`으로 재생성) |
| 2016150 | ET INFO STUN Binding Response | 1,802,472 | 3 | in | 위 요청의 응답 | **DERP 출발지만 억제** (`track by_src`) | 위와 같음 | 위와 같음 |
| 2024897 | ET USER_AGENTS Go HTTP Client User-Agent | 270,975 | 3 | out | Tailscale. 같은 DERP IP로 80/tcp | **DERP 목적지만 억제** | 위와 같음 | 위와 같음 |
| 2060251 | ET INFO Go-http-client User-Agent Observed Outbound | 270,975 | 3 | out | 위와 같은 통신에 동시 발화 | **DERP 목적지만 억제** | 위와 같음 | 위와 같음 |
| 2047702 | ET INFO External IP Lookup Domain (ipify) in DNS Lookup | 8,730 | 3 | out | 공인 IP 감시 스크립트(10분 주기). 하루 291건 = 10분에 2번 | 유지 | 알림 영향 없음. 10분 주기에서 벗어난 조회를 나중에 볼 수 있음 | — |
| 2047703 | ET INFO External IP Address Lookup Domain (ipify) in TLS SNI | 4,319 | 3 | out | 같은 스크립트. 하루 144건 = 10분에 1번 | 유지 | 위와 같음 | — |
| 2402000 | ET DROP Dshield Block Listed Source group 1 | 37,106 | 2 | in | 차단 명단 IP의 무차별 스캔(출발지 1,550곳) | 유지 (watcher에서 SID 범위로 제외) | 정탐이지만 조치 가치 낮음. 표준 서비스 포트를 두드림, 현재 열린 포트 없음. ET가 이미 IP당 시간당 1건으로 빈도 제한 | 포트를 외부에 열게 되면 그 포트 대상 평판 alert는 다시 봄 |
| 2400016, 2400035 외 | ET DROP Spamhaus DROP Listed Traffic Inbound group N | 5,860 / 5,667 외 | 2 | in | 위와 같음 | 유지 (watcher에서 SID 범위로 제외) | 위와 같음 | 위와 같음 |
| 2403403, 2403574 외 | ET CINS Active Threat Intelligence Poor Reputation IP group N | 2,898 / 2,666 외 | 2 | in | 위와 같음 | 유지 (watcher에서 SID 범위로 제외) | 위와 같음 | 위와 같음 |
| 2260001 | SURICATA Applayer Wrong direction first Data | 24,477 | 3 | out | 집 전체 HTTPS(목적지 3,268곳). 특정 프로그램 아님 | 유지 | 센서가 통신을 제대로 읽는지 보여주는 건강 지표 | 하루 건수가 평소 범위를 크게 벗어나면 센서 점검 |
| (미확인) | SURICATA STREAM Packet with invalid ack 계열 | 약 2,440 / 2,438 | 3 | out | 거의 전부 클라우드 서버 한 곳과의 통신. 어떤 앱인지는 미확인 | 유지 | 건강 지표 | 위와 같음 |
| 2227001 | SURICATA DHCP truncated options | 11,453 | 3 | other | 통신사 DHCP 서버 → 공유기 WAN | 유지 | 하루 약 380건, 알림 영향 없음. (끄는 것도 근거 충분: 매일 같은 모양, 우리가 고칠 수 없음) | — |

## 판단 과정에서 확인한 사실

- **룰 방향:** 평판 룰 원문은 `alert ip [명단] any -> $HOME_NET any`. 집 출발 평판 alert 0건은 "나간 적 없음"이 아니라 "나가는 방향을 보는 룰이 없음"
- **들어오는 평판 alert 포트 상위:** 22, 80, 8080, 17000, 3389, 34567, 23, 443 … → 우리 설정과 무관한 무차별 스캔
- **Applayer와 GRO:** 10-15에 하루 건수가 약 720 → 149로 줄었지만, 같은 날 포트포워딩 삭제·공유기 펌웨어 업그레이드·GRO 끄기가 겹쳐 원인 단정 불가

## 결정 기준

튜닝:
1. 이 룰은 무엇이 일으키나 (출처를 목적지·주기·포트로 추적)
2. 알림까지 가나, 저장만 되나 (등급과 watcher 경로)
3. 남겼을 때 볼 수 있는 가치가 있나, 비용은 얼마인가
4. 끄면 무엇을 못 보게 되나 (flow 기록으로 대체 가능한가)

자작 룰 후보:
1. ET Open이 못 보는 빈칸인가
2. 우리 환경에서 실제 위협 신호인가
3. 오탐이 적은가
4. 안전하게 재현할 수 있나

## 적용 방법

- `suricata.yaml`의 `threshold-file` 경로를 명시적으로 지정(기존엔 주석 처리. 기본 경로를 읽는지 확실하지 않아 명시)
- `threshold.config`에 suppress 4줄 추가. 형식: `suppress gen_id 1, sig_id <SID>, track <by_dst|by_src>, ip [DERP IPv4 88개]` (Suricata 공식 문서로 문법 확인)
- `suricata -T` 통과 → 재시작 → 시작 로그에 threshold/error/warn 없음 확인
- 되돌리기: 변경 전 백업 두 파일을 원래 이름으로 복사하고 재시작

## 남은 일

- DERP 목록 갱신을 스크립트로(재생성 → `suricata -T` → 재시작). 실행 주기 결정
- STREAM 계열 SID 번호 확인
