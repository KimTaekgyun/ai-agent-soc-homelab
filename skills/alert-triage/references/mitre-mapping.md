# Suricata 시그니처 → MITRE ATT&CK 운영자 정의 매핑

**이 문서는 공식 매핑이 아니다.** 아래 시그니처들은 ET Open 룰셋에 `mitre_technique_id` 메타데이터가
부여되어 있지 않으며(2026-09-14 확인: 룰셋 전체 32,467개 룰에 태그가 있으나 본 환경에서 발화하는
평판·스캔 계열 룰에는 없음), 따라서 아래 매핑은 **룰 원문의 속성을 근거로 운영자가 판단한 것**이다.

## 매핑 출처 3단계

리포트 작성 시 반드시 출처를 표기한다.

| 표기 | 조건 | 신뢰도 |
|---|---|---|
| `[ET 룰셋 태그]` | alert 데이터에 `mitre_technique_id`가 존재 | 높음 — 룰 작성자가 부여 |
| `[운영자 정의]` | 본 문서에 해당 항목 존재 | 중간 — 근거는 아래 명시 |
| `[추론 기반]` | 위 둘 다 없음 | 낮음 — LLM 판단, 검증 필요 |

## 판단에 사용한 룰 속성

매핑 근거로 삼은 것은 다음 네 가지다.

- **classtype** — 룰 작성자가 분류한 공격 성격. `attempted-recon`처럼 명시적이면 근거가 강하고,
  `misc-attack`/`bad-unknown`이면 룰 자체가 성격을 특정하지 않은 것이므로 매핑 신뢰도가 낮아진다.
- **탐지 방식** — IP 리스트 매칭(출처 기반)인지, 페이로드/플래그 매칭(행위 기반)인지.
  출처 기반은 "누가 접근했는가"만 알려주므로 공격 기법을 특정할 수 없다.
- **threshold** — 임계 제한이 걸린 룰의 개별 alert은 반복 이벤트의 대표값이지 단일 사건이 아니다.
- **flowbits** — 다른 룰과 상관되는지 여부.

---

## 1. ET DROP Dshield Block Listed Source

```
alert ip [45.205.1.0/24, ...] any -> $HOME_NET any
classtype:misc-attack; threshold: type limit, track by_src, seconds 3600, count 1;
flowbits:set,ET.Evil; flowbits:set,ET.DshieldIP; sid:2402000
```

- **매핑**: T1595 Active Scanning
- **출처**: 운영자 정의
- **근거**: 탐지 조건이 출발지 IP의 CIDR 리스트 매칭뿐이며 페이로드 검사가 없다.
  즉 "무엇을 했는가"는 판단하지 않고 "Dshield 피드에 등재된 대역에서 왔다"만 확인한다.
  classtype이 `misc-attack`으로 성격 미특정이며, threshold가 시간당 1회로 제한되어
  개별 alert은 반복 접근의 대표값이다. 행위를 특정할 수 없으므로 관측 가능한
  최소 공통분모인 정찰(T1595)로 분류한다.
- **한계**: 실제 행위가 C2 통신(T1071), 익스플로잇 시도(T1190), 브루트포스(T1110)여도
  이 룰만으로는 구분되지 않는다. **T1595라는 매핑은 "그 이상은 알 수 없다"는 뜻이지
  "정찰이 확실하다"는 뜻이 아니다.**
- **검증 방법**: 동일 출발지 IP가 같은 시간대에 페이로드 기반 룰(ET SCAN, ET EXPLOIT 등)을
  함께 발화시켰는지 ES에서 조회한다. 함께 떴다면 그 룰의 매핑을 우선한다.
- **참고**: `flowbits:set,ET.Evil`이 설정되므로, 이 플래그를 소비하는 후속 룰이 있다면
  상관 분석의 근거가 된다.

## 2. ET DROP Spamhaus DROP Listed Traffic Inbound

```
alert ip [94.103.188.0/24, ...] any -> $HOME_NET any
classtype:misc-attack; threshold: type limit, track by_src, seconds 3600, count 1;
flowbits:set,ET.Evil; flowbits:set,ET.DROPIP; sid:2400016
```

- **매핑**: T1595 Active Scanning
- **출처**: 운영자 정의
- **근거**: 1번과 동일 구조(IP 리스트 매칭, misc-attack, 시간당 1회 제한).
  다만 Spamhaus DROP은 "할당이 회수되었거나 악용이 확인된 대역" 목록이므로
  Dshield 대비 정상 트래픽 가능성이 더 낮다. `signature_severity Minor`로
  ET는 이 룰을 낮게 평가하고 있으나, 이는 "위험이 낮다"가 아니라
  "단일 이벤트의 정보량이 적다"는 의미로 해석한다.
- **한계**: 1번과 동일.
- **검증 방법**: 1번과 동일.

## 3. ET CINS Active Threat Intelligence Poor Reputation IP

```
alert ip [79.116.174.198, ...] any -> $HOME_NET any
classtype:misc-attack; threshold: type limit, track by_src, seconds 3600, count 1;
sid:2403411 (group별 sid 상이)
```

- **매핑**: T1595 Active Scanning
- **출처**: 운영자 정의
- **근거**: 1·2번과 동일 구조. group 번호(3~277)는 IP 목록을 분할한 것일 뿐
  탐지 의미가 다르지 않으므로 패턴 단위로 동일 매핑을 적용한다.
  본 환경 최근 7일 기준 상위 25개 시그니처 중 18개가 이 계열이다.
- **한계**: 1번과 동일. 추가로, CINS 점수는 평판 기반 스코어링이므로
  오래된 등재나 공유 호스팅 IP로 인한 오탐 가능성이 다른 두 리스트보다 높다.
- **검증 방법**: 1번과 동일. 추가로 해당 IP의 등재 사유를 cinsscore.com에서 확인 가능.

## 4. ET SCAN Suspicious inbound to MSSQL port 1433 (및 mySQL 3306, PostgreSQL 5432 등)

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 1433
flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src;
classtype:bad-unknown; sid:2010935
```

- **매핑**: T1046 Network Service Discovery
- **출처**: 운영자 정의
- **근거**: 1~3번과 달리 **행위 기반 탐지**다. 특정 포트(1433)로 향하는 SYN 패킷을
  60초에 5회 이상 관측했을 때 발화하므로, "DB 서비스 존재 여부를 확인하려 했다"는
  행위가 실제로 관측된 것이다. 이는 네트워크 서비스 열거(T1046)의 정의에 부합한다.
  classtype은 `bad-unknown`으로 의도까지는 특정하지 않는다.
- **한계**: 단일 포트 스캔은 자동화 봇의 무차별 탐색일 가능성이 높아,
  T1046으로 매핑하되 의심도 자체는 낮게 유지해야 한다.
  **다만 서로 다른 DB 포트(1433 + 3306 + 5432 등) 2종 이상이 동일 출발지에서 오면
  표적성 열거로 보고 의심도를 상향한다.**
- **검증 방법**: 해당 포트가 실제 외부 노출 중인지 확인. 노출 중이라면 후속
  인증 로그(브루트포스 징후)를 점검한다.

## 5. ET SCAN Sipvicious Scan / User-Agent Detected (friendly-scanner)

```
alert udp $EXTERNAL_NET any -> $HOME_NET 5060
content:"From|3A 20 22|sipvicious"; classtype:attempted-recon; sid:2008578
content:"|0d 0a|User-Agent|3A| friendly-scanner"; classtype:attempted-recon;
confidence High; sid:2011716
```

- **매핑**: T1595.001 Scanning IP Blocks + T1046 Network Service Discovery
- **출처**: 운영자 정의 (**단, 이 항목은 근거가 가장 강함**)
- **근거**: 세 가지 이유로 위 항목들보다 신뢰도가 높다.
  ① classtype이 `attempted-recon`으로 **룰 작성자가 정찰임을 명시**했다.
  ② 탐지 조건이 페이로드 content 매칭(`sipvicious`, `friendly-scanner` 문자열)이므로
  출처가 아닌 **행위와 도구가 식별**된다.
  ③ sid:2011716은 `confidence High`로 표기되어 있다.
  SIPVicious는 VoIP 인프라 열거 도구이므로 IP 블록 스캔(T1595.001)과
  서비스 열거(T1046)를 함께 매핑한다.
- **한계**: 도구가 식별되었다는 것이 곧 침해 시도를 뜻하지는 않는다.
  보안 연구자의 인터넷 전수 스캔일 수도 있다. 다만 도구 식별이 된 만큼
  평판 매칭 계열보다는 의심도를 높게 둔다.
- **검증 방법**: SIP 서비스(5060/udp)가 실제 운용 중인지 확인. 운용 중이 아니라면
  자동화 스캔의 유탄으로 처리한다.

## 6. GPL ATTACK_RESPONSE id check returned root

```
alert ip any any -> any any
content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498
```

- **매핑**: T1059 Command and Scripting Interpreter (조건부)
- **출처**: 운영자 정의
- **근거**: `id` 명령의 실행 결과 문자열이 네트워크를 통해 관측된 것이므로,
  원격에서 명령이 실행되고 그 출력이 반환되었음을 시사한다. 정찰이 아니라
  실행 단계의 징후다.
- **⚠ 중대한 한계**: 이 룰은 `alert ip any any -> any any`로 방향과 대상을 가리지 않으며,
  단순 문자열 매칭이다. **본 환경에서는 운영자의 testmyids.com 검증 트래픽으로도
  동일하게 발화한다** (2026-08-31 실측). 실제로 자동 트리아지가 이를
  "root 권한 획득 성공, 즉각 격리 필요"로 판정한 오탐 사례가 있다.
  따라서 이 시그니처는 **출발지·시각이 운영자의 의도적 테스트와 일치하는지 먼저 확인**해야 한다.
- **검증 방법**: 출발지 IP가 testmyids.com(또는 유사 검증 서비스)인지, 발생 시각이
  수동 테스트 시점과 일치하는지 확인. 일치하면 오탐으로 종결한다.

---

## 커버리지 한계 (센서 구조상 관측 불가능한 영역)

본 센서는 NAT 외부(ISP 세그먼트)의 인라인 브릿지이며 네트워크 트래픽 단일 소스다.
따라서 ATT&CK 전술 중 **관측 자체가 구조적으로 불가능한 영역**이 존재한다.
이를 매핑하지 않는 것은 누락이 아니라 설계상의 한계다.

| 전술 | 관측 가능 여부 | 사유 |
|---|---|---|
| TA0043 Reconnaissance | 부분 가능 | 스캔·열거 트래픽 관측 가능 |
| TA0001 Initial Access | 부분 가능 | 익스플로잇 시도 트래픽은 관측 가능(현재 미발생) |
| TA0002 Execution | 사실상 불가 | 엔드포인트 로그 없음. 응답 페이로드 유출 시에만 간접 추정 |
| TA0003 Persistence | 불가 | 호스트 내부 행위 |
| TA0005 Defense Evasion | 불가 | 동상 |
| TA0006 Credential Access | 부분 가능 | 네트워크 브루트포스 한정 |
| TA0008 Lateral Movement | **불가** | 센서가 NAT 외부라 내부 간 통신 미관측 |
| TA0010 Exfiltration | 제한적 | 암호화 트래픽 내용 판별 불가 |

추가 제약:
- destination IP가 항상 단일 공인 IP이므로 **내부 호스트별 귀속 불가**
- 인접 ISP 세그먼트 트래픽도 캡처되므로, destination이 본 호스트가 아니면 의심도를 낮춘다
- 암호화된 트래픽의 페이로드는 검사 불가

## 갱신 이력

- 2026-09-14 최초 작성. 근거는 `/var/lib/suricata/rules/suricata.rules`의 룰 원문 및
  최근 7일 ES 집계(severity ≤ 2, 상위 25개 시그니처) 기준.
- ET 룰셋에 `mitre_technique_id` 태그가 부여된 룰이 본 환경에서 발화할 경우,
  해당 시그니처는 이 문서가 아닌 `[ET 룰셋 태그]`를 우선한다.
