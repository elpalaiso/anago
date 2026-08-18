# anago — 내 도메인 + 내 서버 = 내 개인 네트워크

> 穴子(아나고, 붕장어): 구멍에 사는 장어. 터널에 사는 도구에게 이보다 맞는 이름이 없다.

## 1. 한 줄 요약

도메인과 서버(VPS)를 가진 사람이라면 누구나 10분 안에 자기 소유의
WireGuard 개인 네트워크를 갖게 해주는 단일 바이너리 셋업 도구.
certbot이 TLS에 해준 일을 개인 네트워크에 해준다.

## 2. 목표

- `anago server init --domain net.example.com` (VPS에서 1회) +
  `anago join net.example.com <코드>` (각 기기에서 1회) = 끝.
- 제3자 인프라 의존 0: 조율 서버도, 릴레이도, 인증도 전부 사용자의 서버.
  Tailscale이 회사여야 하는 이유(전 세계 릴레이망 운영)를 "인프라는 이미
  네 것"이라는 전제로 소거한다.
- 첫날부터 "항상 된다": 허브-스포크(서버 경유)가 기본 토폴로지라서
  NAT/CGNAT 환경(한국 LTE 포함)에서도 무조건 연결된다. 홀펀칭 직결은
  나중에 얹는 성능 최적화다.
- 오픈소스(MIT), 단일 바이너리, 낮은 서버 사양(1코어 VPS면 충분).

## 3. 비목표 (v1에서 의도적으로 안 만드는 것)

- **멀티 테넌시/조직 관리**: 사용자 1명(가족 규모까지)의 기기들. ACL,
  SSO, 감사 로그는 만들지 않는다.
- **모바일 클라이언트 앱**: iOS/Android는 공식 WireGuard 앱에 설정을
  내보내는(QR/파일) 것으로 해결한다. NetworkExtension의 늪에 들어가지
  않는다.
- **자체 암호화**: 암호 프리미티브는 한 줄도 직접 만들지 않는다.
  데이터 플레인은 WireGuard 그 자체다.
- **DERP류 글로벌 릴레이망**: 사용자의 서버가 곧 릴레이다. 릴레이를
  "운영"하는 문제는 이 설계에 존재하지 않는다.
- **범용 VPN**(전체 트래픽 라우팅/출구 노드): v1은 기기 간 사설망이다.
  exit node는 백로그.

## 4. 설계 원칙

1. **어려운 문제는 위임한다.** 암호화·터널=WireGuard(`wg`/커널),
   TLS=rustls+ACME, 프로세스 상주=systemd, DNS=Cloudflare API(또는 수동
   안내). anago가 직접 푸는 문제는 **조율(키·엔드포인트 교환)과 UX
   (셋업 마법사)** 둘뿐이다. — krill 원칙 1과 동일.
2. **서버는 데몬이 정당하다.** krill과 달리 anago server는 VPS에 상주하는
   것이 본질이다(조율+릴레이). 대신 클라이언트 쪽은 상주를 최소화한다
   (§6.3).
3. **단일 바이너리, 서버/클라 공용.** `anago` 하나가 서브커맨드로 양쪽
   역할을 다 한다. 배포물 1개, 문서 1벌.
4. **의존성은 마일스톤이 요구할 때만.** 코어 로직(설정 생성·상태 판정·
   프로토콜 타입)은 순수 std 라이브러리 크레이트(anago-core)로 분리해
   유닛 테스트를 깐다. tokio/axum/rustls는 바이너리 크레이트에만. —
   krill의 검증된 구조를 그대로 쓴다.

## 5. 아키텍처

```
                    net.example.com (A 레코드 → VPS)
                          │
        ┌─────────────────▼──────────────────┐
        │  VPS: anago server (상주)          │
        │  ├─ 컨트롤 API (HTTPS :443)        │  join/peers/endpoint 갱신
        │  ├─ ACME 인증서 자동 갱신          │
        │  └─ wg 허브 피어 (UDP :51820)      │  모든 기기의 트래픽 중계
        └───────▲──────────────▲─────────────┘
                │ wg 터널      │ wg 터널
         ┌──────┴─────┐  ┌─────┴──────┐
         │ 맥북       │  │ 데스크톱   │   ← anago join으로 등록된 기기
         │ 10.100.0.2 │  │ 10.100.0.3 │      (폰: wg 공식 앱 + 내보낸 설정)
         └────────────┘  └────────────┘
```

- **컨트롤 플레인**: HTTPS API. 기기 등록(join), 피어 목록 조회, 공개키
  교환. 상태의 원본은 서버의 단일 상태 파일(§9).
- **데이터 플레인**: WireGuard. M0~M1은 순수 허브-스포크 — 기기끼리의
  패킷은 서버를 경유한다(`AllowedIPs = 10.100.0.0/24`, 서버에서
  `ip_forward` + wg 라우팅). M2에서 홀펀칭 직결이 얹힌다.
- **주소 체계**: 사설 서브넷 기본 `10.100.0.0/24`(설정 가능). 서버 = .1,
  기기는 join 순서대로 할당.

**허브 경유의 신뢰 모델을 명시한다**: WireGuard는 피어 간 암호화이므로
허브-스포크에서 서버는 패킷을 복호화해 라우팅한다. 즉 서버는 트래픽을
볼 수 있다 — 그 서버가 **사용자 본인의 것**이라는 게 이 프로젝트의 전제
이고, 이것이 Tailscale(제3자 DERP는 E2E 유지 필요)과 위협 모델이 다른
이유다. M2 직결이 되면 기기 간 트래픽은 E2E가 된다. 문서에 정직하게
적는다.

## 6. 핵심 플로우

### 6.1 서버 초기화 (VPS에서 1회)

```
anago server init --domain net.example.com
```

1. wg 키쌍 생성, 서브넷/포트 결정, 상태 파일 생성.
2. DNS 확인: `net.example.com`이 이 서버의 공인 IP를 가리키는지 조회.
   - 아니면: **Cloudflare API 토큰이 있으면(`--cf-token` 또는 env) A
     레코드를 자동 생성**, 없으면 "이 레코드를 추가하세요" 안내 후 재시도
     대기. (1차 provider = Cloudflare — 실검증 환경이 Cloudflare 등록
     도메인이다. 다른 provider는 수동 안내로 시작, API 지원은 백로그.)
3. ACME로 TLS 인증서 발급 — 기본 HTTP-01(:80 필요). Cloudflare 토큰이
   있으면 DNS-01도 가능(:80을 안 열어도 됨). 갱신은 서버 데몬이 내장
   처리(§10).
4. systemd 유닛 설치·기동(`/etc/systemd/system/anago.service`, ExecStart는
   `anago server run`). `--no-systemd`면 설치하지 않고 포그라운드로 실행할
   명령을 안내한다 — 컨테이너/비-systemd 환경.
5. 조인 코드 발급·출력: `anago join net.example.com 7QX4-M2KD`(형식은 §7.2).

### 6.2 기기 등록 (각 기기에서 1회)

```
anago join net.example.com 7QX4-M2KD
```

1. HTTPS로 서버에 코드 제출(코드는 1회용·만료 있음, §7).
2. 기기에서 wg 키쌍 생성 — **개인키는 기기를 떠나지 않는다.** 서버에는
   공개키만 등록. 응답으로 할당 IP·서버 공개키·엔드포인트 수신.
3. wg 설정 생성·적용(`wg-quick` 위임), 연결 확인(서버 .1에 ping).
4. `--export qr|conf`면 적용 대신 공식 WireGuard 앱용 설정 출력(폰 경로).

### 6.3 클라이언트 상주 문제

WireGuard 자체는 커널에 있으니 클라 데몬이 없어도 터널은 유지된다.
클라가 해야 할 일은 두 가지뿐이고 둘 다 가볍다:

- **keepalive**: wg의 `PersistentKeepalive = 25`로 NAT 매핑 유지 — 설정
  한 줄, 프로세스 0.
- **피어 목록 동기화**(새 기기 추가 반영): 상주 데몬 대신 **systemd
  timer(맥은 launchd)로 `anago sync`를 주기 실행**(기본 5분). M2의
  홀펀칭이 들어오면 이 주기 작업이 엔드포인트 갱신도 겸한다.

허브-스포크에서는 사실 동기화가 늦어도 통신은 된다(허브가 다 안다).
timer는 편의이지 정합성 요건이 아니다 — 이 성질 덕에 클라이언트도
사실상 데몬 0으로 굴러간다.

## 7. 보안 모델

- **전송**: 컨트롤 API는 TLS(ACME 정식 인증서, 자가서명 없음). 데이터
  플레인은 WireGuard(Noise).
- **조인 코드**: 1회용, 기본 15분 만료, 서버에서 `anago code`로 재발급.
  코드 = 등록 권한 그 자체이므로 짧게 살고 즉시 죽는다. 형식은 §7.2.
- **키**: wg 개인키는 각 기기 로컬에만(0600). 서버 상태 파일에는 기기의
  공개키·IP·이름과 토큰 해시(§7.1)만 — 기기 개인키도, 토큰 평문도 서버에
  없다. 기기 제거 = `anago rm <이름>` → 서버가 피어에서 제거, 다음 sync
  때 각 기기 설정에서도 사라진다.
- **API 인증**: join 이후의 호출(`ls`/`rm`, M1의 `sync`)은 join 때
  발급되는 기기 토큰(bearer)으로. 토큰은 기기 로컬 저장(0600), 서버에는
  해시만 — 상세는 §7.1.
- **Cloudflare 토큰**: DNS 편집 권한만 가진 스코프 토큰을 요구하도록
  문서화. `server init` 완료 후엔 인증서 갱신(DNS-01일 때)에만 쓰므로,
  **그때만** 상태 파일이 아닌 별도 파일(0600)에 남긴다 — 저장 위치와
  이유는 §9.1.

### 7.1 기기 토큰 — M0 확정: 해시 저장

**서버는 기기 토큰을 SHA-256 해시(hex 64자)로만 저장한다. 평문은 상태
파일에도 로그에도 남기지 않는다.**

- **형식**: 256비트 랜덤을 hex로 쓴 64자 `[0-9a-f]`. 조인 코드와 달리
  사람이 손으로 옮겨 적지 않고 설정 파일에 저장되므로, 읽기 좋은
  charset보다 모호함 없는 인코딩이 낫다 — hex면 바이너리가 랜덤
  32바이트를 그대로 인코딩하면 되고 거부 샘플링이 필요 없다.
- **생성**: 바이너리가 `/dev/urandom`에서 32바이트를 읽어 만든다(순수
  std로 가능, 별도 크레이트 없음). 읽기에 실패하면 약한 난수로
  폴백하지 않고 join을 실패시킨다.
- **저장**: 서버는 `peers[].token_hash`(§9.1)에 해시만. 클라이언트는
  `~/.config/anago/device.json`에 평문을 0600으로 — 매 요청에 제시해야
  하므로 불가피하다.
- **검증**: 클라가 bearer로 평문을 보내면 서버가 `sha2`의 SHA-256으로
  해싱해 저장된 해시와 상수시간 비교한다.
- **폐기**: `anago rm <이름>`으로 피어를 지우면 그 토큰은 그 즉시
  무효다. 회전·갱신 API는 M0에 없다 — 필요하면 기기를 다시 join한다.

**왜 평문 저장이 아니라 해시인가.** 상태 파일에는 어차피 서버 wg
개인키가 들어 있으니 "파일이 새면 어차피 끝"이라는 반론이 가능하다.
그래도 해시를 고른 이유는 셋이다. (1) 개인키는 파일에 있을 수밖에
없지만 토큰 평문은 **없앨 수 있는 비밀**이다 — 없앨 수 있는 건 없앤다.
(2) 상태 파일이 통째로 유출되는 경로(백업, 이슈에 붙여넣은 덤프,
`server status` 출력 실수)는 서버 침해와 달리 흔하고, 그때 평문 토큰은
곧바로 재사용 가능한 자격증명이다. (3) 비용이 크레이트 하나다 —
바이너리 크레이트가 `sha2`를 **직접 의존성으로** 선언해 쓴다. rustls가
어떤 provider를 끌고 오든 그건 전이 의존성이라 우리 코드가 직접 부를 수
없고, rustls가 범용 SHA-256 API를 보장하지도 않는다. 그러니 "이미 있는
걸 재활용"이라는 절약은 성립하지 않는다 — 의존성 하나를 명시적으로
추가하는 쪽이 정직하고, 구현 단계에서 다시 고를 일도 없다. anago가
SHA-256을 직접 구현하는 일은 없다(§3, §4 원칙 1).

**솔트·KDF를 쓰지 않는 이유**: 토큰은 사람이 고른 비밀번호가 아니라
256비트 균일 랜덤이다. 사전 공격·레인보우 테이블의 대상이 아니므로
argon2/bcrypt는 비용만 늘리고, 단일 SHA-256으로 충분하다. 이 성질이
깨지는 순간(예: 사람이 고른 토큰 허용)엔 이 문단을 먼저 고친다.

**anago-core의 책임 경계**: 코어는 순수 std라 해싱을 하지 않는다.
코어가 갖는 것은 (a) 토큰 **형식 검증**(길이 64, hex 문자만)과
(b) 두 해시 문자열의 **상수시간 비교**(길이 확인 후 XOR 누적 —
암호 프리미티브를 만드는 게 아니라 조기 반환을 없앤 비교일 뿐이다)
둘뿐이다. 해싱은 바이너리 크레이트가 `sha2`에 위임한다. 즉
토큰의 규칙은 코어에서 유닛 테스트되고, 계산은 라이브러리에 맡긴다.

### 7.2 조인 코드 형식

**`XXXX-XXXX` — 하이픈으로 끊은 4자 두 묶음, 총 8자.** 사용할 문자는
`23456789ABCDEFGHJKMNPQRSTVWXYZ` 30자다.

- **혼동 문자 제외**: `0`/`O`, `1`/`I`/`L`, `U`(V와 혼동)를 뺐다. 이
  코드는 VPS 터미널에서 눈으로 읽어 노트북·폰에 손으로 옮기는 문자열
  이라, 알파벳 크기를 32에서 30으로 줄여 잃는 비트(0.1비트/자)보다
  잘못 읽어 실패하는 비용이 크다.
- **엔트로피**: 30^8 ≈ 6.6×10^11, 약 39.3비트. 15분 만료·1회용과
  합치면 초당 100회로 두들겨도 15분 창에서 성공 확률이 10^-7 수준이다.
  M0에는 레이트 리밋이 없으므로(백로그) 안전 마진을 엔트로피가 진다.
  이전 초안이 쓰던 `CODE-XXXX`는 자리표시자였고, 실제 형식은 이 절이
  정본이다.
- **입력 관용**: 서버가 출력하는 정규형은 대문자에 하이픈 하나
  (`7QX4-M2KD`). 검증은 대소문자를 가리지 않고, 하이픈과 공백은
  무시한다 — `7qx4m2kd`도 같은 코드다. 사람이 옮겨 적는 문자열에서
  대소문자 실수로 등록을 막을 이유가 없다.
- **책임 경계**: 난수는 바이너리가 만든다(토큰과 같은 `/dev/urandom`,
  §7.1). anago-core는 알파벳·형식·정규화·검증만 갖는다 — 순수 함수라
  유닛 테스트로 고정된다.

## 8. 인터페이스 스펙 (CLI)

각 줄에 도입 마일스톤을 붙인다. **M0 바이너리는 M0 표면만 구현하고,
M1+ 서브커맨드·플래그는 "아직 없음(M1에서 들어옴)"이라고 답한다** —
있는 척하는 no-op보다 낫다.

M0에서 실제로 구현하는 표면:

```
anago server init --domain <d> --tls-cert <p> --tls-key <p>
                  [--subnet 10.100.0.0/24] [--port 51820]
                  [--api-port 443] [--no-systemd]
                                   # DNS는 수동 안내(A 레코드 출력), TLS는
                                   # 기존 인증서 경로 지정 (§11 M0)
anago server run                   # 서버 상주 프로세스: 컨트롤 API + wg 인터페이스 유지
                                   # systemd 유닛의 ExecStart. `server init`이
                                   # 대신 설치·기동하므로 손으로 칠 일은
                                   # `--no-systemd`로 포그라운드 실행할 때뿐이다
anago code                         # 서버에서: 조인 코드 발급
anago join <domain> <code> [--name 맥북] [--api-port 443]
                                   # 서버가 --api-port로 초기화됐으면 같은 값을 준다
anago ls                           # 기기 목록 (기기에선 API, 서버에선 상태 파일)
anago rm <이름>                    # 기기 제거 (서버 반영)
```

M1 이후로 미루는 표면(설계는 유지, 구현은 나중):

```
anago server init --cf-token <t>   # M1: Cloudflare A 레코드 자동 생성·DNS-01
anago server init (--tls-cert/key 생략)  # M1: ACME 자동 발급. M0에선 두 플래그가 필수
anago sync                         # M1: 피어 목록 당겨와 wg 설정 갱신 (timer가 부름)
anago join --export qr|conf        # M1: 폰(공식 wg 앱)용 설정 출력
anago ping <이름>                  # M3: 사설 IP 조회 + ping 위임
anago server status                # M3: 피어·마지막 handshake·트래픽 대시보드
```

M0에서 `sync`가 없어도 통신은 된다 — §6.3의 성질 그대로다. 허브가
피어를 다 알고 서버가 자기 wg 설정을 갱신하므로, 기기 쪽 설정이
`AllowedIPs = <subnet>` 한 줄이면 새 기기와도 바로 통신된다. 기기
설정을 다시 만져야 하는 경우는 M2(직결 엔드포인트)부터다.

컨트롤 API(v1, JSON over HTTPS — 스키마는 anago-core의 타입이 원본):

| 메서드/경로 | 마일스톤 | 인증 | 역할 |
|---|---|---|---|
| POST /api/v1/join | M0 | 조인 코드 | 공개키 등록 → IP 할당·서버 정보 응답 |
| GET  /api/v1/peers | M0 | 기기 토큰 | 피어 목록(공개키·IP·이름) |
| DELETE /api/v1/peers/{name} | M0 | 기기 토큰 | 기기 제거 |
| POST /api/v1/endpoint | M2 | 기기 토큰 | 자기 관측 엔드포인트 보고 |

M0의 `GET /api/v1/peers` 응답에 엔드포인트 필드는 없다(§9.1과 같은
이유 — 기기 관측 엔드포인트는 M2에 스키마와 함께 들어온다). `anago
sync`는 M1이지만 그것이 쓸 엔드포인트는 M0에서 이미 서비스되므로,
M1은 클라이언트 쪽만 추가하면 된다.

### 8.1 기기 이름 규칙

이름은 `rm`의 키이자 URL 경로 조각(`DELETE /api/v1/peers/{name}`)이고,
M3에서는 호스트명이 된다. 그래서 규칙을 여기서 못박는다.

- **정규형**: 앞뒤 공백을 떼고 소문자화한 형태. 서버는 정규형을 저장하고
  join 응답의 `name`으로 돌려준다 — 클라이언트는 보낸 이름이 아니라
  받은 이름을 저장한다.
- **길이**: 1–32자(문자 수 기준).
- **허용 문자**: 유니코드 문자·숫자와 `-`, `_`. 첫 자와 끝 자는 문자
  또는 숫자여야 한다. 한글 이름(`맥북`)은 1급 시민이다 — 문서의 예시가
  그렇게 쓰고 있고, 개인용 도구에서 이름은 사람이 읽는 것이다.
- **금지 문자와 이유**: `.`은 M3의 라벨 경계(`맥북.net.example.com`)와
  충돌하고, `/` `%` `?` `#` `:`는 URL 경로를 깨며, 공백·제어문자는 wg
  설정과 셸 인용에서 사고를 낸다.
- **예약어**: `server`. 허브 자신을 가리키는 이름이라 M3의 이름 해석에서
  충돌한다.
- **중복**: 정규형이 같으면 같은 이름이다. `MacBook`과 `macbook`은
  공존할 수 없다.

**알려진 한계(M0)**: 유니코드 정규화(NFC/NFD)는 하지 않는다. 표준
라이브러리에 정규화가 없고 코어는 순수 std이기 때문이다(§4 원칙 4).
따라서 조합형으로 입력한 `맥북`과 완성형 `맥북`은 눈에는 같아 보여도
서로 다른 이름으로 등록될 수 있다. 실사용에서 문제가 되면 그때
바이너리 크레이트에 정규화 의존성을 두고 이 문단을 고친다.

**M3 메모**: 비-ASCII 이름의 DNS 라벨화(punycode)는 M3에서 다룬다. M0는
저장·표시·조회만 한다.

## 9. 서버 상태와 설정

- 상태: `/var/lib/anago/state.json` — 단일 파일, 원자적 쓰기
  (tmp+rename), 0600, 동시 쓰기는 flock으로 직렬화. DB 없음.
- 인증서: 상태는 **경로만 기록한다 — 사람이 준 인증서 파일을 복사하지
  않는다.** M1의 ACME 발급물만 anago가 소유하며 `/var/lib/anago/tls/`
  (`account.key`·`fullchain.pem`·`privkey.pem`, 디렉터리 0700, 파일
  0600)에 둔다. 둘을 가르는 것은 `tls.source` 하나다 — §9.1.
- Cloudflare 토큰: **상태 파일에 넣지 않는다.** DNS-01로 갱신해야 해서
  나중에도 필요할 때만 `/var/lib/anago/cf-token`(0600)에 따로 두고,
  상태에는 그 경로만 적는다 — §9.1.
- 클라: `~/.config/anago/device.json`(도메인·기기 토큰·할당 IP·서버
  공개키), 0600. wg 개인키는 여기 두지 않는다 — wg 설정
  `/etc/wireguard/anago.conf`(wg-quick 규약 위임)에만 있고 기기를
  떠나지 않는다.
  - 정확한 위치는 **`$XDG_CONFIG_HOME/anago/`(설정돼 있고 절대 경로일
    때), 아니면 `$HOME/.config/anago/`**다. `~/.config`는 XDG의 기본값
    이므로, 사용자가 `XDG_CONFIG_HOME`을 옮겨 둔 시스템에서 `~/.config`를
    고집하는 것은 규약 위반이다. 상대 경로 `XDG_CONFIG_HOME`은 무시한다
    — 현재 디렉터리 기준으로 풀면 기기 토큰이 사용자가 서 있던 아무
    곳에나 떨어진다. 둘 다 없으면 추측하지 않고 실패한다.
  - **sudo로 실행된 경우**(`SUDO_UID`가 있으면): 우선순위는 그대로
    **보존된 절대 `XDG_CONFIG_HOME` → `SUDO_UID`의 passwd 홈**이고,
    root의 `HOME`은 쓰지 않는다. 이유는 왕복이다 — 파일은
    `sudo anago join`이 쓰고 평범한 `anago ls`가 읽으므로 두 실행이 같은
    경로를 골라야 한다. sudo는 기본적으로 `XDG_CONFIG_HOME`을 지우므로
    XDG를 옮겨 쓰는 사람은 `sudo -E`가 필요하고, 그렇지 않은 경우
    passwd 홈이 평범한 실행과 같은 답을 준다. root의 `HOME`을 따르면
    `/root/.config/anago`에 쓰여 정작 본인이 찾지 못한다.
  - 소유권도 같이 넘긴다: 파일은 **그것을 만든 디스크립터에 `fchown`**
    으로 `SUDO_UID`/`SUDO_GID`의 것이 된다(경로 기반 `chown`은 그 사이
    이름이 심볼릭 링크로 바뀌는 경합이 있다). 디렉터리는 **anago가 만들지
    않는다** — root가 사용자 소유 경로에 `mkdir -p`를 하는 것 자체가
    링크를 통한 권한 적용 통로다. 없으면 사람에게 만들라고 안내하고
    멈춘다.
  - 서버 쪽 경로에는 이런 재정의가 없다. `/var/lib/anago/`는 systemd
    유닛이 가리키는 고정 위치이고 root 소유다.

### 9.1 서버 상태 파일 스키마

`version`은 **M1에서 2로 올린다**(M0가 쓴 파일은 1). 읽을 때 규칙은
셋이다:

- `2`: 그대로 읽는다.
- `1`: **인메모리로 승격해 읽는다** — 손실 없는 변환이다(아래 "v1 → v2").
- 그 밖(0, 3 이상, 없음, 정수가 아님): **에러로 중단**한다. 구버전
  바이너리가 신버전 상태를 덮어쓰는 사고를 막는 M0의 규칙 그대로다.

모르는 필드는 무시한다. 시각은 전부 **Unix epoch 초(정수)** — 미니
JSON에 날짜 파싱을 들이지 않기 위해서다.

```json
{
  "version": 2,
  "domain": "net.example.com",
  "subnet": "10.100.0.0/24",
  "listen_port": 51820,
  "api_port": 443,
  "tls": {
    "source": "acme",
    "cert_path": "/var/lib/anago/tls/fullchain.pem",
    "key_path": "/var/lib/anago/tls/privkey.pem",
    "not_after": 1763276000,
    "acme": {
      "directory": "https://acme-v02.api.letsencrypt.org/directory",
      "contact": "jo@example.com",
      "account_key_path": "/var/lib/anago/tls/account.key",
      "account_url": "https://acme-v02.api.letsencrypt.org/acme/acct/1234",
      "challenge": "http-01",
      "issued_at": 1755500000,
      "renew_after": 1760684000
    }
  },
  "cloudflare": {
    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
    "record_id": "372e67954025e0ba6aaa6d586b9e0b59",
    "token_path": "/var/lib/anago/cf-token"
  },
  "server": {
    "private_key": "<wg base64>",
    "public_key": "<wg base64>",
    "address": "10.100.0.1"
  },
  "peers": [
    {
      "name": "macbook",
      "public_key": "<wg base64>",
      "address": "10.100.0.2",
      "token_hash": "<토큰의 SHA-256, hex 64자>",
      "created_at": 1755500000,
      "last_seen": 1755500600
    }
  ],
  "codes": [
    {
      "code": "7QX4-M2KD",
      "issued_at": 1755499000,
      "expires_at": 1755499900,
      "used_at": null
    }
  ]
}
```

| 필드 | 타입 | 의미 |
|---|---|---|
| `version` | 정수 | 스키마 버전. M0 = 1, M1 = 2. 1은 승격해 읽고, 그 밖은 에러 |
| `domain` | 문자열 | `server init --domain` 값. 클라 엔드포인트 조립에 사용 |
| `subnet` | 문자열 | CIDR. /24만 허용한다 |
| `listen_port` | 정수 | wg UDP 포트(기본 51820) |
| `api_port` | 정수 | 컨트롤 API TCP 포트(기본 443) |
| `tls.source` | 문자열 | `"manual"`(사람이 준 인증서) 또는 `"acme"`(anago가 발급·갱신) |
| `tls.cert_path` / `tls.key_path` | 문자열 | 인증서·키 경로. **`source`와 무관하게 항상 채워진다** |
| `tls.not_after` | 정수 \| null | **인증서에 적힌 실제 만료 시각**(epoch 초). 읽지 못했으면 `null` — 아래 |
| `tls.acme` | 객체 \| null | `source`가 `"acme"`일 때만. 아니면 `null` |
| `tls.acme.directory` | 문자열 | ACME 디렉터리 URL. staging과 production을 가르는 것이 이 값이다 |
| `tls.acme.contact` | 문자열 \| null | `--acme-email`. 계정을 다시 만들 때만 쓴다 |
| `tls.acme.account_key_path` | 문자열 | ACME 계정 키 경로(0600). 갱신에 필요하다 |
| `tls.acme.account_url` | 문자열 | 등록된 계정 URL. 있으면 재등록하지 않는다 |
| `tls.acme.challenge` | 문자열 | `"http-01"` 또는 `"dns-01"`. 갱신도 같은 방식으로 한다 |
| `tls.acme.issued_at` | 정수 | 인증서를 받은 시각 |
| `tls.acme.renew_after` | 정수 | **이 시각이 지나면 갱신한다.** 만료(`tls.not_after`)가 아니라 정책이다 — 아래 |
| `cloudflare` | 객체 \| null | Cloudflare 토큰으로 DNS를 만진 적이 있으면. 아니면 `null` |
| `cloudflare.zone_id` | 문자열 | 도메인 → zone 조회 결과 캐시 |
| `cloudflare.record_id` | 문자열 \| null | anago가 만든 A 레코드의 id 캐시. 아직 없거나 무효화됐으면 `null` — 아래 |
| `cloudflare.token_path` | 문자열 \| null | DNS-01일 때만 토큰 파일 경로. 아니면 `null` |
| `server.private_key` / `public_key` | 문자열 | 서버 wg 키쌍(`wg genkey`/`wg pubkey` 산출물, base64) |
| `server.address` | 문자열 | 서버 사설 IP = 서브넷의 .1 |
| `peers[]` | 배열 | 등록 기기. 이름은 유일(§8 `rm`의 키) |
| `peers[].token_hash` | 문자열 | 기기 토큰의 SHA-256 해시(hex 64자). 평문은 저장하지 않는다 — §7.1 |
| `peers[].created_at` | 정수 | join 성공 시각 |
| `peers[].last_seen` | 정수 \| null | 마지막 인증된 API 호출 시각. 아직 없으면 null |
| `codes[]` | 배열 | 발급된 조인 코드. 소진·만료된 항목도 감사 목적으로 남긴다 |
| `codes[].used_at` | 정수 \| null | 소진 시각. null이면 미사용 |

**없는 것은 키를 빼지 않고 `null`을 쓴다.** `tls.acme`도
`cloudflare`도 마찬가지다. 출력이 결정적이어야 하고(§10.1), "없다"가
"이 바이너리는 그 필드를 모른다"와 구별되는 편이 낫다.

#### TLS 출처: `manual`과 `acme`

M0의 평평한 `tls_cert_path`/`tls_key_path`를 `tls` 객체로 바꾼다.
**`cert_path`와 `key_path`는 두 경우 모두 채워진다** — TLS를 로드하는
코드는 `source`를 보지 않고, rustls에 먹일 파일 두 개를 그냥 읽는다.
`source`가 가르는 것은 단 하나, **누가 그 파일을 갱신하는가**다.

- `"manual"`: 사람이 `--tls-cert/--tls-key`로 준 경로. anago는 읽기만
  하고 절대 쓰지 않는다. 갱신도 하지 않는다 — certbot이든 무엇이든
  그 파일을 관리하는 쪽이 따로 있다는 뜻이다. M0의 경로가 그대로
  살아 있는 자리이고, M1에서도 1급 시민이다(§11).
- `"acme"`: anago가 발급했고 anago가 갱신한다. 경로는
  `/var/lib/anago/tls/` 아래로 고정된다.

M0가 쓰던 수동 경로는 이렇게 남는다 — 위 예시와 같은 파일의 다른 모습
이다:

```json
  "tls": {
    "source": "manual",
    "cert_path": "/etc/ssl/anago/fullchain.pem",
    "key_path": "/etc/ssl/anago/privkey.pem",
    "not_after": 1763276000,
    "acme": null
  },
```

이 구분이 상태에 남아야 하는 이유는 갱신 루프 때문이다. 파일만 보면
둘을 구별할 수 없고, 남의 인증서를 anago가 덮어쓰는 것은 되돌릴 수
없는 사고다.

#### v1 → v2 승격

M0 파일에는 `tls_cert_path`/`tls_key_path`가 있고 ACME도 Cloudflare도
없다. 그 상태의 v2 의미는 정확히 하나뿐이라 변환이 전면적이다:

```
tls_cert_path, tls_key_path
  → tls = { source: "manual", cert_path, key_path,
            not_after: null, acme: null }
cloudflare = null
```

`not_after`가 `null`인 것은 승격이 **파일을 읽는 일만** 하기 때문이다 —
인증서를 열어 만료를 뜯어보는 것은 승격의 일이 아니고, 다음에 TLS를
로드할 때 채워진다. 그 밖에는 추측이 들어가는 자리가 없으므로 사람에게
묻지 않고 조용히 승격한다.
다만 **읽는 김에 파일을 고쳐 쓰지는 않는다** — `anago ls`가 상태
파일을 건드리는 것은 놀라운 일이다. 상태를 바꾸는 명령(`code`, join,
`rm`, 인증서 발급)이 저장할 때 자연히 v2로 기록된다.

**다운그레이드는 막힌다.** v2 파일을 M0 바이너리가 열면 위 규칙대로
에러로 멈춘다. 이건 부작용이 아니라 `version`을 둔 목적 그 자체다 —
ACME 정보를 모르는 바이너리가 그 필드를 지운 채 덮어쓰는 것, 그게
막으려던 사고다.

#### 인증서 시각: `not_after`는 사실, `renew_after`는 정책

**두 값을 따로 적는다.** 하나로 합치지 않는 이유는 정하는 주체가 다르기
때문이다.

- **`tls.not_after`** — 인증서에 적힌 실제 만료 시각. CA가 정하고
  우리는 읽기만 한다. `"manual"` 인증서에도 채운다(anago가 갱신하지는
  않지만 만료일은 보여 줄 수 있어야 한다).
- **`tls.acme.renew_after`** — 이 시각이 지나면 갱신을 시도한다.
  우리가 정하고, 사람이 파일을 열어 앞당길 수도 있다. 발급하는 순간
  `issued_at + 60일`로 계산해 적는다.

기본 갱신 판정은 `now >= renew_after` 한 줄이고, 코어의 순수 함수라
경계값까지 테스트된다. **`not_after`는 그 판정의 안전망**이다: 가정한
수명보다 짧은 인증서를 받아 `renew_after`가 `not_after`를 넘어서 있으면
그 자체가 잘못된 상태이므로, 판정 함수는 `min(renew_after, not_after -
여유)`로 시점을 앞당기고 그 사실을 로그와 `server status`(M3)가 말한다.
이 안전망이 §10.2에서 x509 파서를 끄면서 남겨 둔 구멍 — "LE가 단기
인증서로 바뀌면 60일 규칙이 늦는다" — 을 스키마 차원에서 막는다.

**`not_after`는 어디서 오는가.** §10.2대로 `x509-parser`는 켜지 않는다
(그건 ARI용이고 ASN.1 파서 계열을 십수 개 끌고 온다). 대신 **바이너리가
이미 있는 `rustls-pemfile`로 PEM을 DER로 풀고, 코어의 순수 함수가 그
DER에서 `notAfter` 한 필드만 읽는다.** 경로는 고정돼 있다:
`Certificate` → `TBSCertificate` → `Validity` → 두 번째 `Time`.
UTCTime과 GeneralizedTime 둘 다 받아 epoch 초로 바꾼다. 체인 파일이면
첫 인증서(엔드 엔티티)를 본다.

이것이 §10.2가 QR 인코더를 코어에서 거절한 것과 어긋나지 않는 이유는
성격이 다르기 때문이다. QR 인코더는 리드-솔로몬·마스킹까지 갖춘 **범용
라이브러리**를 코어에 들이는 일이고, 이쪽은 이미 손에 쥔 바이트에서
**필드 하나를 꺼내는 읽기**다. 무엇보다 **신뢰 판정에 쓰이지 않는다** —
인증서 검증은 rustls가 하고(§7), 이 값은 갱신 일정과 표시에만 쓴다.
그래서 실패해도 안전하다: **읽지 못하면 `not_after`는 `null`이고**,
갱신은 `renew_after`만으로 그대로 돈다. 파싱 버그가 낼 수 있는 최악은
"만료일을 표시하지 못한다"이지 "붙지 못한다"가 아니다.

`renew_after`를 굳이 따로 저장하는 이유도 같은 결이다. 규칙은 언젠가
바뀐다 — LE가 단기 프로파일을 기본으로 돌리거나 ARI(RFC 9773)를 켜면,
그때 바뀌는 것은 `renew_after`를 **계산하는 코드**뿐이고 스키마도 이미
발급된 허브의 예정 시각도 흔들리지 않는다.

#### Cloudflare 캐시: `zone_id`와 `record_id`

`zone_id`(도메인이 사는 zone)와 `record_id`(anago가 만든 A 레코드)를
캐시한다. 캐시는 조용히 낡을 수 있으므로 규칙을 못박는다.

- **생성**: zone은 도메인에서 찾은 직후 `zone_id`에, A 레코드는 만들거나
  고친 직후 응답이 준 id를 `record_id`에 적는다.
- **조회**: 캐시가 있어도 **upsert 전 레코드 목록 조회를 건너뛰지
  않는다.** 프록시(주황 구름)가 켜졌는지 봐야 하고(§13) 값이 이미
  맞는지도 봐야 한다. 그러니까 `record_id`가 하는 일은 왕복을 줄이는 게
  아니라 **어느 레코드가 우리 것인지 지목하는 것**이다 — 같은 이름에 A
  레코드를 여럿 둘 수 있으므로(라운드로빈), 캐시가 없으면 우리가 만들지
  않은 레코드를 골라 고칠 위험이 있다. 반면 `zone_id`는 진짜로 왕복을
  줄인다: DNS-01 갱신은 TXT를 만들기만 하면 되고 zone 목록을 볼 이유가
  없다.
- **무효화**: 목록에 캐시된 `record_id`가 없으면(사람이 대시보드에서
  지웠다) 캐시를 `null`로 만들고 새로 만든 뒤 새 id를 적는다.
  `zone_id`가 바뀌면 — 도메인을 다른 zone으로 옮겼다 — `record_id`도
  함께 무효화한다. 다른 zone의 레코드 id는 의미가 없다.
- **거부는 무효화가 아니다**: 캐시가 가리키는 레코드가 프록시 켜짐이거나
  A가 아니면 **멈추고 사람에게 알리되 캐시는 유지한다**(§13). 사람이
  고쳐야 하는 상태이지 anago가 지우고 새로 만들 상태가 아니다.

**DNS-01의 TXT 레코드 id는 캐시하지 않는다.** 챌린지마다 만들고 검증
직후 지우는, 수명이 분 단위인 레코드다. 상태에 남기면 정리에 실패했을
때 다음 실행이 지워야 할 유령을 물려받는다 — 이름
(`_acme-challenge.<domain>`)으로 조회해 지우는 쪽이 언제나 옳다.

#### Cloudflare 토큰은 상태 파일에 없다

토큰은 **DNS-01로 갱신해야 할 때만** `/var/lib/anago/cf-token`(0600)에
남기고, 상태에는 `cloudflare.token_path`만 적는다. A 레코드만 만들고
HTTP-01로 발급했다면 토큰은 `server init`이 끝나는 순간 잊는다 —
`token_path`는 `null`이 된다.

§7.1의 논리를 그대로 적용한 것이다. 없앨 수 있는 비밀은 없앤다. 없앨
수 없을 때도 **상태 파일과는 분리한다**: 상태 파일이 통째로 새는 경로
(백업, 이슈에 붙인 덤프)가 서버 침해보다 흔하다는 것이 §7.1의 전제였고,
그때 DNS 편집 권한을 가진 토큰이 같이 나가지 않는 편이 낫다. 분리하면
토큰 회전도 상태 파일을 건드리지 않고 된다.

#### 아직 없는 것

`endpoint`·`last_handshake` 필드는 **M1에도 없다**. 허브-스포크에서
기기 엔드포인트는 서버가 wg 커널에서 관측하는 값이고(`anago ls`는
`wg show`에서 읽는다), 기기 관측 엔드포인트 보고는 M2의
`/api/v1/endpoint`가 생길 때 스키마와 함께 들어온다. 그때
`version`을 3으로 올린다.

### 9.2 기기 파일 스키마 (클라, M0)

`~/.config/anago/device.json`(§9의 경로 규칙). 0600.

```json
{
  "version": 1,
  "domain": "net.example.com",
  "api_port": 443,
  "name": "macbook",
  "address": "10.100.0.2",
  "subnet": "10.100.0.0/24",
  "token": "<64 hex>",
  "server_public_key": "<wg base64>",
  "server_endpoint": "net.example.com:51820",
  "server_address": "10.100.0.1"
}
```

모든 필드가 필수다. 특히 `api_port`가 없는 파일은 **443으로 가정하지
않고 거부한다** — 이 필드가 생기기 전의 빌드도 `--api-port`를 받았지만
그 값을 저장하지 않았으므로, 없다는 것은 "443"이 아니라 "모른다"는
뜻이다. 복구는 **파일에 `"api_port"`를 손으로 적어 넣는 것 하나**다:
이 파일과 wg 설정이 남아 있는 한 다시 join하는 길은 막혀 있고(§6.2의
중복 가입 방지), 허브에는 이미 같은 이름이 등록돼 있다.

join 응답(§8)에 기기가 접속에 쓴 `api_port`를 더해 담는다 — 기기가
나중에 `ls`/`rm`을 하려면 토큰과 도메인과 **포트**가(서버가
`--api-port`로 초기화됐을 수 있다), wg 설정을 다시 만들려면 나머지가 필요하기 때문이다. **wg
개인키는 여기 없다**: `/etc/wireguard/anago.conf`에만 있고 서버로도
가지 않는다(§6.2). `name`은 서버가 정규화해 돌려준 이름이라 `anago rm`
이 그대로 쓸 수 있다.

## 10. 기술 스택

| 영역 | 선택 | 비고 |
|---|---|---|
| CLI | 수제 플래그 파서 (krill args.rs 이식) | 의존 최소 — krill에서 검증됨 |
| 서버 HTTP | tokio + axum + axum-server + rustls(ring) + rustls-pemfile | krill serve 경험 재활용. TLS 백엔드는 **ring** — rustls 기본값인 aws-lc-rs는 C 툴체인(cmake 등)을 요구해 "stock VPS에서 그냥 빌드된다"를 깬다. 압축·트레이싱·multipart는 끄지만 **HTTP/2는 끄지 못한다** — axum-server가 `hyper/http2`와 `hyper-util/server-auto`를 켜기 때문이다. M0 API는 h1/h2 어느 쪽으로 와도 같은 JSON을 답하므로 기능 문제는 아니고, 굳이 h1으로 좁히려면 리스너에서 ALPN을 `http/1.1`만 광고하면 된다 |
| ACME | **`instant-acme`** (기본 feature off, `ring`+`rcgen`+`hyper-rustls`) | HTTP-01 기본, DNS-01(Cloudflare) 지원. 기본 feature를 그대로 받으면 aws-lc-rs가 딸려와 위 rustls 결정이 무너진다 — §10.2 |
| Cloudflare | **기존 `client.rs`(블로킹 rustls 클라이언트) 확장** | A 레코드 upsert + DNS-01 TXT. reqwest도 hyper client도 새로 들이지 않는다 — §10.2 |
| wg 제어 | `wg`/`wg-quick` CLI 래핑 | 위임 원칙. boringtun 내장은 백로그(비-커널 환경) |
| QR (`--export qr`) | **`qrcodegen`** (바이너리) + 코어의 터미널 렌더링 | 인코딩은 위임, 화면에 그리는 일은 순수 함수 — §10.2 |
| 직렬화 | **anago-core의 수제 미니 JSON (순수 std)** | anago 자신의 프로토콜·상태 — serde 미사용, §10.1. 제3자(ACME·Cloudflare) JSON만 바이너리에서 `serde_json` — §10.2 |
| 해시(기기 토큰) | `sha2` (바이너리 직접 의존성) | SHA-256만 사용 — §7.1. 전이 의존성에 기대지 않는다 |
| 파일 락 | `libc`의 `flock(2)` (바이너리 직접 의존성) | std에 파일 락이 없다 — §13의 동시 join 직렬화 |
| anago-core | 순수 std | 설정 생성·IP 할당·코드 검증·프로토콜 타입 — 전부 순수 함수로 유닛 테스트. **M1에서도 외부 크레이트 0개** — §10.2 |

### 10.1 직렬화 결정: serde를 쓰지 않는다

**anago의 프로토콜 타입과 서버 상태 파일은 anago-core에 넣은 수제
미니 JSON 인코더/파서(순수 std)로 직렬화한다. serde·serde_json은
쓰지 않는다.**

이유는 하나다. §4 원칙 4와 §8이 "스키마의 원본은 anago-core의 타입"
이라고 못박았는데 core는 순수 std라 serde를 쓸 수 없다. 그러면 남는
선택지는 (a) 타입을 core와 바이너리에 이중으로 두고 손으로 동기화
하거나, (b) 스키마 원본을 바이너리로 옮겨 원칙 4를 깨거나, (c) core
안에서 직렬화까지 끝내는 것뿐이다. (a)는 두 정의가 어긋나는 순간
프로토콜이 조용히 깨지고, (b)는 원본 위치를 뒤집는 설계 변경이다.
(c)를 고른다: 필요한 JSON 표면이 작고(위 스키마 + §8의 4개 타입),
전부 순수 함수라 유닛 테스트가 그대로 게이트가 된다.

미니 JSON의 지원 범위를 좁게 고정한다 — 범용 JSON 라이브러리를
만들 생각이 없다:

- 값: 객체·배열·문자열·정수·불·널. **부동소수는 지원하지 않는다**
  (소수점·지수 표기는 파싱 에러). 스키마에 실수가 필요해지면 이
  문서를 먼저 고친다.
- 정수는 `i64` 하나로 통일한다 — 스키마의 정수는 버전·포트·epoch 초
  뿐이라 i64로 충분하고, 부호 유무로 타입을 나누면 파서만 복잡해진다.
  범위를 넘으면 에러.
- 문자열은 UTF-8, `\u` 이스케이프 디코딩 지원. 출력은 필요한 문자만
  이스케이프.
- 객체의 중복 키는 에러(마지막 값 채택 같은 조용한 처리 금지).
- 출력은 **결정적**이다: 필드는 타입에 선언된 순서로 나간다. 상태
  파일은 사람이 읽고 고칠 수 있게 2칸 들여쓰기, API 응답은 압축 형식.

serde가 다시 논의되는 경우는 하나뿐이다: M1에서 ACME·Cloudflare의
**제3자 JSON 스키마**를 다뤄야 할 때. 그건 남의 스키마이고 바이너리
크레이트에만 필요하므로 이 결정과 충돌하지 않는다. **그 판단은 §10.2
에서 내렸다 — `serde_json`을 바이너리 직접 의존성으로 두고, 제3자
응답에만 쓴다.** anago 자신의 프로토콜·상태가 serde로 넘어가는 일은
없다.

### 10.2 M1 의존성 확정 — ACME·Cloudflare·QR

M1이 새로 들이는 **직접** 의존성은 셋이다: `instant-acme`(ACME),
`serde_json`(제3자 JSON), `qrcodegen`(QR 인코딩).

**셋 다 `crates/anago` 바이너리 크레이트에만 선언한다. anago-core는
M1에서도 외부 크레이트를 한 개도 갖지 않는다.** §4 원칙 4의 선은
마일스톤이 바뀌어도 움직이지 않는다 — 코어가 M1에서 맡는 것도 여전히
순수 함수뿐이다(갱신 시점 판정, 챌린지 문자열 조립, DNS 레코드 upsert
판정, sync 판정, QR 렌더링).

#### ACME — `instant-acme`, 기본 feature는 끈다

```toml
instant-acme = { version = "0.8", default-features = false,
                 features = ["ring", "rcgen", "hyper-rustls"] }
```

- **`default-features = false`는 취향이 아니라 요구사항이다.**
  instant-acme의 기본 feature는 `aws-lc-rs`를 고른다. 그대로 받으면
  위 표의 rustls 결정(ring)이 무너지고, aws-lc-rs가 요구하는 C
  툴체인이 "stock VPS에서 그냥 빌드된다"는 이 프로젝트의 배포 전제를
  깬다. 같은 이유로 rustls를 ring으로 고정했으니 ACME도 같은 백엔드를
  쓴다 — 한 바이너리 안에 암호 백엔드를 두 벌 넣을 이유가 없다.
- **`rcgen`**: 인증서 개인키와 CSR을 만든다. `Order::finalize()`가
  내부에서 키를 생성하고 CSR을 서명해 개인키 PEM을 돌려주므로 우리는
  `rcgen`을 직접 부르지 않는다(직접 의존성이 아니라 feature다). ASN.1
  과 서명을 우리가 짜지 않는 것은 §3·§4 원칙 1 그대로다.
- **`hyper-rustls`**: instant-acme이 자기 HTTP 스택으로 쓴다.
  `HttpClient` 트레이트가 열려 있어 우리 클라이언트를 꽂고 이 feature를
  뺄 수도 있지만, 그러자고 async 어댑터를 손으로 짜는 것은 "어려운
  문제는 위임한다"의 반대 방향이다. hyper·hyper-util은 axum-server
  때문에 어차피 트리에 있다.
  - 부작용 하나는 적어 둔다: 이 feature가 `rustls-platform-verifier`를
    끌고 와서, 한 바이너리 안에 트러스트 루트 경로가 두 벌이 된다(기기
    쪽 `rustls-native-certs`, ACME 쪽 platform-verifier). ACME는 공개
    CA(Let's Encrypt)만 상대하므로 §11의 origin-cert 단서와 무관하고,
    **어느 쪽도 검증을 끄지 않는다**.
- **켜지 않는 것: `x509-parser`·`time`.** 둘은 ARI(RFC 9773)의 갱신
  창을 읽기 위한 것이고, 그 대가로 ASN.1 파서 계열이 십수 개 따라온다.
  M1의 갱신 시점은 ARI 없이 정한다 — 그 규칙(무엇을 상태에 적고 언제
  갱신하는가)은 §9.1에서 확정한다. 인증서의 `notAfter`는 상태에 적지만
  (§9.1의 `tls.not_after`) 그것 때문에 이 feature를 켜지는 않는다:
  PEM→DER은 이미 있는 `rustls-pemfile`이 하고, DER에서 그 필드 하나를
  읽는 것은 코어의 순수 함수다.
- **비동기 경계**: instant-acme은 async다. ACME 작업은 언제나 tokio
  런타임 안에서 돈다 — `server run`은 이미 런타임이 있고, `server init`
  은 발급 구간에만 런타임을 잠깐 띄운다. HTTP-01 챌린지에 답할 :80
  리스너도 이미 있는 tokio/axum으로 세운다(새 의존성 없음).
- **라이선스**: instant-acme은 Apache-2.0이다(anago는 MIT). 퍼미시브라
  배포에 문제는 없지만 M4의 릴리스 산출물에 NOTICE를 챙겨야 한다.

#### Cloudflare — 새 HTTP 클라이언트를 들이지 않는다

표의 "hyper 직접"을 **기존 `client.rs`(블로킹 rustls 클라이언트) 확장**
으로 확정한다. `join`/`ls`/`rm`이 이미 쓰는 코드이고, 요청 조립과 응답
파싱이 순수 함수로 테스트돼 있다. 남은 일은 임의 호스트·헤더·메서드를
받게 넓히는 것뿐이라 reqwest는 물론 hyper의 클라이언트 API도 새로
배우지 않는다.

DNS-01 흐름은 async 안에 있으므로 Cloudflare 호출은 `spawn_blocking`
으로 부른다. 어댑터가 몇 줄이고, 대신 **anago가 밖으로 내는 HTTP는 한
벌로 유지된다** — 타임아웃·트러스트 루트·에러 문구가 두 군데로 갈라지지
않는 쪽이 유지비가 싸다.

#### 제3자 JSON — `serde_json`을 바이너리에 직접 선언한다

§10.1이 "serde가 다시 논의되는 경우는 하나뿐"이라며 예약해 둔 그
순간이다. 여기서 판단한다: **ACME·Cloudflare 응답은 `serde_json`으로
읽는다.**

왜 코어의 미니 JSON을 쓰지 않는가. 미니 JSON의 엄격함(부동소수 거부,
중복 키 거부, `i64` 하나)은 **우리 스키마에 대해서는** 옳다 — 스키마를
우리가 정하니까 좁혀도 안전하다. 남의 스키마에는 정확히 반대로 작용
한다. Cloudflare 응답의 `meta`처럼 우리가 읽지도 않는 구석에 실수나
스키마 변경이 하나 들어오면 응답 **전체**가 파싱 에러가 되고, A 레코드
upsert가 무관한 이유로 죽는다. 남의 JSON에는 관대한 파서가 맞다.

비용은 사실상 0이다: `serde_json`은 instant-acme 때문에 어차피 트리에
들어온다. 그래도 §7.1의 `sha2`와 같은 이유로 **직접 의존성으로 선언**
한다 — 전이 의존성에 기대어 남의 크레이트를 부르지 않는다.

선은 그대로 유지된다: **우리 타입을 serde로 정의하지 않는다.** 제3자
응답은 `serde_json::Value`에서 필요한 필드만 뽑아 즉시 anago-core의
타입(§8, §9.1)으로 옮긴다. `#[derive(Serialize)]`가 붙은 anago 타입은
M1에도 없다.

#### QR — `qrcodegen`으로 인코딩, 렌더링은 코어의 순수 함수

인코딩은 **`qrcodegen` 1.8**(MIT, 의존성 0)에 맡긴다. 직접 구현하지
않는 이유는 §4 원칙 1과 같다 — 리드-솔로몬·마스킹·버전 선택은 이미 잘
풀린 문제이고, 우리가 다시 풀면 "폰이 스캔을 못 한다"는 형태로만 틀린다.
게다가 그 실패는 유닛 테스트로 잡히지 않고 실기기에서만 드러난다.

대신 **화면에 그리는 일은 anago-core가 한다**: 바이너리가
`qrcodegen`에서 모듈 행렬(불리언)을 받아 넘기면, 코어의 순수 함수가
그것을 터미널 문자열(블록 문자·여백)로 만든다. 크레이트 없이 유닛
테스트되는 표면이 이쪽이고, 이 분리 덕에 QR 출력의 회귀가 `cargo test`
에 걸린다.

코어가 인코더까지 갖는 선택지는 버린다. 순수 std로 못 할 일은 아니지만,
그건 코어를 "우리 규칙을 담는 곳"에서 "우리가 만든 라이브러리를 담는
곳"으로 바꾸는 변경이다 — §4 원칙 4가 코어에 그어 둔 선은 "외부 크레이트
금지"이지 "무엇이든 직접 만든다"가 아니다.

#### 새로 들어오는 전이 의존성

위 셋을 더하면 잠금 파일에 **약 20개**가 추가된다(instant-acme,
`rcgen`, `hyper-rustls`, `rustls-platform-verifier`, `serde_json`,
`thiserror`, `base64`, `pem` 등). **그중 C 툴체인을 새로 요구하는 것은
하나도 없다** — aws-lc-rs를 끈 이유가 이것이다. 빌드 스크립트가 있는
것은 셋뿐이고(`serde_json`·`thiserror`·`zmij`) 전부 rustc 버전을 묻는
순수 러스트 프로브다. 이 성질은 M4의 "어느 VPS에서나 `cargo build`"를
지키는 조건이므로, 앞으로 의존성을 더할 때마다 같은 확인을 한다.


## 11. 마일스톤

| 단계 | 내용 | 검증 |
|---|---|---|
| M0 | `server init`(DNS는 수동 안내, TLS는 기존 인증서 지정 — 아래 참조) + `join` + 허브-스포크 통신 + `code`/`ls`/`rm` | 실서버: Cloudflare 도메인 + VPS에서 기기 2대 연결, 서로 ping |
| M1 | ACME 자동 TLS + Cloudflare A 레코드/DNS-01 자동화 + `sync` timer + `--export qr` | 폰(공식 wg 앱) 합류 |
| M2 | 홀펀칭 직결: STUN 관측 → /endpoint 보고 → 서버가 중개 → 실패 시 허브 폴백 유지 | LTE↔집공유기 직결 성사율 측정 |
| M3 | 이름 해석(`맥북.net.example.com` 또는 /etc/hosts 갱신), `server status` 대시보드 | |
| M4 | 릴리스: CI + 태그 릴리스 + Homebrew — krill의 워크플로 재활용 | |

**현재 상태(2026-08)**: M0는 **코드가 완성**됐다 — `server init`,
`server run`, `code`, `join`, `ls`, `rm`이 모두 동작하고, 코어는 순수
함수로 유닛 테스트되며 수명주기 시나리오 테스트가 있다. 아직 남은 것은
표의 "검증" 열이다: 실 VPS·도메인·인증서로 기기 2대를 붙여 서로 ping하는
확인은 사람이 해야 하고(§12의 규칙), 항목은 리포지토리 루트의
`HUMAN-VERIFY.md`에 있다. 그 확인이 끝나기 전까지 M0는 "구현 완료,
미검증"이다.

M0의 TLS: 조인 코드가 평문으로 다니면 안 되므로 **TLS는 M0부터 필수**다.
M0에서는 ACME 자동화 없이 "이미 있는 인증서 경로를 지정"(`--tls-cert/key`)
도 받게 해 부트스트랩 문제를 피하고, M1에서 ACME로 완전 자동화한다.

**Cloudflare origin cert의 단서**: M0의 기기는 서버에 직접 붙고, 검증은
기기의 OS 신뢰 저장소로 한다. origin cert는 공개 신뢰가 아니므로 그대로
쓰면 `join`이 `UnknownIssuer`로 실패한다 — 쓰려면 합류하는 모든 기기에
Origin CA를 설치해야 한다. 기본 경로는 공개 신뢰 인증서(Let's Encrypt 등)
이고, origin cert가 1급 시민이 되는 것은 Cloudflare를 앞단에 두는 구성이
생길 때다.

**실검증 환경**: 소유자의 개인 도메인(Cloudflare 등록) + VPS. 따라서
Cloudflare 경로(A 레코드 자동화, DNS-01, origin cert)가 1차 시민이고
모든 마일스톤의 실기기 검증은 이 환경에서 한다.

## 12. 개발 방식 — krill로 만든다 (dogfood)

이 프로젝트는 **krill의 협업 모드로 개발한다**: 마일스톤을 `krill plan`
으로 분해·승인하고, 작업 슬라이스는 `krill duet`(worker + reviewer 교차
모델, gate = `cargo test`)으로 구현한다. 도구로 도구를 만들었던 krill의
부트스트래핑을 한 단계 확장하는 실험이자, krill §12(협업 모드)의 실전
검증장이다. 발견되는 krill의 문제는 krill 리포의 백로그로 환류한다.

에이전트 작업 규칙(CLAUDE.md에도 요약):
- 작업 전 이 문서를 읽는다. 설계 변경은 문서 갱신이 먼저다.
- anago-core는 순수 std 유지, env를 바꾸는 테스트 금지(씸 패턴 — krill
  CLAUDE.md의 규칙과 동일).
- 실서버가 필요한 검증은 에이전트가 하지 않는다 — 모킹 대신 순수 함수
  분리로 테스트하고, 실기기 검증 항목은 PR 본문에 "사람 확인 필요"로
  명시한다.

## 13. 리스크와 열린 질문

- **wg-quick 의존의 플랫폼 편차**: 맥은 wireguard-tools(brew), 리눅스는
  배포판 패키지. 설치 확인·안내를 join이 해준다. Windows는 v1 비대상
  (WSL2 안내).
- **VPS 방화벽/보안그룹**: :443(API)·:51820/udp(wg)·(HTTP-01이면 :80)을
  열어야 한다. init이 감지는 못 하니 체크리스트로 안내하고, 연결 실패
  시 진단 메시지(`anago server status`가 포트 리스닝 확인)를 준다.
  인바운드만으로는 부족하다: 기기 간 패킷은 허브를 **경유**하므로 호스트
  방화벽의 FORWARD 정책도 `anago`→`anago`를 허용해야 한다. UFW처럼
  라우팅 기본값이 거부인 구성에서 "허브에는 닿는데 기기끼리는 안 닿는"
  증상이 나오는 흔한 원인이고, anago는 wg 설정에 `PostUp` 규칙을 넣지
  않으므로(설정 파일이 곧 상태라는 성질을 지키려고) 운영자 몫이다.
- **Cloudflare 프록시**: A 레코드가 프록시(주황 구름)면 이름이 Cloudflare
  주소로 해석되고 `51820/udp`는 전달되지 않는다. M0는 기기가 서버에 직접
  붙으므로 **DNS only**여야 한다. §11의 실검증 환경이 Cloudflare 도메인
  이라 특히 밟기 쉽다.
- **홀펀칭 성사율(M2)**: 대칭 NAT/CGNAT에서 실패가 정상. 폴백이 기본
  경로라 기능 저하일 뿐 장애가 아니다 — 측정해서 문서에 싣는다.
- **서버 상태 파일 단일화**: 동시 join은 드물지만 파일 락(flock)으로
  직렬화한다. 락은 `state.json`이 아니라 옆의 `state.lock`에 건다 —
  상태 파일은 tmp+rename으로 교체되므로 그 자체를 잠그면 각 writer가
  서로 다른 inode(하나는 이미 unlink된)를 잠그게 되어 직렬화가 무너진다.
- **이름(anago) 충돌**: crates.io 확인 필요(프록시로 미확인). 바이너리
  이름과 크레이트 이름은 분리 가능하므로 블로커 아님.

---

*다음 단계: M0는 코드가 끝났으니(§11) 실서버 검증 — Cloudflare 도메인과
VPS에서 기기 2대를 붙여 서로 ping하는 것 — 이 먼저다. 그게 지나면 M1
(ACME 자동 TLS + Cloudflare DNS 자동화 + `sync` timer + `--export qr`).
문서의 모든 결정은 여전히 뒤집을 수 있다.*
