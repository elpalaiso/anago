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
4. systemd 유닛 설치·기동(`--no-systemd`로 포그라운드 실행도 가능 —
   컨테이너/비-systemd 환경).
5. 조인 코드 발급·출력: `anago join net.example.com CODE-XXXX`.

### 6.2 기기 등록 (각 기기에서 1회)

```
anago join net.example.com CODE-XXXX
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
  코드 = 등록 권한 그 자체이므로 짧게 살고 즉시 죽는다.
- **키**: wg 개인키는 각 기기 로컬에만(0600). 서버 상태 파일에는 공개키·
  IP·이름만. 기기 제거 = `anago rm <이름>` → 서버가 피어에서 제거, 다음
  sync 때 각 기기 설정에서도 사라진다.
- **API 인증**: join 이후의 호출(sync 등)은 join 때 발급되는 기기 토큰
  (bearer)으로. 토큰은 기기 로컬 저장(0600).
- **Cloudflare 토큰**: DNS 편집 권한만 가진 스코프 토큰을 요구하도록
  문서화. 서버에 저장 시 0600, `server init` 완료 후엔 인증서 갱신
  (DNS-01일 때)에만 사용.

## 8. 인터페이스 스펙 (CLI)

```
anago server init --domain <d> [--cf-token <t>] [--subnet 10.100.0.0/24]
                  [--port 51820] [--no-systemd]
anago server status                # 서버에서: 피어·마지막 handshake·트래픽
anago code                         # 서버에서: 조인 코드 발급
anago join <domain> <code> [--name 맥북] [--export qr|conf]
anago sync                         # 피어 목록 당겨와 wg 설정 갱신 (timer가 부름)
anago ls                           # 어디서든: 기기 목록·상태 (API 경유)
anago ping <이름>                  # 사설 IP 조회 + ping 위임
anago rm <이름>                    # 기기 제거 (서버 반영)
```

컨트롤 API(v1, JSON over HTTPS — 스키마는 anago-core의 타입이 원본):

| 메서드/경로 | 인증 | 역할 |
|---|---|---|
| POST /api/v1/join | 조인 코드 | 공개키 등록 → IP 할당·서버 정보 응답 |
| GET  /api/v1/peers | 기기 토큰 | 피어 목록(공개키·IP·이름·엔드포인트) |
| POST /api/v1/endpoint | 기기 토큰 | (M2) 자기 관측 엔드포인트 보고 |
| DELETE /api/v1/peers/{name} | 기기 토큰 | 기기 제거 |

## 9. 서버 상태와 설정

- 상태: `/var/lib/anago/state.json` — 서브넷, 서버 키쌍, 피어 목록
  (이름·공개키·IP·토큰 해시·마지막 sync), 발급된 조인 코드. 단일 파일,
  원자적 쓰기(tmp+rename). DB 없음.
- 인증서: `/var/lib/anago/tls/` (ACME 계정·인증서·키).
- 클라: `~/.config/anago/`(도메인·기기 토큰), wg 설정은
  `/etc/wireguard/anago.conf`(wg-quick 규약 위임).

## 10. 기술 스택

| 영역 | 선택 | 비고 |
|---|---|---|
| CLI | 수제 플래그 파서 (krill args.rs 이식) | 의존 최소 — krill에서 검증됨 |
| 서버 HTTP | tokio + axum + rustls | krill serve 경험 재활용 |
| ACME | instant-acme (또는 동급) | HTTP-01 기본, DNS-01(Cloudflare) 지원 |
| Cloudflare | 얇은 REST 호출 (reqwest 없이 가능하면 hyper 직접) | A 레코드 upsert + DNS-01 TXT |
| wg 제어 | `wg`/`wg-quick` CLI 래핑 | 위임 원칙. boringtun 내장은 백로그(비-커널 환경) |
| 직렬화 | serde + serde_json | 바이너리 크레이트에만 |
| anago-core | 순수 std | 설정 생성·IP 할당·코드 검증·프로토콜 타입 — 전부 순수 함수로 유닛 테스트 |

## 11. 마일스톤

| 단계 | 내용 | 검증 |
|---|---|---|
| M0 | `server init`(DNS는 수동 안내, TLS는 기존 인증서 지정 — 아래 참조) + `join` + 허브-스포크 통신 + `code`/`ls`/`rm` | 실서버: Cloudflare 도메인 + VPS에서 기기 2대 연결, 서로 ping |
| M1 | ACME 자동 TLS + Cloudflare A 레코드/DNS-01 자동화 + `sync` timer + `--export qr` | 폰(공식 wg 앱) 합류 |
| M2 | 홀펀칭 직결: STUN 관측 → /endpoint 보고 → 서버가 중개 → 실패 시 허브 폴백 유지 | LTE↔집공유기 직결 성사율 측정 |
| M3 | 이름 해석(`맥북.net.example.com` 또는 /etc/hosts 갱신), `server status` 대시보드 | |
| M4 | 릴리스: CI + 태그 릴리스 + Homebrew — krill의 워크플로 재활용 | |

M0의 TLS: 조인 코드가 평문으로 다니면 안 되므로 **TLS는 M0부터 필수**다.
M0에서는 ACME 자동화 없이 "이미 있는 인증서 경로를 지정"(`--tls-cert/key`,
Cloudflare origin cert 등)도 받게 해 부트스트랩 문제를 피하고, M1에서
ACME로 완전 자동화한다.

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
- **홀펀칭 성사율(M2)**: 대칭 NAT/CGNAT에서 실패가 정상. 폴백이 기본
  경로라 기능 저하일 뿐 장애가 아니다 — 측정해서 문서에 싣는다.
- **서버 상태 파일 단일화**: 동시 join은 드물지만 파일 락(flock)으로
  직렬화한다.
- **이름(anago) 충돌**: crates.io 확인 필요(프록시로 미확인). 바이너리
  이름과 크레이트 이름은 분리 가능하므로 블로커 아님.

---

*다음 단계: 이 설계가 괜찮으면 M0(server init + join, 허브-스포크)부터.
문서의 모든 결정은 뒤집을 수 있는 초안이다.*
