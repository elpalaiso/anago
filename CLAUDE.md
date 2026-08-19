# anago

도메인+상주 기기(VPS든 집의 윈도우 PC·맥미니든)를 가진 사람을 위한
셀프호스트 WireGuard 개인 네트워크 부트스트래퍼.
**전체 설계는 docs/DESIGN.md — 작업 전에 반드시 먼저 읽을 것.**

## 현재 상태

M0(허브-스포크 코어)·M1(ACME/Cloudflare 자동화·sync 타이머·폰 QR)
**코드 완성, 실서버 미검증**(HUMAN-VERIFY.md가 검증 러너북).
진행 중: **M1.5 — 허브 플랫폼 확장**(Windows 서비스·macOS launchd 허브
1급 지원, 설계는 DESIGN §11.1). M0·M1은 krill plan/duet으로 개발했고,
M1.5는 이 세션에서 직접 개발한다(사용자 결정).

## 설계 원칙 (요약 — 상세는 DESIGN.md §4)

1. 어려운 문제(암호화·터널·TLS·상주·DNS)는 WireGuard/rustls·ACME/systemd/
   Cloudflare API에 위임한다. anago가 직접 푸는 건 조율(키·엔드포인트
   교환)과 UX(셋업 마법사) 둘뿐이다.
2. 허브-스포크(서버 경유)가 기본이라 첫날부터 "항상 된다". 홀펀칭 직결
   (M2)은 성능 최적화이지 정합성 요건이 아니다.
3. 단일 바이너리가 서버/클라 양쪽 역할(서브커맨드). 서버만 상주가 정당,
   클라는 wg 커널 + systemd timer로 사실상 데몬 0.
4. 암호 프리미티브는 한 줄도 직접 만들지 않는다.

## 구조

- `crates/anago-core` — 라이브러리: 순수 std만. 프로토콜 타입, IP 할당,
  wg 설정 생성, 조인 코드 검증 — 전부 순수 함수로 유닛 테스트.
- `crates/anago` — 바이너리: CLI 디스패치, 서버(tokio/axum/rustls),
  `wg`/`wg-quick`/systemd 래핑. 의존성은 바이너리 크레이트에만.

## 빌드와 테스트

`cargo build` → `target/debug/anago`. `cargo test` = 코어 유닛 테스트.
테스트는 env를 변경하지 않는다 — env 의존 로직은 순수 함수 씸으로 분리해
테스트한다 (krill과 같은 패턴).

## 에이전트 작업 규칙 (krill duet/plan으로 개발됨)

- 설계 변경은 DESIGN.md 갱신이 먼저다.
- anago-core에 외부 크레이트 추가 금지.
- 실서버(VPS·DNS·인증서)가 필요한 검증은 에이전트가 시도하지 않는다:
  순수 함수로 분리해 테스트하고, 실기기 검증 항목은 "사람 확인 필요"로
  명시해 남긴다.
- 리뷰어 지적은 REVIEW.md, 게이트는 `cargo test` — krill 심판의 지시를
  따른다. 시키지 않은 커밋은 하지 않는다.
