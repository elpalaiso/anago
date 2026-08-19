# M1 구현 계획

범위(DESIGN.md §11 M1): ACME 자동 TLS 발급·갱신(HTTP-01 기본, Cloudflare
토큰이 있으면 DNS-01) + Cloudflare A 레코드 자동 upsert + `anago sync`
(피어 목록을 당겨 wg 설정 갱신) + systemd timer(맥 launchd) 주기 실행
설치 + `anago join --export qr|conf`(공식 WireGuard 앱용, 폰 경로).

M0의 수동 경로는 **그대로 남긴다** — `--tls-cert/--tls-key`로 기존
인증서를 지정하는 길과 A 레코드 수동 안내는 계속 동작하고, 자동화는
그 위에 얹는다. 홀펀칭 직결(M2), 이름 해석·`server status`(M3)는 이
계획에 없다.

규칙(CLAUDE.md, DESIGN.md §12): anago-core는 순수 std(외부 크레이트
금지), 코어 로직은 순수 함수로 유닛 테스트, 설계 변경은 DESIGN.md 갱신이
먼저, env를 바꾸는 테스트 금지(씸 패턴), 실서버(VPS·DNS·인증서·폰)
검증은 시도하지 않고 `HUMAN-VERIFY.md`에 "사람 확인 필요"로 남긴다.
게이트는 `cargo test`. 커밋은 지시가 있을 때만.

(M0 계획은 git 히스토리에 있다 — 이 파일은 M1로 교체됐다.)

## A. 설계 확정 (코드보다 먼저 — DESIGN.md 갱신)

- [x] DESIGN.md §10 갱신: M1 의존성 확정 — ACME 라이브러리(instant-acme 등) 채택안, 그것이 끌고 오는 serde/HTTP 스택을 §10.1의 "제3자 JSON은 바이너리 몫" 예외로 명시, QR 인코딩 방식(크레이트 vs 자체), 전부 바이너리 크레이트 한정이며 anago-core는 순수 std 유지임을 문장으로 못박는다
- [x] DESIGN.md §9.1 갱신: M1 상태 파일 스키마 — TLS 출처(수동 경로 vs ACME 발급물), ACME 계정·인증서 경로, 발급 방식(`http-01`|`dns-01`), 인증서 만료 epoch, Cloudflare zone/record id 캐시 필드를 추가하고 `version` 처리(2로 올릴지, M0 파일을 어떻게 읽을지)를 확정
- [x] DESIGN.md §8 갱신: M1 CLI 표면 확정 — `server init`의 `--cf-token`/`--acme-email`/`--acme-staging`과 `--tls-cert/--tls-key` 생략 규칙(둘 다 없으면 ACME), `anago sync`의 플래그(`--install-timer`/`--uninstall-timer` 등), `anago join --export qr|conf`의 인자·출력 규약, 이미 선 허브의 인증서 재발급 표면(`server renew` 도입 여부)
- [x] DESIGN.md §6.3 갱신: `sync`가 M1에서 실제로 하는 일 확정 — 허브-스포크라 클라 `AllowedIPs`가 안 변하는데 무엇을 갱신하는가(서버 공개키·엔드포인트 변경 반영, 제거된 기기의 401 감지·안내, 허브의 `last_seen` 갱신), 타이머 기본 주기, 네트워크 실패 시 조용히 끝내는 규약
- [x] DESIGN.md §7 갱신: `--export`로 만든 폰 프로필의 보안 모델 — 개인키가 폰이 아니라 이 기기에서 생성돼 화면/파일로 나가는 §6.2 원칙의 단서, QR의 터미널 스크롤백 노출, conf 파일 0600·사용 후 삭제 안내를 명시
- [x] DESIGN.md §11/§13 갱신: M1 검증 조건(폰이 공식 wg 앱으로 합류)과 새 리스크 — HTTP-01의 :80 개방 요구, DNS-01이 그것을 없애는 대신 토큰 권한을 요구하는 트레이드오프, Let's Encrypt 레이트 리밋(staging 권장), Cloudflare 프록시 off 강제, 맥 launchd 권한 차이

## B. anago-core — 상태·판정 (순수 std, 외부 크레이트 금지)

- [x] `state.rs`: TLS 출처 모델 추가 — 수동 인증서 경로와 ACME 발급물을 구분해 담는 타입 + JSON 직렬화/역직렬화 + A단계에서 정한 `version` 규칙(구버전 파일 처리 포함) + 라운드트립·거부 케이스 유닛 테스트
- [x] `state.rs`: ACME/DNS 상태 필드 추가(계정 키 경로, 발급 방식, 인증서 만료 epoch, Cloudflare zone id/record id 캐시) + 갱신 판정 순수 함수 `needs_renewal(expires_at, now, lead_secs)` + 경계값 유닛 테스트
- [x] `acme.rs`(core): ACME의 순수한 부분만 — HTTP-01 챌린지 경로(`/.well-known/acme-challenge/<token>`)와 응답 본문 조립, DNS-01 TXT 레코드 이름(`_acme-challenge.<domain>`) 조립, 토큰 형식 검증 + 유닛 테스트. 서명·키·해싱·네트워크는 바이너리 몫임을 주석으로 못박는다
- [x] `dns.rs`(core): Cloudflare A 레코드 upsert **판정** 순수 함수 — 기존 레코드 목록과 원하는 IP를 받아 `생성 / 수정 / 변경 없음 / 거부(프록시 켜짐·다른 타입 충돌)` 중 하나를 내는 결정 함수 + 유닛 테스트
- [x] `sync.rs`(core): 동기화 판정 순수 함수 — 저장된 기기 설정과 서버가 준 피어 목록·서버 정보를 비교해 `변경 없음 / wg 설정 재작성 / 이 기기가 제거됨` 중 하나를 내는 결정 함수 + 유닛 테스트(피어 추가만 된 경우가 "변경 없음"임을 고정)
- [x] `wgconf.rs`: `--export`용 완결형 클라이언트 프로필 생성 순수 함수 — 개인키를 실제로 담아 공식 wg 앱이 읽는 필드만 내보낸다. M0 `client_config`와의 공유·분기를 정리하고 스냅샷 유닛 테스트
- [x] `render.rs`: M1 출력 렌더링 순수 함수 — `sync` 결과 한 줄 요약, ACME 발급/갱신 진행·성공 문구, `--export` 사용 안내(경고 포함) + 유닛 테스트

## C. anago 바이너리 — HTTP 클라이언트와 Cloudflare

- [x] `client.rs` 확장: 허브 이외의 호스트(api.cloudflare.com, ACME 디렉터리)로 보내는 GET/POST/PUT/DELETE 요청 지원 — 헤더(Authorization, Content-Type), 응답 본문 크기 상한, 타임아웃. 요청 조립부는 순수 함수로 유닛 테스트
- [x] `cfapi.rs`: Cloudflare 토큰 취득 경로 — `--cf-token` / env / 파일(0600) 우선순위 결정 순수 함수 + 토큰 검증 호출 + 권한 부족·만료 시 안내 문구 + 유닛 테스트
- [x] `cfapi.rs`: zone 조회(도메인 → zone id, 서브도메인이면 상위 zone 탐색) + 응답 파싱 + 실패 시 M0 수동 안내로의 폴백 경로 + 픽스처 기반 파싱 유닛 테스트
- [x] `cfapi.rs`: A 레코드 목록 조회 → 코어의 upsert 판정 호출 → 생성/수정 실행 + 프록시(주황 구름) 켜짐 거부·경고 + 픽스처 파싱 유닛 테스트
- [x] `cfapi.rs`: DNS-01용 TXT 레코드 생성·삭제 + 전파 대기(폴링 간격·타임아웃) — 대기 정책은 순수 함수로 분리해 테스트하고, 실패해도 TXT를 반드시 정리하는 경로를 만든다

## D. anago 바이너리 — ACME

- [x] ACME 의존성 추가(A단계 결정 반영) + feature 최소화 + ring provider 유지 확인 → `cargo build`·`cargo test` 통과, 코어 의존성 무변경 확인
- [x] `acme.rs`(bin): 발급 방식 선택 순수 함수 — `--tls-cert/key` 지정 여부, Cloudflare 토큰 유무, `--acme-staging`을 받아 `수동 인증서 / HTTP-01 / DNS-01`과 디렉터리 URL을 결정 + 유닛 테스트
- [x] `acme.rs`(bin): 계정 키 생성·저장(`/var/lib/anago/tls/account.key`, 0600) + 디렉터리 조회 + 계정 등록, 기존 계정 재사용 판정 + 순수 부분 유닛 테스트
- [x] `acme.rs`(bin): HTTP-01 경로 — :80 임시 리스너(챌린지 응답 전용) 기동·종료, 주문→챌린지→검증 폴링→인증서 수령→`/var/lib/anago/tls/`에 0600 저장. 포트 점유·권한 실패 안내
- [x] `acme.rs`(bin): DNS-01 경로 — Cloudflare TXT 챌린지로 :80 없이 발급, 성공·실패 모두에서 TXT 정리, A단계에서 정한 폴백 규칙대로 HTTP-01 전환 여부 구현
- [x] `acme.rs`(bin): 갱신 — `server run` 안의 주기 점검 태스크(만료 임박 시 재발급), 재시도 백오프(계산은 순수 함수로 테스트), 레이트 리밋에 걸리지 않도록 실패 간격을 벌리는 정책
- [x] `tls.rs`/`serve.rs`: 갱신된 인증서를 무중단으로 반영 — rustls 설정 교체(또는 A단계 결정대로 재기동 안내) + 교체 시점 판정 순수 함수 유닛 테스트

## E. server init 통합 (수동 경로 유지)

- [x] `cli.rs`: `server init` 플래그 확장 — `--cf-token`, `--acme-email`, `--acme-staging` 추가, `--tls-cert/--tls-key`를 선택으로 완화, 상호 배타·필수 조합 검증과 에러 문구 + 파싱 유닛 테스트
- [x] `init.rs`: 조립 갱신 — 토큰이 있으면 A 레코드 자동 upsert, 없으면 M0 수동 안내 유지 → TLS 확보(수동 경로 검증 또는 ACME 발급) → 상태 저장 → wg·systemd 기동. **실패 시 아무 파일도 남기지 않는 M0의 순서를 유지**하고 검증
- [x] `init.rs`: 안내 문구 갱신 — 자동화가 한 일(레코드 upsert 결과, 발급된 인증서 만료일)과 사람이 여전히 해야 하는 일(:80/:443/:51820 방화벽, 프록시 off)을 구분해 출력 + 렌더링 유닛 테스트
- [x] A단계에서 인증서 재발급 표면을 도입하기로 했다면 구현: 이미 선 허브에서 DNS만 다시 밀거나 인증서만 재발급하는 경로(상태 갱신·wg 무영향) + 유닛 테스트

## F. sync 와 주기 실행(timer / launchd)

- [x] `cli.rs`: `anago sync` 라우팅 추가(M0의 "M1에서 들어옴" 안내 제거) + 플래그 파싱 + 유닛 테스트
- [x] `sync.rs`(bin): 본체 — device.json 로드 → `/api/v1/peers` 호출 → 코어 판정 → 필요할 때만 wg 설정 재작성 + `wg syncconf` 적용. 변경 없으면 조용히 종료
- [ ] `sync.rs`(bin): 실패 처리 — 401(제거된 기기)일 때의 정리 안내, 네트워크 실패 시 타이머가 스팸하지 않도록 하는 종료 코드·로그 규약, 동시 실행 방지 잠금 + 유닛 테스트
- [ ] `systemd.rs`: `anago-sync.service` + `anago-sync.timer` 텍스트 생성 순수 함수(기본 주기, 사용자 단위 여부, 샌드박스 설정) + 유닛 테스트
- [ ] `launchd.rs`: 맥 plist 생성 순수 함수(`StartInterval`, 라벨, 로그 경로) + `launchctl bootstrap/bootout` 명령 조립 순수 함수 + 유닛 테스트
- [ ] `sync --install-timer` / `--uninstall-timer`: 플랫폼 감지 → systemd 또는 launchd 설치·활성화, 비-systemd·비-맥 환경에서는 설치하지 않고 수동 실행 방법을 안내 + 설치 경로 결정부 유닛 테스트
- [ ] `join` 성공 후 타이머 안내/자동 설치(A단계 결정대로) 반영 + 문구 유닛 테스트

## G. 폰 경로 — `join --export qr|conf`

- [ ] `cli.rs`: `join --export qr|conf` 파싱 — 값 검증, 로컬 적용 플래그와의 상호 배타, `--name` 기본값 규칙 + 유닛 테스트
- [ ] `join.rs`: `--export conf` 구현 — 로컬 wg 적용과 device.json 쓰기를 건너뛰고, 키쌍 생성 → join 호출 → 완결형 conf를 표준출력 또는 파일(0600)로 출력. 실패 시 서버에 등록만 남지 않도록 기존 undo 경로 재사용
- [ ] QR 인코딩(A단계 결정 방식) 구현 + 터미널 렌더링(반각/전각 블록, 좁은 터미널 안내) + 렌더링 순수 함수 유닛 테스트
- [ ] `--export qr` 조립 + 경고 문구(스크롤백에 개인키가 남음, 스캔 후 화면 정리) 출력 + 폰 기기가 허브 상태에 정상 등록되어 `ls`/`rm`으로 다뤄지는지 확인하는 테스트

## H. 마무리

- [ ] 코어 통합 시나리오 테스트 확장: 초기 상태 → ACME 상태 필드 → 기기 2대 join(폰 export 포함) → sync 판정 → rm 까지 순수 함수만으로 잇는 수명주기 테스트
- [ ] 에러 메시지·usage 일괄 점검: :80 점유·권한, CF 토큰 권한 부족·zone 없음, 프록시 켜짐, ACME 레이트 리밋, DNS 전파 타임아웃, 타이머 설치 불가, QR 미지원 터미널
- [ ] README 갱신: M1 사용법(자동 TLS·DNS 경로와 M0 수동 경로 둘 다), 폰 join(QR) 절차, 타이머 설치·확인 방법, 필요한 방화벽 포트 변경(:80)
- [ ] DESIGN.md §11의 M1 상태 갱신 + `HUMAN-VERIFY.md`에 M1 절 추가: 실 ACME 발급·갱신 성공, :80 개방(HTTP-01), CF A 레코드 실제 반영·프록시 off, DNS-01 발급, 폰이 QR로 합류해 상호 ping, 타이머가 실제로 주기 실행됨, 재부팅 후 타이머·인증서 유지
- [ ] `cargo test`·`cargo build`(가능하면 `cargo clippy`) 그린 확인, REVIEW.md 지적 반영 여부 점검 (커밋은 지시가 있을 때만)
