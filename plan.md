# M0 구현 계획

범위(DESIGN.md §11 M0): `server init`(DNS 수동 안내, TLS는 기존 인증서
경로 `--tls-cert/--tls-key`) + `join` + 허브-스포크 통신 + `code`/`ls`/`rm`.
`sync`/ACME/Cloudflare/`--export qr`/홀펀칭은 M1+ — 이 계획에 없다.

규칙: anago-core는 순수 std(외부 크레이트 금지), 코어 로직은 순수 함수로
유닛 테스트, 설계 변경은 DESIGN.md 갱신이 먼저, 실서버 검증은 시도하지
않고 "사람 확인 필요"로 남긴다. 게이트는 `cargo test`.

## A. 설계 확정 (코드보다 먼저)

- [x] DESIGN.md §9/§10 갱신: M0 상태 파일 스키마(필드 목록)와 직렬화 결정을 명시 — 프로토콜/상태 타입의 JSON 인코딩은 anago-core의 순수 std 미니 JSON으로 하고 serde는 쓰지 않는다(또는 반대 결정)를 문장으로 확정
- [x] DESIGN.md §7 갱신: 기기 토큰의 M0 처리 확정 — 해시(sha2 등 바이너리 크레이트) vs 평문 0600 저장 중 하나를 고르고 근거를 적는다. 코어는 형식 검증·상수시간 비교만 담당함을 명시
- [x] DESIGN.md §8 갱신: M0에서 실제 구현할 CLI 표면과 API 엔드포인트만 추려 M0/M1 표기를 붙인다(`sync`, `--export`, `/api/v1/endpoint`는 M1+ 표시)
- [x] DESIGN.md §7 갱신(건너뜀 복구 — 순회 버그로 미실행): 기기 토큰의 M0 처리 확정 — 해시(바이너리 크레이트) vs 평문 0600 저장 중 하나를 고르고 근거를 적는다. 코어는 형식 검증·상수시간 비교만 담당함을 명시

## B. anago-core — 순수 함수 기반 (외부 크레이트 금지)

- [x] `json.rs`: 최소 JSON 값 타입 + 파서(객체/배열/문자열/숫자/불/널, 이스케이프 처리) — 파싱 유닛 테스트
- [x] `json.rs`: JSON 직렬화(문자열 이스케이프, 결정적 키 순서) + 라운드트립 유닛 테스트, 잘못된 입력에 대한 에러 케이스 테스트
- [x] `proto.rs`: 컨트롤 API 타입 정의 — JoinRequest/JoinResponse/PeerInfo/PeersResponse/ApiError — 필드 확정만
- [x] `proto.rs`: 각 타입의 to_json/from_json 구현 + 라운드트립·누락 필드·타입 불일치 유닛 테스트
- [ ] `subnet.rs` 확장: CIDR 문자열 파싱(`10.100.0.0/24`), 서버 주소(.1) 계산, 잘못된 CIDR 거부 — 기존 `next_free_octet`과 결합한 할당 함수 + 유닛 테스트
- [ ] `code.rs`: 조인 코드 형식(`CODE-XXXX` 문자열 규약, 혼동 문자 제외 charset) 정의 + 형식 검증 함수 + 유닛 테스트 (난수 생성은 바이너리 책임, 코어는 형식/검증만)
- [ ] `code.rs`: 코드 수명 판정 순수 함수 — `is_valid(code, issued_at, now, ttl, used)` 형태로 만료·1회용 소진을 판정 + 경계값 유닛 테스트
- [ ] `name.rs`: 기기 이름 검증/정규화(길이, 허용 문자, 소문자화 등) + 상태 내 중복 판정 + 유닛 테스트
- [ ] `token.rs`: 기기 토큰 형식 검증 + 상수시간 비교 함수 + 유닛 테스트 (해싱은 A단계 결정에 따라 바이너리 측)
- [ ] `state.rs`: 서버 상태 모델(서브넷, 서버 키쌍, 포트, 도메인, 피어 목록, 발급 코드) 타입 정의 + json.rs 기반 직렬화/역직렬화 + 라운드트립 유닛 테스트
- [ ] `state.rs`: 상태 전이 순수 함수 — `add_peer`(IP 할당·이름 중복·코드 소진 반영), `remove_peer` + 유닛 테스트(중복 이름, 서브넷 소진, 없는 이름 제거)
- [ ] `wgconf.rs`: 서버측 wg 설정 생성 순수 함수(`[Interface]` + 피어별 `[Peer]`, AllowedIPs = /32) + 스냅샷 유닛 테스트
- [ ] `wgconf.rs`: 클라이언트측 wg 설정 생성 순수 함수(Address, PrivateKey 자리, 서버 Peer: 공개키·엔드포인트·`AllowedIPs = <subnet>`·`PersistentKeepalive = 25`) + 유닛 테스트
- [ ] `render.rs`: `anago ls` 출력 표 렌더링 순수 함수(이름·IP·공개키 축약·마지막 핸드셰이크 표기, 빈 목록 처리) + 유닛 테스트

## C. anago 바이너리 — CLI 골격과 파일 I/O

- [ ] krill `args.rs` 스타일 수제 플래그 파서 이식 + 파싱 유닛 테스트(순수 함수, env 미변경)
- [ ] CLI 디스패치와 도움말: `server init|status`, `code`, `join`, `ls`, `rm` 라우팅 + M0 미구현 서브커맨드의 명확한 안내 문구
- [ ] 경로 해석 씸: 서버 `/var/lib/anago/`, 클라 `~/.config/anago/`, `/etc/wireguard/anago.conf` — env/HOME 의존부를 순수 함수(입력으로 받은 base 경로)로 분리 + 유닛 테스트
- [ ] 파일 유틸: 원자적 쓰기(tmp+rename), 0600 퍼미션 설정(unix), flock 기반 상태 파일 잠금 — 임시 디렉터리 대상 테스트
- [ ] `wg`/`wg-quick` 래퍼: 존재 확인과 설치 안내(맥 brew / 리눅스 배포판), `wg genkey`/`wg pubkey` 호출로 키쌍 생성 (커맨드 조립부는 순수 함수로 분리해 테스트)

## D. 서버 — 컨트롤 플레인

- [ ] 바이너리 크레이트에 서버 의존성 추가(tokio, axum, rustls 계열) 후 `cargo build` 통과 — 코어는 손대지 않음을 확인
- [ ] HTTPS 리스너: `--tls-cert/--tls-key` PEM 로드 → rustls 설정, 잘못된 경로·형식에 대한 명확한 에러 (경로 검증·에러 문구는 순수 함수 분리)
- [ ] `POST /api/v1/join` 핸들러: 코드 검증 → 이름/공개키 등록 → IP 할당 → 상태 저장(잠금) → JoinResponse (코어 순수 함수 호출부만 얇게)
- [ ] `GET /api/v1/peers` + `DELETE /api/v1/peers/{name}` 핸들러: 기기 토큰 bearer 인증 → 코어 상태 전이 호출
- [ ] 서버 wg 인터페이스 반영: 상태 변경 시 서버 wg 설정 재생성 + `wg syncconf`(또는 wg-quick) 적용, `ip_forward` 확인/안내
- [ ] `anago server init` 조립: 키쌍 생성 → 상태 파일 초기 생성 → DNS 수동 안내 출력(A 레코드 문구, 서버 공인 IP 조회는 실패해도 진행) → 방화벽 체크리스트(:443, :51820/udp) → 첫 조인 코드 출력
- [ ] `--no-systemd` 포그라운드 실행 경로 + systemd 유닛 파일 생성/설치(유닛 텍스트 생성은 순수 함수 + 유닛 테스트)
- [ ] `anago code`: 서버 로컬에서 상태 파일에 코드 발급·저장·출력(`anago join <domain> CODE-XXXX` 형태로 복붙 가능하게)

## E. 클라이언트 — join / ls / rm

- [ ] HTTPS 클라이언트 최소 구현(rustls 기반 요청/응답, JSON 본문, 타임아웃, 에러 메시지) — 요청 조립부 순수 함수 테스트
- [ ] `anago join <domain> <code> [--name]`: 로컬 키쌍 생성(개인키 로컬 0600) → join 호출 → 응답 저장(`~/.config/anago/`: 도메인·토큰·할당 IP)
- [ ] `anago join` 후속: 클라 wg 설정 파일 작성 + `wg-quick up` 위임 + 서버 .1 ping으로 연결 확인, 실패 시 진단 안내
- [ ] `anago ls`: 로컬 토큰으로 `/api/v1/peers` 호출 → 코어 렌더러로 출력. 서버에서 실행 시 상태 파일 직접 읽는 경로도 지원
- [ ] `anago rm <이름>`: `DELETE /api/v1/peers/{name}` 호출(서버 로컬이면 상태 직접 수정) → 서버 wg 설정 갱신 확인

## F. 마무리

- [ ] 코어 통합 성격 유닛 테스트: 초기 상태 → 코드 발급 → join 2대 → wg 설정 생성 → rm 까지 순수 함수만으로 이어지는 시나리오 테스트
- [ ] 에러 메시지·usage 문구 일괄 점검(권한 부족, wg 미설치, 인증서 없음, 코드 만료, 서브넷 소진 각각의 안내 문구)
- [ ] README에 M0 사용법(서버 1회 + 기기 join) 및 방화벽/DNS 사전 준비 문서화, DESIGN.md §11의 M0 상태 갱신
- [ ] `HUMAN-VERIFY.md`(또는 PR 본문 절)에 "사람 확인 필요" 항목 명시: 실 VPS에서 A 레코드 반영, 실 TLS 인증서로 HTTPS 기동, :443/:51820 방화벽 개방, 기기 2대 join 후 상호 ping, wg-quick 맥/리눅스 동작 차이
- [ ] `cargo test`·`cargo build` 그린 확인, REVIEW.md 지적 반영 여부 점검 (커밋은 지시가 있을 때만)
