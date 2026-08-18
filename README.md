# anago 🐟

> your domain + your server = your private network

穴子(아나고): 구멍에 사는 붕장어. 도메인과 서버(VPS)만 있으면 10분 안에
자기 소유의 WireGuard 개인 네트워크를 만들어주는 단일 바이너리입니다.
certbot이 TLS에 해준 일을 개인 네트워크에 합니다 — 조율 서버도 릴레이도
인증도 전부 당신의 서버에서 돕니다. 제3자 인프라 의존이 없습니다.

```sh
# VPS에서 (1회)
anago server init --domain net.example.com
# → 조인 코드 출력

# 각 기기에서 (1회)
anago join net.example.com 7QX4-M2KD
anago ls
ping 10.100.0.2        # 어디에 있든 기기끼리 연결
```

허브-스포크(서버 경유)가 기본이라 NAT/CGNAT 어디서든 **항상** 연결되고,
직결 홀펀칭은 성능 최적화로 얹힐 예정입니다(M2).

전체 그림은 [docs/DESIGN.md](docs/DESIGN.md) 참고.

## 상태

🚧 설계 단계 — 로드맵 M0(서버 초기화 + 기기 등록 + 허브-스포크) 작업 전.

이 프로젝트는 [krill](https://github.com/elpalaiso/krill)의 협업 모드
(plan/duet)로 개발됩니다 — 도구로 도구 만들기의 연장선.

## 요구사항

- 서버: 공인 IP를 가진 리눅스 VPS(1코어면 충분), 도메인 1개
- 기기: WireGuard(리눅스: 배포판 패키지, macOS: `brew install wireguard-tools`)
- 모바일: 공식 WireGuard 앱 + 설정 내보내기(QR)

## 라이선스

MIT
