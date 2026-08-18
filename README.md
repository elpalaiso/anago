# anago 🐟

> your domain + your server = your private network

穴子(아나고): 구멍에 사는 붕장어. 도메인과 서버(VPS)만 있으면 자기 소유의
WireGuard 개인 네트워크를 만들어주는 단일 바이너리입니다. certbot이 TLS에
해준 일을 개인 네트워크에 합니다 — 조율 서버도 릴레이도 인증도 전부 당신의
서버에서 돕니다. 제3자 인프라 의존이 없습니다.

허브-스포크(서버 경유)가 기본이라 NAT/CGNAT 어디서든 **항상** 연결되고,
직결 홀펀칭은 성능 최적화로 얹힐 예정입니다(M2).

전체 그림은 [docs/DESIGN.md](docs/DESIGN.md) 참고.

## 상태

🚧 **M0 구현 완료, 실서버 검증 전.** 코드는 다 있고 유닛/통합 테스트는
초록이지만, 실제 VPS·도메인·인증서로 처음부터 끝까지 돌려본 적은 아직
없습니다 — 실기기에서만 확인할 수 있는 것들(A 레코드 반영, 실제 TLS 기동,
방화벽, 기기 2대 상호 ping, 맥/리눅스 `wg-quick` 차이)이 남아 있습니다.

M0에 있는 것: `server init` / `server run` / `code` / `join` / `ls` / `rm`,
허브-스포크 통신, 수동 DNS 안내, 기존 TLS 인증서 사용.
M1에서 올 것: ACME 자동 발급, Cloudflare A 레코드/DNS-01, `sync` 타이머,
`--export qr`.

이 프로젝트는 [krill](https://github.com/elpalaiso/krill)의 협업 모드
(plan/duet)로 개발됩니다 — 도구로 도구 만들기의 연장선.

## 준비물

**서버(허브)**

- 공인 IP를 가진 리눅스 VPS. 1코어면 충분합니다.
- 도메인 하나. 예: `net.example.com`.
- **A 레코드**가 그 VPS의 공인 IP를 가리켜야 합니다. M0는 DNS를 자동으로
  건드리지 않고 어떤 레코드를 추가할지 안내만 합니다(M1에서 Cloudflare
  API 자동화).
  - Cloudflare를 쓴다면 그 레코드는 반드시 **DNS only**(회색 구름)여야
    합니다. 프록시(주황 구름)를 켜면 이름이 Cloudflare 주소로 해석되고,
    Cloudflare 프록시는 `51820/udp`를 넘겨주지 않습니다 — HTTPS 가입이
    되더라도 기기의 `Endpoint = net.example.com:51820`이 허브에 닿지
    못합니다. M0의 기기는 서버에 **직접** 붙습니다.
- **TLS 인증서와 키**. 조인 코드가 평문으로 다니면 안 되므로 TLS는 M0부터
  필수입니다. 이미 가진 인증서를 씁니다 — 보통 Let's Encrypt(certbot)처럼
  **공개적으로 신뢰되는** 인증서입니다. **anago는 M0에서 인증서를 발급하지
  않습니다**(M1의 ACME).
  - 기기 쪽은 그 기기의 **OS 신뢰 저장소**로만 검증합니다. 그래서
    Cloudflare Origin CA처럼 공개 신뢰가 아닌 인증서를 쓰려면 **합류하는
    모든 기기에 그 CA를 먼저 설치**해야 하고, 그러지 않으면 `anago join`이
    `UnknownIssuer`로 실패합니다. (Origin cert는 Cloudflare를 앞단에
    두는 구성을 위한 것이고, M0는 기기가 서버에 직접 붙습니다.)
- **열어야 하는 포트**: `443/tcp`(컨트롤 API), `51820/udp`(WireGuard).
  둘 중 하나라도 막혀 있으면 기기가 허브에 닿지 못합니다. 클라우드
  보안 그룹과 호스트 방화벽 **양쪽** 모두입니다.
- **호스트 방화벽의 포워딩 정책**: 기기끼리의 트래픽은 허브를 지나 다시
  나가므로 인바운드 허용만으로는 부족합니다. UFW의 기본값처럼 라우팅된
  패킷을 막는 구성이면 두 기기가 각각 허브에는 닿는데 **서로는 못 닿는**
  증상이 나옵니다. anago는 생성하는 wg 설정에 방화벽 규칙(`PostUp`)을
  넣지 않으므로 직접 열어 줍니다:

  셋 중 **하나**를 쓰는 방식에 맞춰 고르세요.

  ```sh
  # (a) UFW — 규칙 추가와 영구화가 한 번에 끝납니다
  sudo ufw route allow in on anago out on anago
  ```

  ```sh
  # (b) iptables — 규칙은 런타임 상태라 따로 저장해야 합니다
  sudo iptables -A FORWARD -i anago -o anago -j ACCEPT
  sudo apt install iptables-persistent      # Debian/Ubuntu
  sudo netfilter-persistent save
  ```

  ```sh
  # (c) nftables 네이티브 — 규칙을 먼저 넣고, 그다음 저장합니다.
  #     테이블/체인 이름은 배포판마다 다르니 먼저 확인하세요.
  sudo nft list ruleset | head -20
  # 예: inet 계열 filter 테이블의 forward 체인이라면
  sudo nft add rule inet filter forward iifname "anago" oifname "anago" accept
  # 그런 테이블이 없다면 만들어서 넣습니다
  #   sudo nft add table inet anago
  #   sudo nft 'add chain inet anago forward { type filter hook forward priority 0; }'
  #   sudo nft add rule inet anago forward iifname "anago" oifname "anago" accept
  sudo nft list ruleset | sudo tee /etc/nftables.conf > /dev/null   # 저장(리다이렉션은 root가)
  sudo systemctl enable nftables
  ```

  **재부팅 뒤에도 남는지 확인하세요.** anago 서비스는 systemd가 다시
  올려주지만 방화벽 규칙은 저장해 두지 않으면 사라지고, 그러면 첫 재부팅
  이후 기기들이 허브에는 붙는데 서로는 못 닿습니다.

  확인은 기기 두 대를 붙인 뒤 서로 ping해 보는 것입니다 — 허브의 `.1`은
  되는데 상대 기기가 안 되면 십중팔구 이 규칙이나 아래 `ip_forward`입니다.
- `wireguard-tools`(`wg`, `wg-quick`)와 root 권한.
- **IPv4 포워딩**: 꺼져 있으면 기기가 서버까지는 닿지만 **기기끼리는 못
  닿습니다** — anago가 감지하면 알려 줍니다. `sysctl -w`는 지금만 켜므로
  파일로도 남깁니다:

  ```sh
  sudo sysctl -w net.ipv4.ip_forward=1                          # 지금
  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-anago.conf   # 재부팅 뒤에도
  ```

**기기**

- WireGuard 도구: 리눅스는 배포판 패키지, macOS는
  `brew install wireguard-tools`.
- `wg-quick`이 인터페이스를 올려야 하므로 root(또는 sudo) 권한.
- 모바일은 M1에서 공식 WireGuard 앱 + 설정 내보내기(QR)로 합류합니다.

## M0 사용법

### 1. 허브 세우기 (VPS에서 1회)

```sh
sudo anago server init \
  --domain net.example.com \
  --tls-cert /etc/letsencrypt/live/net.example.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/net.example.com/privkey.pem
```

이 명령은 서버 wg 키쌍을 만들고, 상태 파일(`/var/lib/anago/state.json`,
0600)과 wg 설정(`/etc/wireguard/anago.conf`)을 쓰고, systemd 유닛을 설치·
기동한 뒤 다음을 출력합니다:

1. 추가할 **A 레코드** (`net.example.com.  A  <서버 공인 IP>`)
2. 열어야 할 **포트 체크리스트** (`443/tcp`, `51820/udp`)
3. 첫 기기에 붙여넣을 **조인 코드 한 줄**

바꿀 수 있는 것: `--subnet 10.100.0.0/24`, `--port 51820`(wg),
`--api-port 443`, 그리고 systemd가 없는 환경이면 `--no-systemd`. 그 경우
허브를 직접 띄웁니다:

```sh
sudo anago server run          # 포그라운드. 상태·TLS 키·wg 설정 모두 root 소유
```

### 2. 기기 등록 (기기마다 1회)

서버에서 코드를 발급하고:

```sh
sudo anago code
# → anago join net.example.com 7QX4-M2KD  (1회용, 15분)
```

기기에서는 먼저 설정 디렉터리를 **자기 권한으로** 한 번 만들고:

```sh
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/anago"    # 처음 한 번, sudo 없이
```

(`XDG_CONFIG_HOME`을 쓰지 않는다면 `~/.config/anago`와 같습니다.)

받은 줄을 그대로 실행합니다:

```sh
sudo anago join net.example.com 7QX4-M2KD          # --name 맥북 으로 이름 지정 가능
```

`sudo`가 필요한 이유는 `/etc/wireguard/anago.conf`를 쓰고 인터페이스를
올려야 하기 때문입니다. **기기 파일(`device.json`)은 sudo로 실행해도 당신
것으로 남습니다** — anago가 `SUDO_UID`를 보고 당신의 홈 아래에 만들고,
그 파일을 만든 디스크립터로 소유권을 넘깁니다. 그래서 이어지는
`anago ls`/`anago rm`은 sudo 없이 실행됩니다.

디렉터리를 anago가 대신 만들어 주지 않는 이유는 그게 **root가 남의 홈에
mkdir하는 일**이기 때문입니다 — 거기에 심볼릭 링크가 있으면 root가 엉뚱한
곳에 권한·소유권을 적용하게 되고, root 소유 `~/.config`가 남으면 다른
프로그램들이 그 아래에 쓰지 못합니다. 디렉터리가 없거나 당신 소유가 아니면
join이 그 사실과 조치를 알려주고 멈춥니다.

`XDG_CONFIG_HOME`을 옮겨 쓴다면 `sudo -E anago join …`으로 실행하세요 —
sudo가 기본으로 그 변수를 지우기 때문에, 그러지 않으면 join은 passwd의 홈
기준으로 저장하고 이후 `anago ls`는 옮긴 위치를 봅니다. 위 `mkdir` 한 줄은
두 경우 모두 join이 실제로 쓸 디렉터리를 만듭니다.

기기가 자기 키쌍을 만들고(**개인키는 기기를 떠나지 않습니다**) 공개키만
등록한 뒤, wg 설정을 쓰고 터널을 올리고 서버의 `.1`에 ping을 던져 확인합니다.

### 3. 확인하고 관리하기

기기에서 (저장된 토큰으로 컨트롤 API 호출, sudo 불필요):

```sh
anago ls                 # 기기 목록
ping 10.100.0.3          # 기기끼리 — 어디에 있든
anago rm 맥북            # 기기 제거
```

허브에서 (상태 파일을 직접 읽고 고치므로 root 필요):

```sh
sudo anago ls            # 마지막 핸드셰이크까지 — `wg show`에서 읽습니다
sudo anago rm 맥북       # 상태를 고치고 wg 설정을 갱신
```

`/var/lib/anago`는 0700이고 상태 파일은 0600이라 허브 쪽 두 명령은 sudo가
필요합니다. 기기 쪽은 자기 홈의 `device.json`만 읽으므로 필요 없습니다.

## 파일과 위치

| 무엇 | 어디 | 비고 |
|---|---|---|
| 서버 상태 | `/var/lib/anago/state.json` | 0600. 서브넷·서버 키쌍·피어·조인 코드 |
| 서버 wg 설정 | `/etc/wireguard/anago.conf` | 상태에서 생성. 피어마다 `/32` |
| systemd 유닛 | `/etc/systemd/system/anago.service` | ExecStart는 `anago server run` |
| 기기 설정 | `~/.config/anago/device.json` | 0600, 당신 소유. 도메인·토큰·할당 IP·서버 공개키 |
| 기기 wg 설정 | `/etc/wireguard/anago.conf` | 개인키는 여기에만 있습니다 |

## 알아둘 것

- 허브는 트래픽을 **복호화해 중계**합니다(허브-스포크의 성질). 그 서버가
  당신의 것이라는 게 이 프로젝트의 전제입니다 — M2의 직결이 붙으면 기기
  간 트래픽은 E2E가 됩니다. 자세한 건 DESIGN §5.
- 조인 코드는 1회용이고 15분 뒤 만료됩니다. 기기 토큰은 서버에 **해시로만**
  저장됩니다(DESIGN §7).
- Windows는 v1 비대상입니다(WSL2로 우회).

## 라이선스

MIT
