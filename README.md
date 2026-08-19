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

🚧 **M0·M1 구현 완료, 실서버 검증 전.** 코드는 다 있고 유닛/통합 테스트는
초록이지만, 실제 VPS·도메인·CA로 처음부터 끝까지 돌려본 적은 아직
없습니다 — 실기기·실 네트워크에서만 알 수 있는 것들(진짜 인증서 발급과
갱신, A 레코드 반영, 방화벽, 폰이 QR로 붙는지, 타이머가 정말 주기적으로
도는지)은 사람이 한 번 돌려봐야 합니다. 목록은
[HUMAN-VERIFY.md](HUMAN-VERIFY.md)에 있습니다.

M0에 있는 것: `server init` / `server run` / `code` / `join` / `ls` / `rm`,
허브-스포크 통신, 수동 DNS 안내, 기존 TLS 인증서 사용.
M1에서 더해진 것: Let's Encrypt 자동 발급·갱신(ACME), Cloudflare A 레코드
자동 등록과 DNS-01, `anago sync`와 그 주기 실행 타이머(systemd·launchd),
그리고 `join --export qr|conf` — 폰이 공식 WireGuard 앱으로 합류합니다.
M1.5에서 더해진 것(이 브랜치): **허브가 윈도우 PC·맥에서도 됩니다** —
윈도우는 진짜 윈도우 서비스로, 맥은 LaunchDaemon으로 상주하고, 터널은
공식 WireGuard 클라이언트(윈도우)·wireguard-tools(맥)가 맡습니다.
"서버"가 없어도 집에 늘 켜져 있는 PC면 그게 허브입니다.
M2에서 올 것: 홀펀칭 직결(성능 최적화이지 정합성 요건이 아닙니다).

이 프로젝트는 [krill](https://github.com/elpalaiso/krill)의 협업 모드
(plan/duet)로 개발됩니다 — 도구로 도구 만들기의 연장선.

## 준비물

**서버(허브)** — 다음 중 하나:

- 공인 IP를 가진 리눅스 VPS (1코어면 충분), **또는**
- **집에 늘 켜져 있는 PC**(윈도우·맥·리눅스) + 공유기 포트포워딩.
  공유기에서 아래 "방화벽" 절의 두 포트를 이 PC로 전달해 주세요
  (통신사 장비 뒤에 공유기가 또 있는 이중 NAT면 양쪽 다 — 위층은 DMZ로
  아래층 공유기를 지정하는 것이 간단합니다). 윈도우는 관리자 PowerShell
  에서 실행하고, 공식 WireGuard 클라이언트가 미리 설치되어 있어야
  합니다: `winget install WireGuard.WireGuard`.
- 도메인 하나. 예: `net.example.com`.
- **A 레코드**가 그 VPS의 공인 IP를 가리켜야 합니다. 둘 중 하나입니다:
  - **Cloudflare API 토큰을 주면 anago가 만듭니다.** 없으면 어떤 레코드를
    추가할지 안내만 하고 넘어갑니다 — 자동화는 기본값을 바꾸는 것이지
    수동 경로를 없애는 게 아닙니다.
  - 토큰은 **Zone → DNS → Edit**(레코드 쓰기)과 **Zone → Zone →
    Read**(그 도메인이 어느 zone인지 찾기) **둘 다** 필요합니다. 읽기
    권한이 없는 토큰은 다른 검사를 전부 통과한 다음에 실패합니다.
  - Cloudflare를 쓴다면 그 레코드는 반드시 **DNS only**(회색 구름)여야
    합니다. 프록시(주황 구름)를 켜면 이름이 Cloudflare 주소로 해석되고,
    Cloudflare 프록시는 `51820/udp`를 넘겨주지 않습니다 — HTTPS 가입이
    되더라도 기기의 `Endpoint = net.example.com:51820`이 허브에 닿지
    못합니다. 기기는 서버에 **직접** 붙습니다.

    자동화가 붙으면서 이 함정은 오히려 더 조용해졌습니다: DNS-01이 쓰는
    TXT 레코드는 애초에 프록시 대상이 아니라서 **인증서는 멀쩡히 발급되고
    HTTPS도 됩니다.** 화면의 모든 줄이 초록인 채로 터널만 죽습니다. anago는
    자기가 만드는 레코드를 프록시 없이 만들고, 이미 프록시가 켜진 레코드는
    **끄지 않고 거절합니다** — 남의 이름에 대한 결정이니까요.
- **TLS**. 조인 코드가 평문으로 다니면 안 되므로 TLS는 처음부터 필수입니다.
  여기도 둘 중 하나입니다:
  - **anago가 Let's Encrypt에서 받아 옵니다**(기본값). `--acme-email`만
    주면 되고, 이후 갱신은 허브가 스스로 합니다 — cron도 certbot도
    없습니다.
  - **이미 가진 인증서를 씁니다.** `--tls-cert`/`--tls-key`로 경로를 주면
    anago는 그 파일을 **읽기만** 합니다. certbot이 이미 도는 서버에서는
    이쪽이 옳은 답이고, M1 이후로도 1급 시민입니다.
  - 어느 쪽이든 기기는 그 기기의 **OS 신뢰 저장소**로만 검증합니다. 그래서
    Cloudflare Origin CA처럼 공개 신뢰가 아닌 인증서를 쓰려면 **합류하는
    모든 기기에 그 CA를 먼저 설치**해야 하고, 그러지 않으면 `anago join`이
    `UnknownIssuer`로 실패합니다. (`--acme-staging`으로 받은 인증서도
    마찬가지입니다 — 배선 확인용이고, join이 거부하는 게 정상입니다.)
- **열어야 하는 포트**: `443/tcp`(컨트롤 API), `51820/udp`(WireGuard).
  둘 중 하나라도 막혀 있으면 기기가 허브에 닿지 못합니다. 클라우드
  보안 그룹과 호스트 방화벽 **양쪽** 모두입니다.
  - **HTTP-01로 인증서를 받는다면 `80/tcp`도 열어야 합니다** — 그리고
    **계속** 열어 둬야 합니다. CA가 발급 때만 :80을 보는 게 아니라
    **갱신 때마다** 다시 봅니다. 첫 발급만 통과시키고 닫으면 몇 달 뒤
    조용히 갱신이 멈추고, 그때는 인증서가 만료돼서야 알게 됩니다.
  - **DNS-01이면 :80이 필요 없습니다.** Cloudflare 토큰이 있으면 anago는
    DNS-01을 기본으로 고릅니다. 대신 그 토큰이 계속 유효해야 합니다 —
    갱신할 때마다 TXT 레코드를 다시 씁니다.
  - anago는 알아서 다른 챌린지로 갈아타지 않습니다. :80을 여는 건 남의
    서버에 대한 결정이라 대신 하지 않고, 무엇이 막혔는지 말하고 멈춥니다.
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
- **폰에는 anago를 설치하지 않습니다.** 공식 WireGuard 앱(iOS/Android)만
  있으면 되고, 설정은 다른 기계에서 QR이나 파일로 넘겨줍니다 — 아래
  [3. 폰 합류 — QR](#3-폰-합류--qr).

## 사용법

### 1. 허브 세우기 (허브 기기에서 1회 — VPS 또는 상주 PC)

**어느 인증서를 쓸지가 나머지를 정합니다.** 세 갈래 중 하나를 고르세요.

**(a) 다 맡기기 — Cloudflare 도메인이라면 이게 제일 짧습니다**

토큰을 먼저 파일에 넣어 둡니다 (0600이 아니면 anago가 경고합니다 — 그
토큰은 zone 전체를 고칠 수 있습니다):

```sh
sudo touch /root/cf-token && sudo chmod 600 /root/cf-token
sudo $EDITOR /root/cf-token        # 토큰 한 줄. 셸 히스토리에 남기지 않기
```

```sh
sudo anago server init \
  --domain net.example.com \
  --acme-email you@example.com \
  --cf-token-file /root/cf-token
```

토큰이 있으면 anago가 **A 레코드를 만들고**(프록시 없이), 그 토큰으로
**DNS-01** 챌린지를 풀어 인증서를 받습니다. **`:80`은 한 번도 필요하지
않습니다.** DNS-01은 TXT 레코드로 증명하므로 A 레코드가 아직 없어도, 아직
안 퍼졌어도 발급됩니다 — 순서를 지킬 것이 없다는 뜻입니다. (다만 AWS·GCP
처럼 1:1 NAT 뒤라 anago가 공인 주소를 알아낼 수 없으면 레코드는 **직접
넣도록 안내하고 넘어갑니다** — 틀린 주소를 적는 것보다 안 적는 게 낫기
때문입니다. 인증서는 그대로 발급됩니다.)

토큰은 `--cf-token <값>`으로도 줄 수 있지만 그러면 `ps`와 셸 히스토리에
남고, 환경 변수 `CLOUDFLARE_API_TOKEN`도 읽습니다(sudo가 기본으로 환경을
비우므로 `sudo -E`가 필요합니다). anago는 DNS-01 갱신이 그 토큰을 다시 쓸
것이므로 `/var/lib/anago/cf-token`(0600)에 복사해 둡니다 — **상태 파일
안에는 넣지 않습니다.**

**(b) Cloudflare가 아닌 DNS — 인증서만 자동으로**

토큰이 없으면 챌린지는 **HTTP-01**이고, 그래서 **A 레코드를 먼저 만들어야
합니다.** CA가 바깥에서 `http://net.example.com/...`을 직접 가져가 보는
방식이라, init을 돌리는 시점에 이름이 이미 이 서버를 가리키고 있어야
합니다. anago는 인증서를 손에 쥔 **다음에** 안내를 출력하므로, 레코드가
없으면 그 안내를 보기도 전에 발급에서 멈춥니다. (그래도 허브가 반쯤
만들어지지는 않습니다 — 상태 파일도 wg 설정도 인증서 다음에 쓰기 때문에,
레코드를 고치고 그냥 다시 실행하면 됩니다.)

서버의 공인 주소는 **프로바이더 콘솔이 보여주는 값**이 가장 확실합니다.
리눅스에서 직접 보려면:

```sh
ip route get 1.1.1.1        # 출력의 `src` 뒤가 이 기계가 나갈 때 쓰는 주소
```

AWS·GCP처럼 1:1 NAT 뒤라면 여기서 **사설** 주소가 나옵니다 — 그때는 콘솔의
공인 주소를 쓰세요. (anago도 같은 방법으로 추정하기 때문에, 그 경우
init의 안내에는 주소 대신 자리표시자가 찍힙니다.)

레코드를 넣었으면 퍼졌는지 확인하고:

```sh
dig +short net.example.com      # VPS의 공인 IP가 그대로 나와야 합니다
```

`80/tcp`를 열어 둔 채로 — **지금도, 갱신 때마다도** — 실행합니다:

```sh
sudo anago server init \
  --domain net.example.com \
  --acme-email you@example.com
```

먼저 배선만 확인하고 싶으면 `--acme-staging`을 붙이세요. **프로덕션 한도를
쓰지 않습니다** — 스테이징에도 한도는 있지만 훨씬 넉넉한 별도 한도입니다.
그 인증서는 아무도 믿지 않으므로 `join`이 거부하는 게 **정상**이고, 그
단계에서 보는 것은 :80과 DNS 배선이지 신뢰가 아닙니다. 확인이 끝나면
`sudo anago server renew --acme-production`.

배선이 틀린 채로 실패를 반복하면 **실패한 검증도 CA 한도에 셉니다** —
셋업 중에 걸리기 가장 쉬운 한도가 이것이라, 스테이징으로 먼저 도는 것이
그 대비입니다.

**(c) 이미 인증서가 있다면 — M0와 같은 경로**

```sh
sudo anago server init \
  --domain net.example.com \
  --tls-cert /etc/letsencrypt/live/net.example.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/net.example.com/privkey.pem
```

anago는 이 파일들을 **읽기만** 하고 절대 덮어쓰지 않습니다. 갱신은
certbot(또는 그 파일을 만든 무엇이든)의 몫이고, anago는 파일이 바뀌면
재시작 없이 새 인증서를 집어 듭니다.

세 경우 모두 서버 wg 키쌍을 만들고, 상태 파일(`/var/lib/anago/state.json`,
0600)과 wg 설정(`/etc/wireguard/anago.conf`)을 쓰고, systemd 유닛을 설치·
기동한 뒤 **한 일**과 **당신이 아직 할 일**을 나눠서 출력합니다:

```
anago is set up for net.example.com.

anago did these for you:

  created the A record, DNS only — no orange cloud (9c8b7a65)
  issued a certificate for net.example.com via dns-01
    expires in 90d, renewing in 60d

Still yours to do:

1. Firewall — open these, or nothing can reach the hub:

     443/tcp   control API (HTTPS)
     51820/udp WireGuard

2. Cloudflare — check the A record is DNS only:

     The cloud beside it must be grey, not orange. A proxied record still
     gets a certificate and still serves HTTPS, so nothing above would have
     failed — but WireGuard's UDP port is not forwarded through the proxy,
     and devices would join and then reach nothing.

Then add a device — run this on it:

     anago join net.example.com 7QX4-M2KD

That code is single use and expires in 15 minutes; `anago code` issues another.
```

목록은 **실제로 일어난 일에 따라 바뀝니다.** anago가 한 게 없으면 위쪽
절이 통째로 사라지고(경로 (c)가 그렇습니다), A 레코드를 직접 넣어야 하면
그 줄이 1번으로 올라오고, HTTP-01이면 포트 목록에 이 줄이 함께 나옵니다:

```
     80/tcp    certificate renewal, now and at every renewal
```

"now and at every renewal" — 발급 때만이 아닙니다.

바꿀 수 있는 것: `--subnet 10.100.0.0/24`, `--port 51820`(wg),
`--api-port 443`, `--acme-challenge http-01|dns-01`(기본값을 뒤집습니다),
그리고 systemd가 없는 환경이면 `--no-systemd`. 그 경우 허브를 직접 띄웁니다:

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
끝나면 아래 4번의 타이머를 설치하는 방법도 같이 안내합니다.

### 3. 폰 합류 — QR

폰에는 anago가 없습니다. 그래서 **다른 기계가 폰 몫의 키를 만들어** 완결형
설정을 QR로 넘기고, 폰은 공식 WireGuard 앱으로 그것을 읽습니다.

허브에서 코드를 하나 받고:

```sh
sudo anago code
```

`wg`가 깔린 아무 기계에서나 (이미 합류한 노트북이면 됩니다) — **sudo가
필요 없습니다.** 이 경로는 로컬에 아무것도 쓰지 않고 인터페이스도 올리지
않습니다:

```sh
anago join net.example.com 7QX4-M2KD --export qr --name 폰
```

`--name`은 **필수**입니다 — 빼면 파서가 거절하고 아무것도 등록되지
않습니다. 호스트 이름을 기본값으로 쓰는 것은 일반 join뿐이고, 여기서
그러면 폰이 **이 기계의** 이름으로 등록될 테니까요.

터미널에 QR이 그려지면 폰의 WireGuard 앱에서 **+ → QR 코드에서 만들기**로
스캔하고, 터널을 켭니다. 그러면 폰은 다른 기기들과 똑같은 피어입니다 —
`anago ls`에 뜨고, `anago rm 폰`으로 지웁니다. 폰 자신만 그 두 명령을 못
합니다(토큰이 없으니까요). 허브에서든, 방금 QR을 띄운 노트북에서든,
합류한 기기라면 어디서 실행해도 같습니다.

**스캔한 뒤에는 두 번 치워야 합니다.** QR은 그림이지 텍스트가 아니지만
담고 있는 건 같은 개인키이고, 읽을 수 있는 무엇이든 그 키를 갖습니다:

1. `clear`(또는 Ctrl-L) — **화면**에서 지웁니다. 대신 스크롤백으로
   들어갑니다.
2. 터미널 자체의 **Clear Scrollback**(tmux는 `clear-history`) — **기록**을
   비웁니다. 화면에 보이는 것은 그대로 두므로 순서가 이쪽이 나중입니다.

둘 중 하나만으로는 안 됩니다. 스크롤백을 디스크에 남기는 터미널도 있고,
SSH로 들어와 있다면 양쪽 끝에 남습니다.

파일로 넘기고 싶으면 QR 대신:

```sh
anago join net.example.com 7QX4-M2KD --export conf --name 폰 --out phone.conf
```

`--out`은 0600으로 만들고, **이미 있는 파일은 덮어쓰지 않고 에러**입니다.
셸 리다이렉션(`>`) 대신 이걸 쓰세요 — `>`는 모드를 umask에 맡기고, 보통
0644입니다. 옮긴 뒤에는 지우고, 백업·클라우드 동기화 폴더에 두지 마세요.

터미널이 좁아 QR이 줄바꿈될 상황이면 anago는 **그리지 않고 거절합니다** —
줄바꿈된 QR도 QR처럼 보여서, 폰을 들이대 봐야 알게 되기 때문입니다.
그 거절이 조인 코드를 쓰기 전에 일어나면 코드는 그대로 살아 있습니다.

### 4. sync 타이머 (기기마다, 선택)

`anago sync`는 허브에 피어 목록을 물어보고, **달라진 게 있을 때만** wg
설정을 고칩니다. 허브-스포크라서 기기 설정은 "서브넷 전체를 허브로"
한 줄이고, 그래서 **다른 기기가 새로 들어오는 것은 여기에 아무 영향이
없습니다** — 대부분의 실행은 "바뀐 것 없음"으로 끝나고 그게 정상입니다.

그래도 돌릴 값어치가 있는 건 나머지입니다: 이 기기가 제거된 걸 알아채는
것, 서버 키나 엔드포인트가 바뀐 걸 따라가는 것.

한 번만 돌려보려면:

```sh
sudo anago sync
```

주기 실행을 걸려면:

```sh
sudo anago sync --install-timer                 # 기본 5분
sudo anago sync --install-timer --interval 1h   # 90s / 5m / 1h — 1m~24h
```

리눅스면 systemd 타이머(`anago-sync.timer` + `anago-sync.service`), 맥이면
LaunchDaemon(`com.github.elpalaiso.anago.sync`)을 설치하고 바로 켭니다.
**둘 다 없는 기계에서는 설치하지 않고**, 대신 crontab에 넣을 줄을
출력합니다 — 못 하는 일을 한 척하지 않습니다. (cron은 스톱워치가 아니라
시계로 반복하므로, 그 경우 주기는 한 시간이나 하루를 나누는 값이어야
합니다.)

먼저 join이 되어 있어야 합니다 — 가리킬 `device.json`이 없는 타이머는
설치된 것처럼 보이면서 몇 분마다 실패하기만 하므로, anago는 그 상태로는
설치하지 않습니다. 설치되는 유닛에는 `--config <device.json 경로>`가
명령줄에 박혀 있습니다: 타이머에는 사용자 세션이 없어서 `ls`/`rm`처럼
경로를 알아낼 방법이 없기 때문입니다.

설치됐는지 **확인**은:

```sh
# 리눅스
systemctl list-timers 'anago-sync*'      # 다음에 언제 도는지
systemctl cat anago-sync.service         # 어떤 device.json을 읽는지

# 맥 — sudo와 `system/` 둘 다 필요합니다.
# 그냥 `launchctl list`는 당신의 로그인 세션만 봅니다.
sudo launchctl print system/com.github.elpalaiso.anago.sync
```

파일이 있다는 것과 돌고 있다는 것은 다릅니다 — 특히 맥에서는 시스템
설정 → **로그인 항목 및 확장 프로그램**에서 꺼 둘 수 있고, 그러면
설치는 멀쩡한데 한 번도 실행되지 않습니다. 로그는
`/var/log/anago-sync.log`입니다.

떼려면:

```sh
sudo anago sync --uninstall-timer
```

주기를 바꾸는 것도 **떼고 다시 설치**입니다. 자리에서 갈아끼우지 않는
이유는, 중간에 실패하면 옛 것도 새 것도 없는 상태가 남기 때문입니다.

### 5. 인증서 갱신

anago가 발급한 인증서는 **허브가 알아서 갱신합니다** — `server run`이
주기적으로 확인하고, 수명의 **2/3**가 지나면 다시 받아 재시작 없이
갈아끼웁니다. cron도 certbot도 필요 없습니다. (고정 일수가 아니라 2/3인
이유는 Let's Encrypt가 인증서 수명을 90일에서 줄이고 있기 때문입니다.)

직접 만질 일이 있다면:

```sh
# 필요하면 지금 받고, 아니면 언제 받을지만 알려주고 끝 — cron에 넣어도 안전
sudo anago server renew

# 지금 무조건. CA의 얼마 안 되는 주간 한도를 씁니다
sudo anago server renew --force

# 설정만 바꾸기 — 인증서는 그대로, 다음 갱신부터 적용
sudo anago server renew --acme-email you@example.com

# 서버 공인 IP가 바뀌었을 때 A 레코드만 다시 가리키기
sudo anago server renew --dns
```

**어느 CA에서 받을지를 바꾸는 플래그는 즉시 재발급입니다** — `--force`가
필요 없고, 그래서 **`--acme-staging`은 돌고 있는 허브에서 쓰면 안 됩니다**:
지금 서빙 중인 인증서를 아무도 믿지 않는 것으로 갈아끼우고, 그때부터
`--acme-production`으로 되돌릴 때까지 `join`이 실패합니다. 배선 확인용
스테이징은 **처음 세울 때** 쓰는 것입니다.

레이트 리밋에 걸리면 anago가 그렇게 말하고, CA가 알려준 만큼 기다리라고
안내합니다 — 그리고 **디스크의 인증서가 그때까지 버티는지 아닌지**까지
같이 말합니다. 버티면 기다리는 데 드는 비용이 없고, 못 버티면 그 사이
컨트롤 API가 신뢰를 잃습니다(터널은 무관합니다 — wg는 인증서를 쓰지
않습니다).

certbot이 관리하는 인증서(경로 (c))라도 `server run`은 파일이 바뀐 것을
알아채고 재시작 없이 새 인증서를 내놓습니다.

### 6. 확인하고 관리하기

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
| 서버 상태 | `/var/lib/anago/state.json` | 0600. 서브넷·서버 키쌍·피어·조인 코드·TLS 설정 |
| 서버 wg 설정 | `/etc/wireguard/anago.conf` | 상태에서 생성. 피어마다 `/32` |
| systemd 유닛 | `/etc/systemd/system/anago.service` | ExecStart는 `anago server run` |
| 발급받은 인증서 | `/var/lib/anago/tls/fullchain.pem`, `privkey.pem` | anago가 발급했을 때만. `--tls-cert`로 준 파일은 있던 자리 그대로 |
| ACME 계정 키 | `/var/lib/anago/tls/account.key` | 이 허브가 CA에게 자기를 증명하는 키 |
| Cloudflare 토큰 | `/var/lib/anago/cf-token` | 0600. **DNS-01 갱신이 다시 쓸 때만** 보관. 상태 파일에는 안 들어갑니다 |
| 기기 설정 | `~/.config/anago/device.json` | 0600, 당신 소유. 도메인·토큰·할당 IP·서버 공개키 |
| 기기 wg 설정 | `/etc/wireguard/anago.conf` | 개인키는 여기에만 있습니다 |
| sync 타이머 (리눅스) | `/etc/systemd/system/anago-sync.{timer,service}` | `--install-timer`가 씁니다 |
| sync 타이머 (맥) | `/Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist` | 로그는 `/var/log/anago-sync.log` |

## 알아둘 것

- 허브는 트래픽을 **복호화해 중계**합니다(허브-스포크의 성질). 그 서버가
  당신의 것이라는 게 이 프로젝트의 전제입니다 — M2의 직결이 붙으면 기기
  간 트래픽은 E2E가 됩니다. 자세한 건 DESIGN §5.
- 조인 코드는 1회용이고 15분 뒤 만료됩니다. 기기 토큰은 서버에 **해시로만**
  저장됩니다(DESIGN §7).
- **`--export`는 "개인키는 기기를 떠나지 않는다"의 유일한 예외**이고,
  의도된 것입니다 — 폰에는 키를 만들 anago가 없으니까요. 그래서 그 경로만
  경고와 정리 안내를 달고 다닙니다(DESIGN §7.3). 그리고 그 폰은 자기
  토큰을 받지 않으므로 **스스로를 지우지 못합니다** — 지우는 것은 다른
  쪽 일입니다. 허브에서 `sudo anago rm <이름>`, 또는 **이미 합류한 아무
  기기에서나** `anago rm <이름>`. 컨트롤 API는 *부르는 쪽*을 인증하지
  지워지는 쪽을 인증하지 않으므로, 유효한 토큰을 가진 기기면 됩니다.
- 실패했을 때 anago는 **되돌릴 뿐, 조용히 고치지 않습니다.** join이 중간에
  실패하면 허브의 등록을 취소하고, 프록시가 켜진 A 레코드는 끄지 않고
  거절하고, 정리하지 못한 DNS-01 TXT 레코드는 어느 것을 지워야 하는지
  말합니다. 사람의 이름·서버·계정에 대한 결정은 사람이 합니다.
- Windows는 v1 비대상입니다(WSL2로 우회).

## 라이선스

MIT
