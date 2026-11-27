# 🛡️ WireGuard DPI Bypass Module (`wgjunk`) for `zapret-win-bundle`

An independent, drop-in Lua & WinDivert module built for **`bol-van/zapret-win-bundle`** (`winws2.exe`). Instead of relying on static random junk or broken IP fragmentation, this engine uses **Zero-NAT port preservation**, **Stateful CPS framing**, and **Noise_IK Role Swapping** to bypass deep packet inspection on standard and commercial WireGuard clients (Windscribe, WARP, official WireGuard).

---

## 📦 Prerequisites & Installation (Drop-In Add-on)

This repository contains **only the modular bypass files** and requires the official Windows binary bundle:

1. Download the latest **`zapret-win-bundle`** from the official repository:  
   👉 **[github.com/bol-van/zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle)**
2. Extract the archive and open the **`zapret-winws/`** directory.
3. Copy all files and folders from this module (`preset2_wireguard_junk.cmd`, `lua/`, `windivert.filter/`) directly into **`zapret-winws/`** (overwrite if prompted).

---

## ⚡ Core Innovations & Differentiators

| Capability | Standard Tools / Generic Presets | **This Module (`Zero-NAT` + `Reverse Rekey`)** |
| :--- | :--- | :--- |
| **Zero-NAT Port Integrity** | Port spoofing breaks NAT tables or drops `Type 4` data | **100% Authentic Ephemeral Port:** Never rewrites client source ports. Data packets and keepalives flow with zero kernel/Wintun mismatch and zero IP fragmentation. |
| **Dead-Port Eviction** | Repeats useless junk on blocked sockets | **Immediate Duplicate Drop (`VERDICT_DROP`):** Retries on unestablished sockets are dropped instantly, forcing closed clients (Windscribe/WireGuard) to rotate to a fresh ephemeral port immediately. |
| **Stateful CPS Framing** | Static random noise blobs | **RFC Signature (`I1`) + Unix Timestamp (`I2`):** Lead-in packets pair authentic protocol headers (`QUIC v1/v2`, `WebRTC`, `DTLS`, `STUN`, `IPsec`) with live 32-bit `os.time()` payloads, followed by dual asynchronous trail packets (`+60ms`, `+180ms`). |
| **Zero-Overhead Session Lock** | Keeps inspecting and injecting throughout the tunnel | **Instant Disengagement (`LOCKED_ESTABLISHED`):** The moment the 92 B server response (`Type 2`) arrives, the engine disengages completely (`0 ms` added latency). |
| **Permanent Role Swap (Beta)** | Client always emits detectable `148 B` rekeys every 2 min | **Noise_IK Reverse Handshake (`wg_reverse_rekey.lua`):** Suppresses the client's first outbound rekey (`120s..220s`), causing the **Server** to assume the `Initiator` role (`Inbound 148 B`) while the Client permanently switches to `Responder` (`Outbound 92 B`). |

---

## 🔄 How `Reverse Rekey` (Noise_IK Role Swap) Works

Per the WireGuard specification (*"allow initiator and responder to swap roles"*), peer roles are not fixed:

```text
[t = 0s]     Client sends Stateful Cover Envelope ──► Handshake (148 B) ──► Server replies (92 B)
             Session state locks (LOCKED_ESTABLISHED). Server now knows Client's exact IP:Port.

[t = 120s]   Client attempts Rekey #1 (Outbound 148 B) ──► Suppressed by wg_reverse_rekey.lua
             (Existing Type 4 user traffic continues uninterrupted on the active keypair)

[t ~ 180s]   Server's Reject-After-Time window triggers ──► Server initiates Inbound Type 1 (148 B)
             Client replies Outbound Type 2 (92 B) ──► Client locks as RESPONDER (is_initiator = false)

[t > 180s]   Module enters DEEP_SLEEP (0% CPU). On all subsequent cycles (t = 300s, 420s, ...),
             the Server initiates rekeys automatically and the Client never emits outbound 148 B again.
```

---

## 🌟 Operational Modes [0..17]

```
=========================================================================
      WireGuard DPI Bypass - Protocol Mimicry + Cover Envelope
=========================================================================
  [0]  AUTO (Auto-rotate across 6 Golden Protocols) [RECOMMENDED]
  [1]  Classic Random Junk (AmneziaWG)
  -----------------------------------------------------------------------
  [2]  QUIC v1 / HTTP/3 (Short 0x43)      [10] STUN / ICE (WebRTC NAT)
  [3]  QUIC v2 / RFC 9369                 [11] TURN ChannelData
  [4]  WebRTC / SRTP (VoIP)               [12] Steam Source (CS:GO)
  [5]  DTLS 1.2 (AnyConnect)              [13] Steam Datagram (CS2 SDR)
  [6]  DNS Query / mDNS                   [14] Riot Games (Valorant/LoL)
  [7]  IPsec NAT-T ESP (Tunnel)           [15] Zoom Media Stream
  [8]  uTP BitTorrent                     [16] Microsoft RDP over UDP
  [9]  RakNet (Minecraft)                 [17] Discord Voice + Media
=========================================================================
```

* **`[0] AUTO` [RECOMMENDED]:** Strictly rotates without repeating across the **6 Tier-1 Golden Protocols**:
  1. `QUIC v1 / HTTP/3` (Short Header `0x43` Data Stream)
  2. `QUIC v2 / RFC 9369` (Initial Long Header Stream)
  3. `WebRTC / SRTP` (RTP v2 Dynamic Payload Type 96 VoIP)
  4. `DTLS 1.2` (Cisco AnyConnect / OpenConnect Application Data)
  5. `IPsec NAT-T ESP` (Enterprise UDP Encapsulated Tunnel)
  6. `STUN / ICE Media` (NAT Traversal Binding Request)
* **`[1] Classic Random Junk`:** AmneziaWG noise burst inside the Dual-Phase Envelope.
* **`[2..17] Extended Protocols`:** Direct selection of specific protocols.

---

## 🚀 Usage

### WireGuard (`preset2_wireguard_junk.cmd`)
1. Inside **`zapret-winws/`**, right-click **`preset2_wireguard_junk.cmd`** and select **Run as Administrator**.
2. Choose **`0` (AUTO)** to auto-rotate cleanly across 6 Tier-1 protocols, or pick any specific profile **`[1..17]`**.
3. Choose whether to activate **`Beta Reverse-Handshake (Rekey Swap)`** (`y` or `N`):
   * **`N` (Default):** Runs the proven `Zero-NAT` + `Session Lock` core.
   * **`y` (Beta):** Activates `wg_reverse_rekey.lua` (`220s` suppression window + `DEEP_SLEEP` passive audit).
4. Start your WireGuard or Windscribe connection.

### OpenVPN UDP (`preset2_openvpn_junk.cmd`)
1. Inside **`zapret-winws/`**, right-click **`preset2_openvpn_junk.cmd`** and select **Run as Administrator**.
2. Choose **`0` (AUTO)** or any specific protocol **`[1..17]`**.
3. Supports **all UDP ports** (`1194`, `54783`, `443`, etc.) and all OpenVPN UDP modes (`Plain 14B`, `tls-auth SHA1 42B / SHA256 54B / SHA512 86B`, `tls-crypt 54B`, `tls-crypt-v2 0x50`) with `Zero-NAT`, `Cooldown (<3s)` retry protection, and `Session Lock` on server `0x40`/`0x58` response.
4. Start your OpenVPN UDP or Windscribe (OpenVPN UDP with `Protocol Tweaks: Disabled`) connection.

### IKEv2 Dual-Port (`preset2_ikev2_junk.cmd`)
1. Inside **`zapret-winws/`**, right-click **`preset2_ikev2_junk.cmd`** and select **Run as Administrator**.
2. Choose **`0` (AUTO)** or any specific protocol **`[1..17]`**.
3. Protects both **`UDP 500`** (`IKE_SA_INIT` with `<1s` fast envelope) and **`UDP 4500`** (`IKE_AUTH` NAT-T with `1.3..1.85s` envelope and RFC 7383 `SKF 0x35` fragment pass-through), while leaving Raw **`IPsec ESP (Protocol 50)`** untouched in kernel.
4. Start your IKEv2 connection.

### All-in-One Unified UDP + Self-Learning AI Brain (`preset2_all_udp.cmd`) [RECOMMENDED]
1. Inside **`zapret-winws/`**, right-click **`preset2_all_udp.cmd`** and select **Run as Administrator**.
2. Choose **`0` (AUTO)** to activate the **Dual-Perspective Self-Learning AI Brain (`windscribe_ai_brain.lua`)** across **IKEv2 + WireGuard + OpenVPN UDP** simultaneously in one `winws2.exe` instance.
3. Switch freely between protocols in Windscribe (or use Automatic mode) without restarting `winws2.exe` — the AI Brain tracks **Welford Lock RTT**, **Discounted UCB1 (`γ=0.90`) + 15% Hysteresis**, **Circadian Buckets**, **Port/Subnet Affinity**, and **Contract-Verified Parameter Evolution (`jc`, `pace`, `size_bias`, `trail_ms`)** with `<1ms` Auto-Rollback in `ai_state/`.

---

## 📜 Credits & Acknowledgements

This module builds upon and integrates with several foundational open-source network technologies:

- **[zapret](https://github.com/bol-van/zapret)** & **[zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle)** by **bol-van**: The core anti-DPI packet-processing daemon, multi-protocol engine, and Windows runtime framework (`winws2.exe`).
- **[WinDivert](https://reqrypt.org/windivert.html)** by **basil00**: The high-performance Windows kernel driver enabling real-time packet interception, modification, and injection.
- **[WireGuard](https://www.wireguard.com/)** by **Jason A. Donenfeld**: The modern, high-speed secure network tunnel protocol and Noise_IK cryptographic framework ("initiator/responder role-swapping" specification).
- **[AmneziaWG](https://github.com/amnezia-vpn/amnezia-client)**: Pioneer of client-side initiation framing and noise packet obfuscation concepts for UDP tunnels.

---

## ⚖️ License & Disclaimer

This project is distributed for educational and research purposes under open-source terms compatible with upstream components. All copyrights, trademarks, and registered names belong to their respective project authors.

