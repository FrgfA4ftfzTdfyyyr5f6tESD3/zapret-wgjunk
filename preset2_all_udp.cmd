@echo off
chcp 65001 >nul
title All-in-One UDP DPI Bypass (IKEv2 + WireGuard + OpenVPN UDP)
cd /d "%~dp0"

:: Terminate any previously running winws2 instances to avoid filter conflicts
taskkill /f /im winws2.exe >nul 2>&1

set "WGJUNK_MODE=%~1"
if not "%WGJUNK_MODE%"=="" goto START_DIRECT

:MENU
cls
echo =========================================================================
echo       All-in-One UDP DPI Bypass (IKEv2 + WireGuard + OpenVPN UDP)
echo =========================================================================
echo   [0]  AUTO (Auto-rotate across 6 Golden Protocols) [RECOMMENDED]
echo   [1]  Classic Random Junk (AmneziaWG)
echo   -----------------------------------------------------------------------
echo   [2]  QUIC v1 / HTTP/3 (Short 0x43)      [10] STUN / ICE (WebRTC NAT)
echo   [3]  QUIC v2 / RFC 9369                 [11] TURN ChannelData
echo   [4]  WebRTC / SRTP (VoIP)               [12] Steam Source (CS:GO)
echo   [5]  DTLS 1.2 (AnyConnect)              [13] Steam Datagram (CS2 SDR)
echo   [6]  DNS Query / mDNS                   [14] Riot Games (Valorant/LoL)
echo   [7]  IPsec NAT-T ESP (Tunnel)           [15] Zoom Media Stream
echo   [8]  uTP BitTorrent                     [16] Microsoft RDP over UDP
echo   [9]  RakNet (Minecraft)                 [17] Discord Voice + Media
echo =========================================================================
echo   Unified Multi-Protocol Engine:
echo     * IKEv2       : Dual-Port UDP 500 (^<1s) + UDP 4500 (Frag Safe); Raw ESP native
echo     * WireGuard   : Zero-NAT + Drop Dead-Port Repeat + Session Lock (92B)
echo     * OpenVPN UDP : All ports (0x38/0x50) + Cooldown (^<3s) + Session Lock (0x40)
echo     * Auto-Detect : Switch freely in Windscribe without restarting winws2
echo =========================================================================
set "WGJUNK_MODE=0"
set /p "WGJUNK_MODE=Select mode [0-17] (Default: 0 - AUTO): "
if "%WGJUNK_MODE%"=="" set "WGJUNK_MODE=0"

:START_DIRECT
echo.
echo Launching unified winws2 for IKEv2 + WireGuard + OpenVPN UDP (Mode: %WGJUNK_MODE%)...
echo Raw IPsec ESP (Proto 50) bypasses WinDivert natively in kernel.
echo.

"%~dp0winws2.exe" ^
--wf-dup-check=0 ^
--ctrack-disable=1 ^
--reasm-disable ^
--payload-disable ^
--ipcache-lifetime=0 ^
--wf-filter-lan=0 ^
--writable=ai_state ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.ikev2_handshake.txt" ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.wireguard_handshake.txt" ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.openvpn_handshake.txt" ^
--lua-init=@"%~dp0lua\zapret-lib.lua" ^
--lua-init=@"%~dp0lua\zapret-antidpi.lua" ^
--lua-init=@"%~dp0lua\wg_protocols.lua" ^
--lua-init=@"%~dp0lua\windscribe_ai_brain.lua" ^
--lua-init=@"%~dp0lua\wg_state.lua" ^
--lua-init=@"%~dp0lua\wg_reverse_rekey.lua" ^
--lua-init=@"%~dp0lua\ovpn_state.lua" ^
--lua-init=@"%~dp0lua\ikev2_state.lua" ^
--lua-init=@"%~dp0lua\wg_envelope.lua" ^
--lua-init=@"%~dp0lua\zapret-wgjunk.lua" ^
--lua-init=@"%~dp0lua\zapret-ovpnjunk.lua" ^
--lua-init=@"%~dp0lua\zapret-ikev2junk.lua" ^
--out-range=a ^
--in-range=a ^
--lua-desync=ikev2_junk:mode=%WGJUNK_MODE% ^
--lua-desync=wg_junk:mode=%WGJUNK_MODE%:reverse=0 ^
--lua-desync=ovpn_junk:mode=%WGJUNK_MODE%

echo.
echo winws2 process terminated.
pause
