@echo off
chcp 65001 >nul
title IKEv2 NAT-T (UDP 4500) DPI Bypass (Proactive Cover Envelope + Session Lock)
cd /d "%~dp0"

:: Terminate any previously running winws2 instances to avoid filter conflicts
taskkill /f /im winws2.exe >nul 2>&1

set "CHOSEN_MODE=%~1"
if not "%CHOSEN_MODE%"=="" goto START_DIRECT

:MENU
cls
echo =========================================================================
echo       IKEv2 NAT-T (UDP 4500) DPI Bypass - Protocol Mimicry + Envelope
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
echo   Engine Features + Mode Guide:
echo     * Dual-Port   : UDP 500 (^<1s Fast) + UDP 4500 (NAT-T 1.3..1.85s)
echo     * Raw ESP     : IP Protocol 50 bypasses WinDivert natively in kernel
echo     * Frag Safe   : SKF (0x35) fragments 2..N pass immediately (no drops)
echo     * Session Lock: Disengages 100%% on server UDP 500 / 4500 response
echo =========================================================================
set "CHOSEN_MODE=0"
set /p "CHOSEN_MODE=Select mode [0-17] (Default: 0 - AUTO): "
if "%CHOSEN_MODE%"=="" set "CHOSEN_MODE=0"

:START_DIRECT
echo.
echo Launching winws2 for IKEv2 NAT-T (UDP 4500) with mode: %CHOSEN_MODE%...
echo Note: UDP 500 and Raw IPsec ESP (Proto 50) pass natively with zero overhead.
echo.

"%~dp0winws2.exe" ^
--wf-dup-check=0 ^
--ctrack-disable=1 ^
--reasm-disable ^
--payload-disable ^
--ipcache-lifetime=0 ^
--wf-filter-lan=0 ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.ikev2_handshake.txt" ^
--lua-init=@"%~dp0lua\zapret-lib.lua" ^
--lua-init=@"%~dp0lua\zapret-antidpi.lua" ^
--lua-init=@"%~dp0lua\wg_protocols.lua" ^
--lua-init=@"%~dp0lua\ikev2_state.lua" ^
--lua-init=@"%~dp0lua\wg_envelope.lua" ^
--lua-init=@"%~dp0lua\zapret-ikev2junk.lua" ^
--out-range=a ^
--in-range=a ^
--lua-desync=ikev2_junk:mode=%CHOSEN_MODE%

echo.
echo winws2 process terminated.
pause
