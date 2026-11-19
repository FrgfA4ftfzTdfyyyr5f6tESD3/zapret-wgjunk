@echo off
chcp 65001 >nul
title WireGuard DPI Bypass (Stateful Cover Envelope + Session Lock)
cd /d "%~dp0"

:: Terminate any previously running winws2 instances to avoid filter conflicts
taskkill /f /im winws2.exe >nul 2>&1

set "CHOSEN_MODE=%~1"
set "REVERSE_ARG=%~2"
if not "%CHOSEN_MODE%"=="" goto START_DIRECT

:MENU
cls
echo =========================================================================
echo       WireGuard DPI Bypass - Protocol Mimicry + Cover Envelope
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
echo     * [0] AUTO    : Smart non-repeating rotation across 6 Tier-1 Golden Protocols
echo     * Zero-NAT    : Authentic client ephemeral port preserved (zero data drops)
echo     * Drop Repeat : Immediate drop of dead-port retries (forces port rotation)
echo     * Session Lock: Disengages 100%% on 92B response; re-keys pass directly
echo     * Stateful CPS: Authentic RFC signature (I1) + Unix Timestamp (I2) in 1.5..2.5s
echo =========================================================================
set "CHOSEN_MODE=0"
set /p "CHOSEN_MODE=Select mode [0-17] (Default: 0 - AUTO): "
if "%CHOSEN_MODE%"=="" set "CHOSEN_MODE=0"

echo.
set "ENABLE_REV=N"
set /p "ENABLE_REV=Enable Beta Reverse-Handshake (Rekey Swap) [y/N]? (Default: N): "
if /i "%ENABLE_REV%"=="y" (
    set "REVERSE_ARG=1"
) else (
    set "REVERSE_ARG=0"
)

:START_DIRECT
if "%REVERSE_ARG%"=="" set "REVERSE_ARG=0"

echo.
echo Launching winws2 with mode: %CHOSEN_MODE% (Reverse Rekey Beta: %REVERSE_ARG%)...
echo Listening for WireGuard Type 1 Handshakes (148 B) and Type 2 Responses (92 B)...
echo.

"%~dp0winws2.exe" ^
--wf-dup-check=0 ^
--ctrack-disable=1 ^
--reasm-disable ^
--payload-disable ^
--ipcache-lifetime=0 ^
--wf-filter-lan=0 ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.wireguard_handshake.txt" ^
--lua-init=@"%~dp0lua\zapret-lib.lua" ^
--lua-init=@"%~dp0lua\zapret-antidpi.lua" ^
--lua-init=@"%~dp0lua\wg_protocols.lua" ^
--lua-init=@"%~dp0lua\wg_state.lua" ^
--lua-init=@"%~dp0lua\wg_reverse_rekey.lua" ^
--lua-init=@"%~dp0lua\wg_envelope.lua" ^
--lua-init=@"%~dp0lua\zapret-wgjunk.lua" ^
--out-range=a ^
--in-range=a ^
--lua-desync=wg_junk:mode=%CHOSEN_MODE%:reverse=%REVERSE_ARG%

echo.
echo winws2 process terminated.
pause
