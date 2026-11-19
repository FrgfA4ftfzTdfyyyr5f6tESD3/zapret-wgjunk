-- =============================================================================
-- wg_protocols.lua - Protocol Mimicry Specifications & Builders
-- =============================================================================
-- Modular protocol definitions for WireGuard DPI Bypass.
-- RFC-aligned UDP packet structures for 17 protocols with realistic headers.
-- All protocols configured for balanced Lead-In streams (4..8 packets)
-- within the golden 1.5s - 2.5s window to reliably trigger DPI Fast-Path offload.
--
-- Stateful CPS Chain (I1 / I2):
--   - seq == 1 (I1): Authentic Protocol Signature with binary handshake headers.
--   - seq >  1 (I2): Stateful Dynamic Session with 32-bit Big-Endian Unix Timestamp
--                    (os.time()) + Sequence Counter (seq) to defeat behavioral DPI.
-- =============================================================================

-- Binary encoding helpers
local function u16be(n)
	n = (n or 0) % 65536
	return string.char(math.floor(n / 256), n % 256)
end

local function u32be(n)
	n = (n or 0) % 4294967296
	local b0 = math.floor(n / 16777216) % 256
	local b1 = math.floor(n / 65536) % 256
	local b2 = math.floor(n / 256) % 256
	local b3 = n % 256
	return string.char(b0, b1, b2, b3)
end

local function u24le(n)
	n = (n or 0) % 16777216
	return string.char(n % 256, math.floor(n / 256) % 256, 0)
end

-- Stateful CPS Chain Body Builder (I1 / I2):
--   seq == 1 (I1): Authentic Protocol Signature with random entropy
--   seq >  1 (I2): Dynamic Session packet with 32-bit Big-Endian Unix Timestamp (os.time())
--                  + Sequence Counter (seq) followed by entropy
local function build_lead_payload(hdr, size, seq)
	local pad_len = math.max(0, size - #hdr)
	if (seq or 1) > 1 and pad_len >= 8 then
		local ts_now = os.time()
		local dynamic_hdr = u32be(ts_now) .. u32be(seq)
		return hdr .. dynamic_hdr .. brandom(pad_len - 8)
	elseif (seq or 1) > 1 and pad_len >= 4 then
		local ts_now = os.time()
		return hdr .. u32be(ts_now) .. brandom(pad_len - 4)
	else
		return hdr .. brandom(pad_len)
	end
end

-- =============================================================================
-- Profile Specifications (Dual-Phase Cover Envelope Protocols)
-- =============================================================================
WG_PROTO_SPECS = {
	junk = {
		name = "Classic Random Junk (AmneziaWG)",
		c_min = 4, c_max = 8,
		s_min = 100, s_max = 950,
		build = function(size, seq)
			if (seq or 1) > 1 and size >= 8 then
				return u32be(os.time()) .. u32be(seq) .. brandom(size - 8)
			else
				return brandom(size)
			end
		end
	},
	quic_v1 = {
		name = "QUIC v1 / HTTP/3 (Short Header 1-RTT Stream)",
		c_min = 4, c_max = 8,
		s_min = 1200, s_max = 1250,
		build = function(size, seq)
			-- Byte 0: 0x43 (1-RTT Short Header, PktNumLen=2) - Fast-Path encrypted data bypass
			-- Bytes 1..8: 8-byte DCID
			-- Bytes 9..10: Packet Number (seq)
			-- Bytes 11..12: Flags (0x0000)
			-- Bytes 13..19: Token
			local hdr = "\x43" .. brandom(8) .. u16be(seq) .. "\x00\x00" .. brandom(7)
			return build_lead_payload(hdr, size, seq)
		end
	},
	quic_v2 = {
		name = "QUIC v2 / RFC 9369 (Initial Long Header Stream)",
		c_min = 4, c_max = 8,
		s_min = 1200, s_max = 1250,
		build = function(size, seq)
			-- Byte 0: 0xD0 (Long Header, Type=Initial(1) in v2, FixedBit=1)
			-- Bytes 1..4: 0x6B, 0x33, 0x43, 0xCF (QUIC v2 Version)
			-- Byte 5: 0x08 (DCID Length)
			-- Bytes 6..13: 8-byte DCID
			-- Byte 14: 0x00 (SCID Length = 0)
			-- Byte 15: 0x00 (Token Length = 0)
			-- Bytes 16..17: Length
			-- Byte 18: Packet Number (seq)
			local hdr = "\xD0\x6B\x33\x43\xCF\x08" .. brandom(8) .. "\x00\x00\x44\x50" .. string.char(seq % 256)
			return build_lead_payload(hdr, size, seq)
		end
	},
	webrtc = {
		name = "WebRTC / SRTP (RTP v2 Dynamic PT=96)",
		c_min = 4, c_max = 8,
		s_min = 64, s_max = 220,
		build = function(size, seq)
			local ts = (seq * 160) % 4294967296
			local hdr = "\x80\x60" .. u16be(seq) .. u32be(ts) .. "\x11\x22\x33\x44\x00\x00" .. brandom(6)
			return build_lead_payload(hdr, size, seq)
		end
	},
	dtls = {
		name = "DTLS 1.2 (Application Data Record Stream)",
		c_min = 4, c_max = 8,
		s_min = 180, s_max = 350,
		build = function(size, seq)
			local frag_len = math.max(0, size - 13)
			local hdr = "\x17\xFE\xFD\x00\x01\x00\x00\x00\x00" .. u16be(seq) .. u16be(frag_len) .. "\x00\x00" .. brandom(5)
			return build_lead_payload(hdr, size, seq)
		end
	},
	dns = {
		name = "DNS Query / mDNS (RFC 1035 Standard)",
		c_min = 4, c_max = 8,
		s_min = 42, s_max = 68,
		build = function(size, seq)
			local tx_id = math.random(1, 0xFFFF)
			local hdr = u16be(tx_id) .. "\x01\x00\x00\x01\x00\x00\x00\x00" .. brandom(8) .. "\x00\x01"
			return build_lead_payload(hdr, size, seq)
		end
	},
	esp = {
		name = "IPsec NAT-T ESP (Enterprise Tunnel)",
		c_min = 4, c_max = 8,
		s_min = 100, s_max = 850,
		build = function(size, seq)
			local hdr = "\x19\x84\x07\x10" .. u32be(seq) .. "\x00\x00" .. brandom(8) .. "\x00\x00"
			return build_lead_payload(hdr, size, seq)
		end
	},
	utp = {
		name = "uTP BitTorrent (State Data Packet)",
		c_min = 4, c_max = 8,
		s_min = 60, s_max = 400,
		build = function(size, seq)
			local ts = math.floor(clock_getfloattime() * 1000000) % 4294967296
			local hdr = "\x21\x00\x04\xD2" .. u32be(ts) .. "\x00\x00\x00\x00\x00\x10\x00\x00" .. u16be(seq) .. u16be(math.max(0, seq - 1))
			return build_lead_payload(hdr, size, seq)
		end
	},
	raknet = {
		name = "RakNet Gaming (Minecraft Bedrock)",
		c_min = 4, c_max = 8,
		s_min = 100, s_max = 500,
		build = function(size, seq)
			local body_bytes = math.max(0, size - 7)
			local bit_len = (body_bytes * 8) % 65536
			local hdr = "\x84" .. u24le(seq) .. "\x40" .. u16be(bit_len) .. u24le(seq) .. "\x00\x00\x00\x00" .. brandom(6)
			return build_lead_payload(hdr, size, seq)
		end
	},
	stun = {
		name = "STUN / ICE Media (WebRTC NAT Traversal)",
		c_min = 4, c_max = 8,
		s_min = 48, s_max = 120,
		build = function(size, seq)
			local msg_len = math.max(0, math.floor((size - 20) / 4) * 4)
			local hdr = "\x00\x01" .. u16be(msg_len) .. "\x21\x12\xA4\x42" .. brandom(12)
			local target_size = 20 + msg_len
			return build_lead_payload(hdr, target_size, seq)
		end
	},
	turn = {
		name = "TURN ChannelData (Relayed Media Stream)",
		c_min = 4, c_max = 8,
		s_min = 48, s_max = 100,
		build = function(size, seq)
			local data_len = math.max(0, size - 4)
			local hdr = "\x40\x00" .. u16be(data_len) .. "\x00\x00\x00\x00" .. brandom(12)
			return build_lead_payload(hdr, size, seq)
		end
	},
	steam = {
		name = "Steam / Valve Source (CS:GO / Dota 2)",
		c_min = 4, c_max = 8,
		s_min = 40, s_max = 120,
		build = function(size, seq)
			local hdr = "\xFF\xFF\xFF\xFF\x54Source Engine Query\x00"
			return build_lead_payload(hdr, size, seq)
		end
	},
	sdr = {
		name = "Steam Datagram Relay (CS2 SDR Transport)",
		c_min = 4, c_max = 8,
		s_min = 60, s_max = 150,
		build = function(size, seq)
			local hdr = "\x01\x00\x01\x00\x00" .. u32be(seq) .. "\x00\x00" .. brandom(9)
			return build_lead_payload(hdr, size, seq)
		end
	},
	riot = {
		name = "Riot Games (Valorant / LoL Media)",
		c_min = 4, c_max = 8,
		s_min = 50, s_max = 120,
		build = function(size, seq)
			local hdr = "\x00\x01\x02" .. u32be(seq) .. "\x00\x00" .. brandom(11)
			return build_lead_payload(hdr, size, seq)
		end
	},
	zoom = {
		name = "Zoom Media Stream (RTP Video / Voice)",
		c_min = 4, c_max = 8,
		s_min = 80, s_max = 240,
		build = function(size, seq)
			local ts = (seq * 3000) % 4294967296
			local hdr = "\x80\x62" .. u16be(seq) .. u32be(ts) .. "\x4A\x53\x54\x55\x00\x00" .. brandom(6)
			return build_lead_payload(hdr, size, seq)
		end
	},
	rdp = {
		name = "Microsoft RDP over UDP (MS-RDPEUDP)",
		c_min = 4, c_max = 8,
		s_min = 70, s_max = 200,
		build = function(size, seq)
			local hdr = "\xD0\x00\x00\x01" .. u32be(seq) .. "\x00\x00" .. brandom(8) .. "\x00\x00"
			return build_lead_payload(hdr, size, seq)
		end
	},
	discord = {
		name = "Discord Voice & Media (Opus Audio Transport)",
		c_min = 4, c_max = 8,
		s_min = 60, s_max = 160,
		build = function(size, seq)
			local ts = (seq * 960) % 4294967296
			local hdr = "\x80\x78" .. u16be(seq) .. u32be(ts) .. "\xDE\xAD\xBE\xEF\x00\x00" .. brandom(6)
			return build_lead_payload(hdr, size, seq)
		end
	}
}

-- Tier-1 Golden Protocols for AUTO mode (highest success rate on strict networks)
TIER1_PROTO_LIST = {
	"quic_v1",  -- [2] QUIC v1 / HTTP3 Short Header (0x43) - Fast-Path encrypted data
	"quic_v2",  -- [3] QUIC v2 / RFC 9369 Long Header Initial
	"webrtc",   -- [4] WebRTC / SRTP VoIP Media (PT=96)
	"dtls",     -- [5] DTLS 1.2 Cisco AnyConnect / Enterprise
	"esp",      -- [7] IPsec NAT-T ESP Enterprise VPN Tunnel
	"stun"      -- [10] STUN / ICE Media NAT Traversal
}

-- List of all 17 selectable profiles [1..17]
PROTOCOL_LIST = {
	"junk", "quic_v1", "quic_v2", "webrtc", "dtls", "dns", "esp", "utp",
	"raknet", "stun", "turn", "steam", "sdr", "riot", "zoom", "rdp", "discord"
}

-- Numeric ID mapping for CMD menu [0..17]
NUM_TO_PROTO = {
	["0"]  = "auto",
	["1"]  = "junk",
	["2"]  = "quic_v1",
	["3"]  = "quic_v2",
	["4"]  = "webrtc",
	["5"]  = "dtls",
	["6"]  = "dns",
	["7"]  = "esp",
	["8"]  = "utp",
	["9"]  = "raknet",
	["10"] = "stun",
	["11"] = "turn",
	["12"] = "steam",
	["13"] = "sdr",
	["14"] = "riot",
	["15"] = "zoom",
	["16"] = "rdp",
	["17"] = "discord"
}
