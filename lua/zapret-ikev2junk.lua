-- =============================================================================
-- zapret-ikev2junk.lua - Dual-Port IKEv2 (UDP 500 + UDP 4500) DPI Bypass
-- =============================================================================
-- Reuses wg_protocols.lua (17 RFC protocols + Tier-1 AUTO) and wg_envelope.lua
-- (Dual-Phase Stateful CPS Cover Envelope) for IKEv2 over UDP 500 & UDP 4500.
-- Raw IPsec ESP (IP Protocol 50) never enters WinDivert (native kernel speed).
--
-- Wire Offsets:
--   * UDP 500 (offset = 0):
--       Byte 17: Next Payload | Byte 18: Version (0x20) | Byte 19: Exch (0x22/0x23)
--       Bytes 21..24: MID | SKF (0x35) Frag/Total at Bytes 33..36
--   * UDP 4500 (offset = 4, prefixed by 4-byte Non-ESP Marker 0x00000000):
--       Byte 21: Next Payload | Byte 22: Version (0x20) | Byte 23: Exch (0x22/0x23)
--       Bytes 25..28: MID | SKF (0x35) Frag/Total at Bytes 37..40
-- =============================================================================

if not WG_PROTO_SPECS or not TIER1_PROTO_LIST then
	if not pcall(dofile, "lua/wg_protocols.lua") then pcall(dofile, "wg_protocols.lua") end
end
if not execute_envelope then
	if not pcall(dofile, "lua/wg_envelope.lua") then pcall(dofile, "wg_envelope.lua") end
end
if not ikev2_flow_get_entry then
	if not pcall(dofile, "lua/ikev2_state.lua") then pcall(dofile, "ikev2_state.lua") end
end

local ikev2_hs_counter = 0
local ikev2_last_profile = nil

local function has_non_esp_marker(payload)
	if #payload < 32 then return false end
	return string.byte(payload, 1) == 0 and string.byte(payload, 2) == 0
	   and string.byte(payload, 3) == 0 and string.byte(payload, 4) == 0
end

-- Returns (is_target, exchange_name, mid, frag_num, total_frags, is_port_500)
local function parse_ikev2_packet(payload, sport, dport)
	local is_port_500 = (sport == 500 or dport == 500)
	local off = 0

	if is_port_500 then
		if #payload < 28 then return false end
		off = 0
	else
		if not has_non_esp_marker(payload) then return false end
		off = 4
	end

	local next_payload = string.byte(payload, 17 + off)
	local version      = string.byte(payload, 18 + off)
	local exch_type    = string.byte(payload, 19 + off)
	if version ~= 0x20 then return false end

	if exch_type ~= 0x22 and exch_type ~= 0x23 then
		return false
	end

	local mid = ((string.byte(payload, 21 + off) * 256 + string.byte(payload, 22 + off)) * 256
	           + string.byte(payload, 23 + off)) * 256 + string.byte(payload, 24 + off)

	local frag_num = 1
	local total_frags = 1
	if next_payload == 0x35 and #payload >= (36 + off) then
		frag_num    = string.byte(payload, 33 + off) * 256 + string.byte(payload, 34 + off)
		total_frags = string.byte(payload, 35 + off) * 256 + string.byte(payload, 36 + off)
	end

	local label = (exch_type == 0x22) and "IKE_SA_INIT (0x22)" or "IKE_AUTH (0x23)"
	return true, label, mid, frag_num, total_frags, is_port_500
end

function ikev2_junk(ctx, desync)
	local dis = desync.dis
	if not dis or not dis.udp or not dis.payload then return VERDICT_PASS end

	local payload_len = #dis.payload
	local sport = dis.udp.uh_sport or 0
	local dport = dis.udp.uh_dport or 0

	-- =========================================================================
	-- 1. INBOUND PACKET HANDLING (Server Response on UDP 500 or 4500 -> Lock)
	-- =========================================================================
	if not desync.outgoing then
		local flow_key = ikev2_get_flow_key(dis, true)
		local entry = flow_key and ikev2_flow_get_entry(flow_key)
		if entry and entry.state ~= "ESTABLISHED" then
			local is_port_500 = (sport == 500 or dport == 500)
			local locked = false
			if is_port_500 then
				if payload_len >= 28 and string.byte(dis.payload, 18) == 0x20 then
					locked = true
				end
			else
				local is_ike_resp = has_non_esp_marker(dis.payload) and string.byte(dis.payload, 22) == 0x20
				local is_esp_udp  = (not has_non_esp_marker(dis.payload)) and payload_len >= 32
				if is_ike_resp or is_esp_udp then locked = true end
			end

			if locked then
				ikev2_flow_set_established(flow_key)
				local time_str = os.date("%H:%M:%S")
				print("=========================================================================")
				print(string.format("  IKEv2 SERVER RESPONSE RECEIVED (UDP %d)!", is_port_500 and 500 or 4500))
				print("-------------------------------------------------------------------------")
				print(string.format("  Time          : %s", time_str))
				print(string.format("  Flow          : %s (%d B)", flow_key, payload_len))
				print("  Session State : LOCKED_ESTABLISHED (Tunnel Handshake Proceeding)")
				print("  Desync Engine : Disengaged for this flow. Zero-overhead passthrough.")
				if ai_brain_on_lock then
					ai_brain_on_lock(is_port_500 and "ikev2_500" or "ikev2_4500", flow_key, payload_len)
				end
				print("=========================================================================\n")
			end
		end
		return VERDICT_PASS
	end

	-- =========================================================================
	-- 2. OUTBOUND PACKET HANDLING (UDP 500 IKE_SA_INIT & UDP 4500 IKE_AUTH)
	-- =========================================================================
	local is_target, exch_label, mid, frag_num, total_frags, is_port_500 = parse_ikev2_packet(dis.payload, sport, dport)
	if not is_target then
		return VERDICT_PASS
	end

	local flow_key = ikev2_get_flow_key(dis, false)
	if not flow_key then return VERDICT_PASS end

	local entry = ikev2_flow_get_entry(flow_key)
	if entry and entry.state == "ESTABLISHED" then
		return VERDICT_PASS
	end

	local now = clock_getfloattime()
	-- Handle subsequent SKF fragments (2/N, 3/N...) cleanly in order behind LEAD-IN
	if frag_num > 1 then
		if entry and entry.last_mid == mid and entry.hs_fire_at then
			local fkey = tostring(mid) .. ":" .. tostring(frag_num) .. ":" .. tostring(entry.attempt or 1)
			if entry.frags_sent and entry.frags_sent[fkey] then
				return VERDICT_DROP
			end
			if entry.frags_sent then entry.frags_sent[fkey] = true end

			local rem_ms = math.floor((entry.hs_fire_at - now) * 1000)
			if rem_ms > 0 and on_frag_timer then
				timer_set(string.format("ikefrag_%d_%d_%d", sport, frag_num, math.random(1000, 9999)),
					on_frag_timer, rem_ms + (frag_num * 5), true, {
						frag_dis    = deepcopy(dis),
						frag_num    = frag_num,
						total_frags = total_frags,
						start_time  = entry.last_envelope or now
					})
				return VERDICT_DROP
			end
		end
		print(string.format("  [FRAGMENT %d/%d PASSED] Flow %s (MID=%d) ---> VERDICT_PASS", frag_num, total_frags, flow_key, mid))
		return VERDICT_PASS
	end

	local proto_key = is_port_500 and "ikev2_500" or "ikev2_4500"
	local cooldown = is_port_500 and 1.2 or 2.5
	if entry and entry.state == "TRIED" and entry.last_mid == mid and (now - (entry.last_envelope or 0)) < cooldown then
		if ai_brain_on_retry_drop then ai_brain_on_retry_drop(proto_key, flow_key, "cooldown_overlap") end
		print(string.format("  [RETRY OVERLAP DROPPED] Flow %s (MID=%d, dt=%.2fs < %.1fs) ---> DROPPED",
			flow_key, mid, now - (entry.last_envelope or 0), cooldown))
		return VERDICT_DROP
	end

	local start_time = now
	ikev2_hs_counter = ikev2_hs_counter + 1
	local updated_entry = ikev2_flow_register_attempt(flow_key, ikev2_hs_counter, mid)

	local raw_mode = tostring((desync.arg and desync.arg.mode) or "auto"):lower()
	local exclude_mask = (updated_entry.attempt > 1) and ikev2_last_profile or nil
	local selected_key, spec, is_auto, ai_label = nil, nil, false, nil
	if ai_brain_select_spec then
		selected_key, spec, is_auto, ai_label = ai_brain_select_spec(proto_key, raw_mode, ikev2_last_profile, exclude_mask, flow_key)
		if is_auto then ikev2_last_profile = selected_key end
	else
		selected_key = (NUM_TO_PROTO and NUM_TO_PROTO[raw_mode]) or raw_mode
		if selected_key == "auto" then
			is_auto = true
			local pool = (TIER1_PROTO_LIST and #TIER1_PROTO_LIST > 0) and TIER1_PROTO_LIST or PROTOCOL_LIST
			if pool and #pool > 0 then
				local pick = pool[math.random(1, #pool)]
				if #pool > 1 and pick == ikev2_last_profile then
					local candidate_pool = {}
					for _, v in ipairs(pool) do
						if v ~= ikev2_last_profile then table.insert(candidate_pool, v) end
					end
					pick = candidate_pool[math.random(1, #candidate_pool)]
				end
				selected_key = pick
				ikev2_last_profile = selected_key
			else
				selected_key = "quic_v1"
			end
		end
		spec = (WG_PROTO_SPECS and WG_PROTO_SPECS[selected_key]) or (WG_PROTO_SPECS and WG_PROTO_SPECS.junk)
	end
	if not spec then
		spec = {
			name = "Random Noise Junk",
			c_min = 4, c_max = 8,
			s_min = 100, s_max = 900,
			build = function(size, seq) return brandom(size) end
		}
	end

	-- Fast <1s envelope on UDP 500 (IKE_SA_INIT); snappy 1.3..1.85s on UDP 4500 (IKE_AUTH)
	local base_opts = is_port_500
		and { jc_min = 2, jc_max = 3, pace_min = 600, pace_max = 950, size_bias = 1.0, trail1_ms = 60, trail2_ms = 180 }
		or  { jc_min = 4, jc_max = 6, pace_min = 1300, pace_max = 1850, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220 }
	local env_opts = ai_brain_get_envelope_opts and ai_brain_get_envelope_opts(proto_key, base_opts, flow_key) or base_opts

	if ai_brain_on_attempt then
		ai_brain_on_attempt(proto_key, flow_key, selected_key, updated_entry.attempt, start_time, env_opts)
	end

	local time_str = os.date("%H:%M:%S")
	local tier_label = is_auto and (ai_label and (" [" .. ai_label .. "]") or " [Tier-1 Auto-Selected]") or ""

	print("=========================================================================")
	print(string.format("  IKEv2 UDP %d HANDSHAKE #%d DETECTED (Attempt #%d | MID=%d)",
		is_port_500 and 500 or 4500, ikev2_hs_counter, updated_entry.attempt, mid))
	print("-------------------------------------------------------------------------")
	print(string.format("  Time          : %s", time_str))
	print(string.format("  Packet Type   : %s | %d B", exch_label, payload_len))
	print(string.format("  Flow (Wire)   : %s", flow_key))
	print(string.format("  Framing Mode  : Dual-Phase Cover Envelope (%s)%s", spec.name, tier_label))
	print("  Envelope Plan : LEAD-IN (I1 Signature + I2 Timestamp) ➔ IKEv2 ➔ DUAL TRAIL (60ms, 180ms)")
	print(string.format("  Port Strategy : %s", is_port_500 and "UDP 500 Fast (<1s) Silent-Drop Safe" or "UDP 4500 Non-Zero SPI Safe Cover (RFC 3948)"))
	print("-------------------------------------------------------------------------")

	local verdict, total_win_ms = execute_envelope(ctx, desync, spec, start_time, env_opts)
	if total_win_ms and updated_entry then
		updated_entry.hs_fire_at = start_time + (total_win_ms / 1000.0)
	end
	return verdict
end
