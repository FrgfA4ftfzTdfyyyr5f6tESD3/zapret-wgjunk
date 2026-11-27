-- =============================================================================
-- zapret-ovpnjunk.lua - OpenVPN UDP DPI Desync & Cover Envelope Orchestrator
-- =============================================================================
-- Reuses wg_protocols.lua (17 RFC protocols + Tier-1 AUTO) and wg_envelope.lua
-- (Dual-Phase Stateful CPS Cover Envelope) for OpenVPN UDP handshakes.
--
-- Supported OpenVPN Hard Reset packets:
--   - Outbound Client V2 (0x38): 14 B (Plain), 42 B (SHA1), 54 B (SHA256 / tls-crypt), 86 B (SHA512)
--   - Outbound Client V3 (0x50): >= 100 B (tls-crypt-v2)
--   - Inbound  Server V2 (0x40) / V3 (0x58): >= 14 B -> Locks session (LOCKED_ESTABLISHED)
-- =============================================================================

if not WG_PROTO_SPECS or not TIER1_PROTO_LIST then
	if not pcall(dofile, "lua/wg_protocols.lua") then pcall(dofile, "wg_protocols.lua") end
end
if not execute_envelope then
	if not pcall(dofile, "lua/wg_envelope.lua") then pcall(dofile, "wg_envelope.lua") end
end
if not ovpn_flow_get_entry then
	if not pcall(dofile, "lua/ovpn_state.lua") then pcall(dofile, "ovpn_state.lua") end
end

local ovpn_hs_counter = 0
local ovpn_last_profile = nil

local VALID_V2_LENGTHS = { [14] = true, [42] = true, [54] = true, [86] = true }

local function is_ovpn_client_reset(payload)
	local plen = #payload
	local b0 = string.byte(payload, 1)
	if b0 == 0x38 and VALID_V2_LENGTHS[plen] then
		return true, "P_CONTROL_HARD_RESET_CLIENT_V2 (0x38)"
	end
	if b0 == 0x50 and plen >= 100 then
		return true, "P_CONTROL_HARD_RESET_CLIENT_V3 (0x50)"
	end
	return false, nil
end

local function is_ovpn_server_reset(payload)
	local plen = #payload
	local b0 = string.byte(payload, 1)
	if (b0 == 0x40 or b0 == 0x58) and plen >= 14 then
		return true
	end
	return false
end

function ovpn_junk(ctx, desync)
	local dis = desync.dis
	if not dis or not dis.udp or not dis.payload then return VERDICT_PASS end

	local payload_len = #dis.payload

	-- =========================================================================
	-- 1. INBOUND PACKET HANDLING (Server Hard Reset Response -> Session Lock)
	-- =========================================================================
	if not desync.outgoing then
		if is_ovpn_server_reset(dis.payload) then
			local flow_key = ovpn_get_flow_key(dis, true)
			if flow_key and ovpn_flow_get_entry(flow_key) then
				ovpn_flow_set_established(flow_key)

				local time_str = os.date("%H:%M:%S")
				print("=========================================================================")
				print("  OPENVPN SERVER RESPONSE (Hard Reset 0x40/0x58) RECEIVED!")
				print("-------------------------------------------------------------------------")
				print(string.format("  Time          : %s", time_str))
				print(string.format("  Flow          : %s (%d B)", flow_key, payload_len))
				print("  Session State : LOCKED_ESTABLISHED (TLS Handshake Proceeding)")
				print("  Desync Engine : Disengaged for this flow. Zero-overhead passthrough.")
				if ai_brain_on_lock then ai_brain_on_lock("openvpn", flow_key, payload_len) end
				print("=========================================================================\n")
			end
		end
		return VERDICT_PASS
	end

	-- =========================================================================
	-- 2. OUTBOUND PACKET HANDLING (Client Hard Reset V2/V3)
	-- =========================================================================
	local is_reset, reset_label = is_ovpn_client_reset(dis.payload)
	if not is_reset then
		return VERDICT_PASS
	end

	local flow_key = ovpn_get_flow_key(dis, false)
	if not flow_key then return VERDICT_PASS end

	local entry = ovpn_flow_get_entry(flow_key)
	local now = clock_getfloattime()

	-- Case 1: Session already established
	if entry and entry.state == "ESTABLISHED" then
		return VERDICT_PASS
	end

	-- Case 2: Overlapping retry queued during or right after an active envelope (< 3.0s)
	if entry and entry.state == "TRIED" and (now - (entry.last_envelope or 0)) < 3.0 then
		if ai_brain_on_retry_drop then ai_brain_on_retry_drop("openvpn", flow_key, "cooldown_overlap") end
		print(string.format("  [RETRY OVERLAP DROPPED] Flow %s (dt=%.2fs < 3.0s) ---> DROPPED",
			flow_key, now - (entry.last_envelope or 0)))
		return VERDICT_DROP
	end

	-- Case 3: Fresh flow OR retry after cooldown (>= 3.0s) -> Run Cover Envelope
	local start_time = now
	ovpn_hs_counter = ovpn_hs_counter + 1
	local updated_entry = ovpn_flow_register_attempt(flow_key, ovpn_hs_counter)

	local raw_mode = tostring((desync.arg and desync.arg.mode) or "auto"):lower()
	local exclude_mask = (updated_entry.attempt > 1) and ovpn_last_profile or nil
	local selected_key, spec, is_auto, ai_label = nil, nil, false, nil
	if ai_brain_select_spec then
		selected_key, spec, is_auto, ai_label = ai_brain_select_spec("openvpn", raw_mode, ovpn_last_profile, exclude_mask, flow_key)
		if is_auto then ovpn_last_profile = selected_key end
	else
		selected_key = (NUM_TO_PROTO and NUM_TO_PROTO[raw_mode]) or raw_mode
		if selected_key == "auto" then
			is_auto = true
			local pool = (TIER1_PROTO_LIST and #TIER1_PROTO_LIST > 0) and TIER1_PROTO_LIST or PROTOCOL_LIST
			if pool and #pool > 0 then
				local pick = pool[math.random(1, #pool)]
				if #pool > 1 and pick == ovpn_last_profile then
					local candidate_pool = {}
					for _, v in ipairs(pool) do
						if v ~= ovpn_last_profile then table.insert(candidate_pool, v) end
					end
					pick = candidate_pool[math.random(1, #candidate_pool)]
				end
				selected_key = pick
				ovpn_last_profile = selected_key
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

	local env_opts = ai_brain_get_envelope_opts and ai_brain_get_envelope_opts("openvpn", nil, flow_key) or nil
	if ai_brain_on_attempt then
		ai_brain_on_attempt("openvpn", flow_key, selected_key, updated_entry.attempt, start_time, env_opts)
	end

	local time_str = os.date("%H:%M:%S")
	local tier_label = is_auto and (ai_label and (" [" .. ai_label .. "]") or " [Tier-1 Auto-Selected]") or ""

	print("=========================================================================")
	print(string.format("  OPENVPN HANDSHAKE #%d DETECTED (Attempt #%d)", ovpn_hs_counter, updated_entry.attempt))
	print("-------------------------------------------------------------------------")
	print(string.format("  Time          : %s", time_str))
	print(string.format("  Packet Type   : %s | %d B", reset_label, payload_len))
	print(string.format("  Flow (Wire)   : %s", flow_key))
	print(string.format("  Framing Mode  : Dual-Phase Cover Envelope (%s)%s", spec.name, tier_label))
	print("  Envelope Plan : LEAD-IN (I1 Signature + I2 Timestamp) ➔ HANDSHAKE ➔ DUAL TRAIL (80ms, 220ms)")
	print("  Port Strategy : Authentic Client Ephemeral Port (Zero-NAT)")
	print("-------------------------------------------------------------------------")

	local verdict = execute_envelope(ctx, desync, spec, start_time, env_opts)
	return verdict
end
