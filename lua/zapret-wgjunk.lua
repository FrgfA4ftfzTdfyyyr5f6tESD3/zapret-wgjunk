-- =============================================================================
-- zapret-wgjunk.lua - WireGuard DPI Desync & Dual-Phase Cover Envelope Orchestrator
-- =============================================================================
-- Features:
--   [+] Modular architecture:
--         - lua/wg_protocols.lua     (17 RFC Protocol Specs, Builders & Tier-1 Pool)
--         - lua/wg_envelope.lua      (Dual-Phase Cover Envelope Engine: LEAD-IN ➔ HANDSHAKE ➔ DUAL TRAIL)
--         - lua/wg_state.lua         (Dual-Stack Flow State Machine: Drop Duplicates on Dead Ports)
--         - lua/wg_reverse_rekey.lua (Beta Module: Reverse Rekey & Role Swap Engine)
--   [+] Authentic Ephemeral Port Preservation (Zero-NAT):
--         - Client's authentic ephemeral port is preserved 100% on the wire.
--         - WireGuard Type 4 data packets flow directly through kernel without NAT mismatch.
--   [+] Immediate Drop on Dead Port Retries:
--         - Attempt 1 on a fresh flow key executes the Dual-Phase Cover Envelope.
--         - Attempt 2+ on the SAME unestablished flow key is immediately DROPPED (VERDICT_DROP).
--           This prevents wasting 2.5s on a blocked port and forces the client to rotate
--           to a fresh ephemeral port right away.
--   [+] Session-Locked State Machine (LOCKED_ESTABLISHED):
--         - Once Type 2 (92 B) arrives, session locks: desync completely DISENGAGES for this flow.
--         - Subsequent re-keys (every 120s) and data packets pass directly without delay or junk.
--   [+] Dual-Stack Native: Full support for both IPv4 and IPv6 flows.
--   [+] Strict No-Repeat Tier-1 AUTO Rotation across 6 Golden Protocols.
--   [+] Pacing Window: Strictly 1.5s to 2.5s with 4..8 lead-in packets.
-- =============================================================================

-- Ensure submodules are loaded
if not WG_PROTO_SPECS or not TIER1_PROTO_LIST then
	if not pcall(dofile, "lua/wg_protocols.lua") then pcall(dofile, "wg_protocols.lua") end
end
if not execute_envelope then
	if not pcall(dofile, "lua/wg_envelope.lua") then pcall(dofile, "wg_envelope.lua") end
end
if not flow_get_state then
	if not pcall(dofile, "lua/wg_state.lua") then pcall(dofile, "wg_state.lua") end
end
if not reverse_rekey_handle_outbound_hs then
	if not pcall(dofile, "lua/wg_reverse_rekey.lua") then pcall(dofile, "wg_reverse_rekey.lua") end
end

local hs_counter = 0
local last_profile = nil

-- Main Desync Action Entry Point
function wg_junk(ctx, desync)
	local dis = desync.dis
	if not dis or not dis.udp then return VERDICT_PASS end

	-- Enable reverse rekey if specified via desync arguments
	if desync.arg and (desync.arg.reverse or desync.arg.rev) then
		local rval = desync.arg.reverse or desync.arg.rev
		if enable_reverse_rekey then
			enable_reverse_rekey(rval == "1" or rval == "true" or rval == "yes")
		end
	end

	local payload_len = #dis.payload

	-- =========================================================================
	-- 1. INBOUND PACKET HANDLING
	-- =========================================================================
	if not desync.outgoing then
		-- Inbound Type 2: WireGuard Handshake Response (92 bytes: 0x02 0x00 0x00 0x00)
		if payload_len == 92 and string.byte(dis.payload, 1) == 2 and string.byte(dis.payload, 2) == 0 then
			local flow_key = get_flow_key(dis, true)
			if flow_key then
				flow_set_established(flow_key)
			end

			local time_str = os.date("%H:%M:%S")
			print("=========================================================================")
			print("  WIREGUARD SERVER RESPONSE (Type 2 - 92 B) RECEIVED!")
			print("-------------------------------------------------------------------------")
			print(string.format("  Time          : %s", time_str))
			print(string.format("  Flow          : %s (Response received)", flow_key or "unknown"))
			print("  Session State : LOCKED_ESTABLISHED (Connection Successfully Secured)")
			print("  Zero-Latency  : Passed directly to kernel / Wintun (Noise_IK timer intact)")
			print("  Desync Engine : Disengaged for this flow. All subsequent packets pass directly.")
			if ai_brain_on_lock and flow_key then
				ai_brain_on_lock("wireguard", flow_key, payload_len)
			end
			print("=========================================================================\n")
		end

		-- Inbound Type 1: Server-Initiated Rekey (Reverse Rekey Beta: 148 bytes: 0x01 0x00 0x00 0x00)
		if payload_len == 148 and string.byte(dis.payload, 1) == 1 and string.byte(dis.payload, 2) == 0 then
			if reverse_rekey_handle_inbound_hs and is_reverse_rekey_enabled and is_reverse_rekey_enabled() then
				local flow_key = get_flow_key(dis, true)
				local entry = FLOW_TABLE and FLOW_TABLE[flow_key]
				reverse_rekey_handle_inbound_hs(flow_key, entry, clock_getfloattime())
			end
		end

		-- Inbound packets pass immediately with zero latency and zero modification
		return VERDICT_PASS
	end

	-- =========================================================================
	-- 2. OUTBOUND PACKET HANDLING
	-- =========================================================================

	-- Outbound Type 2: Client Response in Reverse Rekey (92 bytes: 0x02 0x00 0x00 0x00)
	if payload_len == 92 and string.byte(dis.payload, 1) == 2 and string.byte(dis.payload, 2) == 0 then
		if reverse_rekey_handle_outbound_resp and is_reverse_rekey_enabled and is_reverse_rekey_enabled() then
			local flow_key = get_flow_key(dis, false)
			local entry = FLOW_TABLE and FLOW_TABLE[flow_key]
			reverse_rekey_handle_outbound_resp(flow_key, entry, clock_getfloattime())
		end
		return VERDICT_PASS
	end

	-- Outbound Type 1: WireGuard Handshake Initiation (148 bytes: 0x01 0x00 0x00 0x00)
	if payload_len ~= 148 or string.byte(dis.payload, 1) ~= 1 or string.byte(dis.payload, 2) ~= 0 then
		return VERDICT_PASS
	end

	local flow_key = get_flow_key(dis, false)
	if not flow_key then return VERDICT_PASS end

	local state = flow_get_state(flow_key)

	-- Case 1: Session is already established (Re-keying)
	if state == "ESTABLISHED" then
		-- Check Beta Reverse Rekey handler if active
		if reverse_rekey_handle_outbound_hs and is_reverse_rekey_enabled and is_reverse_rekey_enabled() then
			local entry = FLOW_TABLE and FLOW_TABLE[flow_key]
			local verdict = reverse_rekey_handle_outbound_hs(flow_key, entry, clock_getfloattime())
			if verdict == VERDICT_DROP then
				return VERDICT_DROP
			end
		end

		print(string.format("  [SESSION LOCKED] Re-keying on active flow %s ---> Direct Passthrough", flow_key))
		return VERDICT_PASS
	end

	-- Case 2: Duplicate handshake on an unestablished, already-tried flow
	if state == "TRIED" then
		if ai_brain_on_retry_drop then ai_brain_on_retry_drop("wireguard", flow_key, "duplicate_dead_port") end
		print(string.format("  [DUPLICATE HANDSHAKE DROPPED] Retried on unestablished flow %s ---> DROPPED", flow_key))
		print("  Reason: Forcing client (Windscribe/WireGuard) to rotate to a fresh ephemeral port immediately.\n")
		return VERDICT_DROP
	end

	-- Case 3: Fresh flow key (Attempt 1 on new ephemeral port)
	local start_time = clock_getfloattime()
	hs_counter = hs_counter + 1
	flow_register_attempt(flow_key, hs_counter)

	-- Determine target mode via AI Brain (if loaded) or Tier-1 fallback
	local raw_mode = tostring(desync.arg.mode or "auto"):lower()
	local selected_key, spec, is_auto, ai_label = nil, nil, false, nil
	if ai_brain_select_spec then
		selected_key, spec, is_auto, ai_label = ai_brain_select_spec("wireguard", raw_mode, last_profile, nil, flow_key)
		if is_auto then last_profile = selected_key end
	else
		selected_key = (NUM_TO_PROTO and NUM_TO_PROTO[raw_mode]) or raw_mode
		if selected_key == "auto" then
			is_auto = true
			local pool = (TIER1_PROTO_LIST and #TIER1_PROTO_LIST > 0) and TIER1_PROTO_LIST or PROTOCOL_LIST
			if pool and #pool > 0 then
				local pick = pool[math.random(1, #pool)]
				if #pool > 1 and pick == last_profile then
					local candidate_pool = {}
					for _, v in ipairs(pool) do
						if v ~= last_profile then table.insert(candidate_pool, v) end
					end
					pick = candidate_pool[math.random(1, #candidate_pool)]
				end
				selected_key = pick
				last_profile = selected_key
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

	local env_opts = ai_brain_get_envelope_opts and ai_brain_get_envelope_opts("wireguard", nil, flow_key) or nil
	if ai_brain_on_attempt then
		ai_brain_on_attempt("wireguard", flow_key, selected_key, 1, start_time, env_opts)
	end

	local time_str = os.date("%H:%M:%S")
	local tier_label = is_auto and (ai_label and (" [" .. ai_label .. "]") or " [Tier-1 Auto-Selected]") or ""

	print("=========================================================================")
	print(string.format("  WIREGUARD HANDSHAKE #%d DETECTED (Fresh Ephemeral Port)", hs_counter))
	print("-------------------------------------------------------------------------")
	print(string.format("  Time          : %s", time_str))
	print(string.format("  Flow (Wire)   : %s", flow_key))
	print(string.format("  Framing Mode  : Dual-Phase Cover Envelope (%s)%s", spec.name, tier_label))
	print("  Envelope Plan : LEAD-IN (I1 Signature + I2 Timestamp) ➔ HANDSHAKE (148B Authentic) ➔ DUAL TRAIL (80ms, 220ms)")
	print("  Port Strategy : Authentic Client Ephemeral Port (Zero-NAT)")
	print("-------------------------------------------------------------------------")

	local verdict = execute_envelope(ctx, desync, spec, start_time, env_opts)
	return verdict
end
