-- =============================================================================
-- wg_envelope.lua - Dual-Phase Cover Envelope Execution Engine (IPv4 & IPv6)
-- =============================================================================
-- Wraps the authentic WireGuard handshake inside a continuous, realistic protocol flow
-- to trigger DPI hardware Fast-Path offload and shield the return path.
--
-- Architecture:
--   Phase 1 [LEAD-IN]:   Stateful CPS Chain across 1.5..2.5s (4..8 packets):
--                        * i == 1 (I1): Authentic Protocol Signature & handshake header.
--                        * i >  1 (I2): Stateful Dynamic Session with 32-bit Unix Timestamp
--                                       (os.time()) + Sequence Counter (seq).
--   Phase 2 [HANDSHAKE]: Authentic 148-byte WireGuard Initiation packet released directly.
--   Phase 3 [TRAIL]:     Dual post-handshake cover packets at t+60ms and t+180ms
--                        via non-blocking timers to shield the return window of the
--                        server's 92-byte response without stalling the packet loop.
-- =============================================================================

local function delay_ms(ms)
	if not ms or ms <= 0 then return end
	local target = clock_getfloattime() + (ms / 1000.0)
	while clock_getfloattime() < target do end
end

-- Callback for asynchronous non-blocking Trail packets
function on_trail_timer(name, data)
	local dummy_dis = deepcopy(data.dummy_dis)
	local spec = data.spec
	local cur_size = (data.jmin == data.jmax) and data.jmin or math.random(data.jmin, data.jmax)
	dummy_dis.payload = spec.build(cur_size, data.seq)
	dummy_dis.udp.uh_ulen = (UDP_BASE_LEN or 8) + #dummy_dis.payload
	if dummy_dis.ip then dummy_dis.ip.ip_id = math.random(1, 0xFFFF) end

	rawsend_dissect(dummy_dis)

	local cur_t = math.floor((clock_getfloattime() - data.start_time) * 1000)
	local desc = (data.trail_num == 1) and "RETURN PATH SHIELD" or "FLOW WARM ACTIVE"
	print(string.format("    [TRAIL %d/2]     -> Size: %4d B   [SENT at t+%dms] ---> [%s]", data.trail_num, #dummy_dis.payload, cur_t, desc))

	if data.trail_num == 2 then
		local total_elapsed = clock_getfloattime() - data.start_time
		print("-------------------------------------------------------------------------")
		print(string.format("  Envelope Cycle Completed at t+%.2fs | Status: SECURED", total_elapsed))
		print("=========================================================================\n")
	end
end

-- Executes the 3-phase Dual-Phase Cover Envelope sequence
function execute_envelope(ctx, desync, spec, start_time)
	local dis = desync.dis
	local udp_base_len = UDP_BASE_LEN or 8

	-- Resolve lead-in packet count (Balanced: 4 to 8 packets)
	local jc_min = tonumber(desync.arg.jc_min) or spec.c_min or 4
	local jc_max = tonumber(desync.arg.jc_max) or spec.c_max or 8
	if jc_min > jc_max then jc_min, jc_max = jc_max, jc_min end
	local jc = desync.arg.jc and tonumber(desync.arg.jc) or math.random(jc_min, jc_max)

	-- Resolve payload size range
	local jmin = tonumber(desync.arg.jmin) or spec.s_min
	local jmax = tonumber(desync.arg.jmax) or spec.s_max
	if jmin > jmax then jmin, jmax = jmax, jmin end

	-- Resolve lead-in pacing window (Strictly 1500 - 2500 ms, i.e. 1.5 to 2.5 seconds)
	local pace_min = tonumber(desync.arg.pace_min or desync.arg.hs_delay_min) or 1500
	local pace_max = tonumber(desync.arg.pace_max or desync.arg.hs_delay_max) or 2500
	if pace_min > pace_max then pace_min, pace_max = pace_max, pace_min end
	local total_window = (desync.arg.pace or desync.arg.hs_delay) and tonumber(desync.arg.pace or desync.arg.hs_delay) or math.random(pace_min, pace_max)

	-- Spacing interval between lead-in packets (typically 280 to 420 ms)
	local interval = (jc > 1) and math.floor(total_window / jc) or total_window

	-- Packet template preserving strict 5-tuple and dissect structure (IPv4 & IPv6)
	local dummy_dis = deepcopy(dis)
	dummy_dis.payload = ""

	-- -------------------------------------------------------------------------
	-- Phase 1: [LEAD-IN] (Stateful CPS Chain: I1 Signature + I2 Timestamp Streams)
	-- -------------------------------------------------------------------------
	for i = 1, jc do
		local cur_size = (jmin == jmax) and jmin or math.random(jmin, jmax)
		dummy_dis.payload = spec.build(cur_size, i)
		dummy_dis.udp.uh_ulen = udp_base_len + #dummy_dis.payload

		if dummy_dis.ip then
			dummy_dis.ip.ip_id = math.random(1, 0xFFFF)
		end

		rawsend_dissect(dummy_dis)

		local cur_t = math.floor((clock_getfloattime() - start_time) * 1000)
		local stage_label = (i == 1) and "I1: SIGNATURE" or "I2: TIMESTAMP"
		print(string.format("    [LEAD-IN %d/%d (%s)] -> Size: %4d B   [SENT at t+%dms]", i, jc, stage_label, #dummy_dis.payload, cur_t))

		-- Delay natural interval (~280..420 ms)
		delay_ms(interval)
	end

	-- -------------------------------------------------------------------------
	-- Phase 2: [HANDSHAKE] (Authentic 148-Byte WireGuard Initiation Released)
	-- -------------------------------------------------------------------------
	rawsend_dissect(dis)
	local hs_t = math.floor((clock_getfloattime() - start_time) * 1000)
	print(string.format("    [HANDSHAKE]     -> Size: %4d B   [SENT at t+%dms] ---> [PASSED]", #dis.payload, hs_t))

	-- -------------------------------------------------------------------------
	-- Phase 3: [TRAIL] (Dual Shield: Non-blocking timers at t+60ms and t+180ms)
	-- -------------------------------------------------------------------------
	local trail_sport = dis.udp.uh_sport
	local trail_data_1 = {
		dummy_dis = dummy_dis,
		spec = spec,
		seq = jc + 1,
		start_time = start_time,
		trail_num = 1,
		jmin = jmin,
		jmax = jmax
	}
	local trail_data_2 = {
		dummy_dis = dummy_dis,
		spec = spec,
		seq = jc + 2,
		start_time = start_time,
		trail_num = 2,
		jmin = jmin,
		jmax = jmax
	}

	timer_set(string.format("trail1_%d_%d", trail_sport, math.random(1000, 9999)), on_trail_timer, 60, true, trail_data_1)
	timer_set(string.format("trail2_%d_%d", trail_sport, math.random(1000, 9999)), on_trail_timer, 180, true, trail_data_2)

	-- Handshake dispatched via rawsend_dissect; drop original to prevent duplicate
	return VERDICT_DROP
end
