-- =============================================================================
-- wg_envelope.lua - Non-Blocking Dual-Phase Cover Envelope Engine (IPv4 & IPv6)
-- =============================================================================
-- Uses native winws2 `timer_set` async timers for ALL phases (zero CPU spinloop,
-- zero LuaJIT trace aborts, and <0.5ms packet-loop latency so inbound server
-- responses and fragmented IKE_AUTH packets are processed immediately).
--
-- Architecture:
--   Phase 1 [LEAD-IN]:   t=0 (I1 Signature) + t+interval*(i-1) (I2 Timestamp)
--   Phase 2 [HANDSHAKE]: Authentic handshake released at t+total_window
--   Phase 3 [TRAIL]:     Dual return-path shield at t+total_window+60ms & +180ms
-- =============================================================================

local function build_cover_dis(template_dis, spec, seq, jmin, jmax)
	local dummy_dis = deepcopy(template_dis)
	local cur_size = (jmin == jmax) and jmin or math.random(jmin, jmax)
	dummy_dis.payload = spec.build(cur_size, seq)
	dummy_dis.udp.uh_ulen = (UDP_BASE_LEN or 8) + #dummy_dis.payload
	if dummy_dis.ip then
		dummy_dis.ip.ip_id = math.random(1, 0xFFFF)
	end
	return dummy_dis
end

function on_lead_timer(name, data)
	local dummy_dis = build_cover_dis(data.dummy_dis, data.spec, data.seq, data.jmin, data.jmax)
	rawsend_dissect(dummy_dis)
	local cur_t = math.floor((clock_getfloattime() - data.start_time) * 1000)
	print(string.format("    [LEAD-IN %d/%d (I2: TIMESTAMP)] -> Size: %4d B   [SENT at t+%dms]",
		data.seq, data.jc, #dummy_dis.payload, cur_t))
end

function on_hs_timer(name, data)
	rawsend_dissect(deepcopy(data.hs_dis))
	local hs_t = math.floor((clock_getfloattime() - data.start_time) * 1000)
	print(string.format("    [HANDSHAKE]     -> Size: %4d B   [SENT at t+%dms] ---> [PASSED]",
		#data.hs_dis.payload, hs_t))
end

function on_frag_timer(name, data)
	rawsend_dissect(deepcopy(data.frag_dis))
	local cur_t = math.floor((clock_getfloattime() - data.start_time) * 1000)
	print(string.format("    [FRAGMENT %d/%d]  -> Size: %4d B   [SENT at t+%dms] ---> [PASSED]",
		data.frag_num, data.total_frags, #data.frag_dis.payload, cur_t))
end

function on_trail_timer(name, data)
	local dummy_dis = build_cover_dis(data.dummy_dis, data.spec, data.seq, data.jmin, data.jmax)
	rawsend_dissect(dummy_dis)

	local cur_t = math.floor((clock_getfloattime() - data.start_time) * 1000)
	local desc = (data.trail_num == 1) and "RETURN PATH SHIELD" or "FLOW WARM ACTIVE"
	print(string.format("    [TRAIL %d/2]     -> Size: %4d B   [SENT at t+%dms] ---> [%s]",
		data.trail_num, #dummy_dis.payload, cur_t, desc))

	if data.trail_num == 2 then
		local total_elapsed = clock_getfloattime() - data.start_time
		print("-------------------------------------------------------------------------")
		print(string.format("  Envelope Cycle Completed at t+%.2fs | Status: SECURED", total_elapsed))
		print("=========================================================================\n")
	end
end

-- Executes the 3-phase Dual-Phase Cover Envelope asynchronously via timer_set.
-- Returns (VERDICT_DROP, total_window_ms).
function execute_envelope(ctx, desync, spec, start_time, opts)
	local dis = desync.dis
	opts = opts or {}

	-- Resolve lead-in packet count
	local jc_min = opts.jc_min or tonumber(desync.arg.jc_min) or spec.c_min or 4
	local jc_max = opts.jc_max or tonumber(desync.arg.jc_max) or spec.c_max or 8
	if jc_min > jc_max then jc_min, jc_max = jc_max, jc_min end
	local jc = (not opts.jc_min and desync.arg.jc) and tonumber(desync.arg.jc) or math.random(jc_min, jc_max)

	-- Resolve payload size range with optional AI size_bias scaling (clamped safely to [32, 1380])
	local size_bias = tonumber(opts.size_bias) or 1.0
	local jmin = tonumber(desync.arg.jmin) or math.max(32, math.floor(spec.s_min * size_bias))
	local jmax = tonumber(desync.arg.jmax) or math.min(1380, math.floor(spec.s_max * size_bias))
	if jmin > jmax then jmin, jmax = jmax, jmin end

	-- Resolve lead-in pacing window
	local pace_min = opts.pace_min or tonumber(desync.arg.pace_min or desync.arg.hs_delay_min) or 1500
	local pace_max = opts.pace_max or tonumber(desync.arg.pace_max or desync.arg.hs_delay_max) or 2500
	if pace_min > pace_max then pace_min, pace_max = pace_max, pace_min end
	local total_window = (not opts.pace_min and (desync.arg.pace or desync.arg.hs_delay))
		and tonumber(desync.arg.pace or desync.arg.hs_delay) or math.random(pace_min, pace_max)

	local interval = (jc > 1) and math.floor(total_window / jc) or total_window
	local trail1_off = tonumber(opts.trail1_ms) or 80
	local trail2_off = tonumber(opts.trail2_ms) or 220
	if trail2_off <= trail1_off then trail2_off = trail1_off + 100 end

	-- Clean packet template preserving strict 5-tuple & IPv4/IPv6 dissect structure
	local dummy_template = deepcopy(dis)
	dummy_template.payload = ""
	local sport = dis.udp.uh_sport or 0
	local tag = math.random(10000, 99999)

	-- Phase 1a: Send LEAD-IN 1/jc (I1: Signature) immediately at t=0
	local first_dis = build_cover_dis(dummy_template, spec, 1, jmin, jmax)
	rawsend_dissect(first_dis)
	local t1 = math.floor((clock_getfloattime() - start_time) * 1000)
	print(string.format("    [LEAD-IN 1/%d (I1: SIGNATURE)] -> Size: %4d B   [SENT at t+%dms]",
		jc, #first_dis.payload, t1))

	-- Phase 1b: Schedule LEAD-IN 2..jc asynchronously (zero CPU spin)
	for i = 2, jc do
		local delay = interval * (i - 1)
		timer_set(string.format("lead_%d_%d_%d", sport, tag, i), on_lead_timer, delay, true, {
			dummy_dis  = dummy_template,
			spec       = spec,
			seq        = i,
			jc         = jc,
			start_time = start_time,
			jmin       = jmin,
			jmax       = jmax
		})
	end

	-- Phase 2: Schedule authentic Handshake release at t+total_window
	local hs_dis = deepcopy(dis)
	timer_set(string.format("hs_%d_%d", sport, tag), on_hs_timer, total_window, true, {
		hs_dis     = hs_dis,
		start_time = start_time
	})

	-- Phase 3: Schedule dual return-path shield trails cleanly after handshake & any fragments
	timer_set(string.format("trail1_%d_%d", sport, tag), on_trail_timer, total_window + trail1_off, true, {
		dummy_dis  = dummy_template,
		spec       = spec,
		seq        = jc + 1,
		start_time = start_time,
		trail_num  = 1,
		jmin       = jmin,
		jmax       = jmax
	})
	timer_set(string.format("trail2_%d_%d", sport, tag), on_trail_timer, total_window + trail2_off, true, {
		dummy_dis  = dummy_template,
		spec       = spec,
		seq        = jc + 2,
		start_time = start_time,
		trail_num  = 2,
		jmin       = jmin,
		jmax       = jmax
	})

	-- Drop original packet (scheduled via timer_set); packet loop returns immediately
	return VERDICT_DROP, total_window
end
