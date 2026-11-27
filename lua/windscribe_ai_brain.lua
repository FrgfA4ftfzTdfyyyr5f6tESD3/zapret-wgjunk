-- =============================================================================
-- windscribe_ai_brain.lua - Deep Expert Dual-Perspective AI Engine (v4.1)
-- =============================================================================
-- Architecture:
--   1. Internal Code & Execution Brain:
--      - Safe LuaJIT `jit.attach` trace profiler + memory monitor (`collectgarbage`)
--      - `jit.off` on cold JSON/disk serializers to prevent hot-path trace aborts
--      - Leak-free State Transition Matrix + Autonomous Upgrade Blueprint
--   2. External Network & Adaptive Evasion Brain:
--      - Welford Online Baseline (mean, variance, stddev of Lock RTT)
--      - Joint Discounted UCB1 (gamma=0.90) + Circadian Buckets + 15% Hysteresis
--        across BOTH Protocol Masks (17 RFC specs) AND Evasion Tactics:
--        (`balanced`, `blitz_fast`, `heavy_shield`, `micro_stealth`)
--      - Per-Port & Subnet (/24) Affinity Memory
--      - 200-Event Circular Ring Buffer + Root Cause Analysis (AI RCA)
--   3. Self-Mutating Contract-Verified Policy (`evolved_policy.lua`):
--      - Online Coordinate-Descent parameter mutation (`jc_min/max`, `pace_min/max`,
--        `size_bias`, `trail1_ms/trail2_ms`) verified by Digital Twin Contract
--      - Instant <1ms Auto-Rollback on regression
-- =============================================================================

local GAMMA           = 0.90   -- Discount factor for non-stationary DPI networks
local UCB_C           = 0.85   -- Exploration constant
local HYSTERESIS_MULT = 1.15   -- 15% Hysteresis to prevent jittery switching
local MAX_RING_SIZE   = 200    -- Fixed-size circular event ring buffer
local WRITABLE_DIR    = os.getenv("WRITABLE")
local BASE_DIR        = (WRITABLE_DIR and #WRITABLE_DIR > 0) and WRITABLE_DIR or "."
local POLICY_PATH     = BASE_DIR .. "/evolved_policy.lua"
local SEED_POLICY     = "lua/evolved_policy.lua"
local REPORT_PATH     = BASE_DIR .. "/windscribe_ai_report.json"
local SESSION_LOG     = BASE_DIR .. "/windscribe_session.log"

-- Escalation pool appended when consecutive failures >= 2
local ESCALATION_POOL = { "discord", "zoom", "turn", "riot", "sdr" }

-- Evading Tactics (Jointly optimized alongside Protocol Masks)
local TACTICS = {
	balanced = {
		name = "balanced", jc_delta = 0, pace_scale = 1.00, size_bias = 1.00, trail1_ms = 80, trail2_ms = 220
	},
	blitz_fast = {
		name = "blitz_fast", jc_delta = -2, pace_scale = 0.65, size_bias = 0.85, trail1_ms = 60, trail2_ms = 160
	},
	heavy_shield = {
		name = "heavy_shield", jc_delta = 2, pace_scale = 1.15, size_bias = 1.15, trail1_ms = 90, trail2_ms = 260
	},
	micro_stealth = {
		name = "micro_stealth", jc_delta = 1, pace_scale = 0.85, size_bias = 0.60, trail1_ms = 70, trail2_ms = 190
	}
}
local TACTIC_LIST = { "balanced", "blitz_fast", "heavy_shield", "micro_stealth" }

AI_BRAIN = AI_BRAIN or {
	started_at = os.time(),
	last_persist_at = 0,
	internal = {
		jit_attached    = false,
		traces_compiled = 0,
		traces_aborted  = 0,
		last_abort      = nil,
		hotpath_us_sum  = 0,
		hotpath_samples = 0,
		transitions     = {},
		last_phase      = {}
	},
	external = {
		welford_rtt     = {},
		welford_mask    = {},
		buckets         = {}, -- [bucket][proto][mask]
		tactic_buckets  = {}, -- [bucket][proto][tactic]
		affinity        = {}, -- [proto..":"..port_or_net][mask] = { n, wins }
		incumbent       = {}, -- [bucket..":"..proto] = mask
		consec_failures = {},
		active_flows    = {},
		last_pending    = {},
		ring_buffer     = {},
		ring_head       = 0,
		ring_count      = 0
	},
	policy = nil,
	stable_policy = nil,
	evolution_eval = {}
}

-- =============================================================================
-- Utility Helpers & Cold-Path JSON Serializer
-- =============================================================================
local function now_sec()
	if clock_getfloattime then return clock_getfloattime() end
	return os.clock()
end

local function deepcopy_tbl(t)
	if type(t) ~= "table" then return t end
	local out = {}
	for k, v in pairs(t) do
		out[k] = deepcopy_tbl(v)
	end
	return out
end

local function extract_endpoint_keys(flow_key)
	if not flow_key then return nil, nil end
	local dst = flow_key:match("->(.+)$")
	if not dst then return nil, nil end
	local ip, port = dst:match("^(.+):(%d+)$")
	if not ip then return nil, nil end
	local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.%d+$")
	local subnet = a and string.format("%s.%s.%s.0/24", a, b, c) or ip
	return port, subnet
end

local function json_escape(s)
	s = tostring(s or "")
	s = s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
	return '"' .. s .. '"'
end

local function is_array(t)
	if type(t) ~= "table" then return false end
	local n = #t
	local count = 0
	for _ in pairs(t) do count = count + 1 end
	return n > 0 and count == n
end

local function to_json(val, indent)
	indent = indent or 0
	local pad = string.rep("  ", indent)
	local pad_in = string.rep("  ", indent + 1)
	local tv = type(val)
	if tv == "nil" then return "null"
	elseif tv == "boolean" then return val and "true" or "false"
	elseif tv == "number" then
		if val ~= val or val == math.huge or val == -math.huge then return "0" end
		if math.floor(val) == val then return string.format("%d", val) end
		return string.format("%.4f", val)
	elseif tv == "string" then return json_escape(val)
	elseif tv == "table" then
		if is_array(val) then
			local items = {}
			for i = 1, #val do items[i] = pad_in .. to_json(val[i], indent + 1) end
			return "[\n" .. table.concat(items, ",\n") .. "\n" .. pad .. "]"
		else
			local keys = {}
			for k in pairs(val) do table.insert(keys, tostring(k)) end
			table.sort(keys)
			if #keys == 0 then return "{}" end
			local items = {}
			for _, k in ipairs(keys) do
				local raw_k = val[k] ~= nil and k or tonumber(k)
				table.insert(items, pad_in .. json_escape(k) .. ": " .. to_json(val[raw_k], indent + 1))
			end
			return "{\n" .. table.concat(items, ",\n") .. "\n" .. pad .. "}"
		end
	end
	return json_escape(tostring(val))
end

local function append_session_log(line)
	local f = io.open(SESSION_LOG, "a")
	if not f then return end
	f:write(string.format("[%s] %s\n", os.date("%Y-%m-%d %H:%M:%S"), line))
	f:close()
end

-- =============================================================================
-- 1. Internal Code Brain: JIT Trace Profiler & State Transition Matrix
-- =============================================================================
local function init_jit_profiler()
	if AI_BRAIN.internal.jit_attached then return end
	if jit and type(jit.attach) == "function" then
		local ok = pcall(jit.attach, function(what, tr, func, pc, otr, oex)
			if what == "stop" then
				AI_BRAIN.internal.traces_compiled = AI_BRAIN.internal.traces_compiled + 1
			elseif what == "abort" then
				AI_BRAIN.internal.traces_aborted = AI_BRAIN.internal.traces_aborted + 1
				AI_BRAIN.internal.last_abort = tostring(otr or "unknown")
			end
		end, "trace")
		AI_BRAIN.internal.jit_attached = ok
	end
end

function ai_brain_record_transition(proto, flow_key, to_phase, keep_phase)
	local internal = AI_BRAIN.internal
	local from_phase = (flow_key and internal.last_phase[flow_key]) or "INIT"
	if flow_key and not keep_phase then
		if to_phase == "LOCKED" then
			internal.last_phase[flow_key] = nil
		else
			internal.last_phase[flow_key] = to_phase
		end
	end

	internal.transitions[proto] = internal.transitions[proto] or {}
	local edge = from_phase .. "->" .. to_phase
	internal.transitions[proto][edge] = (internal.transitions[proto][edge] or 0) + 1
end

local function record_hotpath_us(dt_sec)
	if not dt_sec or dt_sec < 0 then return end
	AI_BRAIN.internal.hotpath_us_sum = AI_BRAIN.internal.hotpath_us_sum + (dt_sec * 1000000)
	AI_BRAIN.internal.hotpath_samples = AI_BRAIN.internal.hotpath_samples + 1
end

-- =============================================================================
-- 2. External Brain: Ring Buffer, Welford Baseline & Circadian Buckets
-- =============================================================================
local function push_ring(proto, flow_key, event_name, mask_key, rtt_ms, detail)
	local ext = AI_BRAIN.external
	ext.ring_head = (ext.ring_head % MAX_RING_SIZE) + 1
	ext.ring_count = math.min(MAX_RING_SIZE, ext.ring_count + 1)
	ext.ring_buffer[ext.ring_head] = {
		ts     = os.time(),
		proto  = proto or "unknown",
		flow   = flow_key or "-",
		event  = event_name,
		mask   = mask_key or "-",
		rtt_ms = rtt_ms and math.floor(rtt_ms) or nil,
		detail = detail
	}
end

local function get_recent_ring(limit)
	local ext = AI_BRAIN.external
	local out = {}
	local n = math.min(limit or ext.ring_count, ext.ring_count)
	for i = 0, n - 1 do
		local idx = ((ext.ring_head - 1 - i) % MAX_RING_SIZE) + 1
		if ext.ring_buffer[idx] then
			table.insert(out, ext.ring_buffer[idx])
		end
	end
	return out
end

function ai_brain_welford_update(tbl, key, x)
	local s = tbl[key]
	if not s then
		s = { n = 0, mean = 0.0, m2 = 0.0 }
		tbl[key] = s
	end
	s.n = s.n + 1
	local delta = x - s.mean
	s.mean = s.mean + (delta / s.n)
	local delta2 = x - s.mean
	s.m2 = s.m2 + (delta * delta2)
	return s
end

function ai_brain_welford_summary(s)
	if not s or s.n == 0 then
		return { n = 0, mean = 0, variance = 0, stddev = 0 }
	end
	local var = (s.n > 1) and (s.m2 / (s.n - 1)) or 0.0
	if var < 0 then var = 0.0 end
	return {
		n = s.n,
		mean = s.mean,
		variance = var,
		stddev = math.sqrt(var)
	}
end

function ai_brain_get_circadian_bucket(hour_override)
	local hr = hour_override or (os.date("*t") and os.date("*t").hour) or 12
	if hr < 6 then return "night_00_06"
	elseif hr < 12 then return "morning_06_12"
	elseif hr < 18 then return "afternoon_12_18"
	else return "evening_18_24" end
end

-- =============================================================================
-- 3. Contract-Verified Self-Mutating Policy & <1ms Auto-Rollback
-- =============================================================================
local DEFAULT_POLICIES = {
	ikev2_500  = { jc_min = 2, jc_max = 3, pace_min = 600,  pace_max = 950,  size_bias = 1.0, trail1_ms = 60, trail2_ms = 180, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 },
	ikev2_4500 = { jc_min = 4, jc_max = 6, pace_min = 1300, pace_max = 1850, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 },
	wireguard  = { jc_min = 4, jc_max = 8, pace_min = 1500, pace_max = 2500, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 },
	openvpn    = { jc_min = 4, jc_max = 8, pace_min = 1500, pace_max = 2500, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 }
}

local function clamp_num(v, lo, hi)
	if v < lo then return lo end
	if v > hi then return hi end
	return v
end

function ai_brain_validate_policy_contract(pol_map)
	if type(pol_map) ~= "table" then return false, "policy_not_table" end
	for proto, p in pairs(pol_map) do
		if type(p) ~= "table" then return false, proto .. "_not_table" end
		if type(p.jc_min) ~= "number" or type(p.jc_max) ~= "number" then return false, proto .. "_invalid_jc_type" end
		if p.jc_min < 1 or p.jc_max > 8 or p.jc_min > p.jc_max then return false, proto .. "_jc_out_of_bounds" end
		if type(p.pace_min) ~= "number" or type(p.pace_max) ~= "number" then return false, proto .. "_invalid_pace_type" end
		if p.pace_min < 400 or p.pace_max > 2500 or p.pace_min > p.pace_max then return false, proto .. "_pace_out_of_bounds" end
		if proto == "ikev2_500" and p.pace_max > 1050 then return false, "ikev2_500_exceeds_timeout_contract" end
		if proto == "ikev2_4500" and p.pace_max > 1950 then return false, "ikev2_4500_exceeds_timeout_contract" end

		local sb = p.size_bias or 1.0
		if type(sb) ~= "number" or sb < 0.50 or sb > 1.30 then return false, proto .. "_size_bias_out_of_bounds" end

		local t1, t2 = p.trail1_ms or 80, p.trail2_ms or 220
		if t1 < 40 or t2 > 500 or t1 >= t2 then return false, proto .. "_trail_out_of_bounds" end

		if p.preferred_mask and WG_PROTO_SPECS and not WG_PROTO_SPECS[p.preferred_mask] then
			return false, proto .. "_unknown_mask"
		end
	end
	return true, "ok"
end

local function serialize_lua_value(v, indent)
	indent = indent or 0
	local pad = string.rep("\t", indent)
	local pad_in = string.rep("\t", indent + 1)
	local tv = type(v)
	if tv == "nil" then return "nil"
	elseif tv == "boolean" then return v and "true" or "false"
	elseif tv == "number" then
		if math.floor(v) == v then return tostring(v) end
		return string.format("%.6f", v)
	elseif tv == "string" then return string.format("%q", v)
	elseif tv == "table" then
		local keys = {}
		for k in pairs(v) do table.insert(keys, k) end
		table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
		if #keys == 0 then return "{}" end
		local parts = {}
		for _, k in ipairs(keys) do
			local kstr = (type(k) == "string" and k:match("^[A-Za-z_][A-Za-z0-9_]*$")) and k or ("[" .. string.format("%q", tostring(k)) .. "]")
			table.insert(parts, pad_in .. kstr .. " = " .. serialize_lua_value(v[k], indent + 1))
		end
		return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
	end
	return "nil"
end

function ai_brain_save_policy(path_override)
	local target = path_override or POLICY_PATH
	local ok_c, reason = ai_brain_validate_policy_contract(AI_BRAIN.policy)
	if not ok_c then
		append_session_log("CONTRACT_REJECTED: " .. tostring(reason))
		return false, reason
	end

	local payload = {
		version = 2,
		updated_at = os.time(),
		policies = AI_BRAIN.policy,
		buckets = AI_BRAIN.external.buckets,
		tactic_buckets = AI_BRAIN.external.tactic_buckets,
		affinity = AI_BRAIN.external.affinity,
		incumbents = AI_BRAIN.external.incumbent
	}
	local f = io.open(target, "w")
	if not f then return false, "io_open_failed" end
	f:write("-- Auto-generated by windscribe_ai_brain.lua v4.1 (Contract-Verified)\nreturn ")
	f:write(serialize_lua_value(payload, 0))
	f:write("\n")
	f:close()
	return true, "ok"
end

function ai_brain_load_policy(path_override)
	local candidates = path_override and { path_override } or { POLICY_PATH, SEED_POLICY }
	for _, target in ipairs(candidates) do
		local ok_chunk, chunk = pcall(loadfile, target)
		if ok_chunk and type(chunk) == "function" then
			local ok_run, data = pcall(chunk)
			if ok_run and type(data) == "table" and type(data.policies) == "table" then
				local valid = ai_brain_validate_policy_contract(data.policies)
				if valid then
					AI_BRAIN.policy = deepcopy_tbl(data.policies)
					for k, def in pairs(DEFAULT_POLICIES) do
						if not AI_BRAIN.policy[k] then
							AI_BRAIN.policy[k] = deepcopy_tbl(def)
						else
							for dk, dv in pairs(def) do
								if AI_BRAIN.policy[k][dk] == nil and dk ~= "preferred_mask" then
									AI_BRAIN.policy[k][dk] = dv
								end
							end
						end
					end
					AI_BRAIN.stable_policy = deepcopy_tbl(AI_BRAIN.policy)
					if type(data.buckets) == "table" then AI_BRAIN.external.buckets = deepcopy_tbl(data.buckets) end
					if type(data.tactic_buckets) == "table" then AI_BRAIN.external.tactic_buckets = deepcopy_tbl(data.tactic_buckets) end
					if type(data.affinity) == "table" then AI_BRAIN.external.affinity = deepcopy_tbl(data.affinity) end
					if type(data.incumbents) == "table" then AI_BRAIN.external.incumbent = deepcopy_tbl(data.incumbents) end
					return true
				end
			end
		end
	end
	AI_BRAIN.policy = deepcopy_tbl(DEFAULT_POLICIES)
	AI_BRAIN.stable_policy = deepcopy_tbl(DEFAULT_POLICIES)
	return false
end

-- Helper to apply a tactic's envelope parameters while strictly obeying contract bounds
local function build_tactic_candidate(proto, base_pol, tactic_name)
	local def = DEFAULT_POLICIES[proto] or DEFAULT_POLICIES.wireguard
	local tac = TACTICS[tactic_name] or TACTICS.balanced
	local c = deepcopy_tbl(base_pol)

	local max_pace = (proto == "ikev2_500") and 1000 or ((proto == "ikev2_4500") and 1900 or 2500)
	local min_pace = (proto == "ikev2_500") and 450 or 700

	c.tactic    = tac.name
	c.jc_min    = clamp_num(def.jc_min + tac.jc_delta, 1, 7)
	c.jc_max    = clamp_num(math.max(c.jc_min, def.jc_max + tac.jc_delta), c.jc_min, 8)
	c.pace_min  = clamp_num(math.floor(def.pace_min * tac.pace_scale), min_pace, max_pace - 150)
	c.pace_max  = clamp_num(math.floor(def.pace_max * tac.pace_scale), c.pace_min + 120, max_pace)
	c.size_bias = tac.size_bias
	c.trail1_ms = (proto == "ikev2_500") and clamp_num(tac.trail1_ms, 50, 90) or tac.trail1_ms
	c.trail2_ms = math.max(c.trail1_ms + 80, (proto == "ikev2_500") and clamp_num(tac.trail2_ms, 140, 220) or tac.trail2_ms)
	return c
end

local function maybe_evolve_or_rollback(proto, mask_key, won, rtt_ms, used_tactic)
	local pol = AI_BRAIN.policy[proto]
	if not pol then return end
	local ev = AI_BRAIN.evolution_eval[proto]
	if not ev then
		ev = { active = false, attempts = 0, wins = 0, rollback_count = 0 }
		AI_BRAIN.evolution_eval[proto] = ev
	end

	if won then
		pol.wins = (pol.wins or 0) + 1
		if rtt_ms and rtt_ms < 2200 then
			pol.preferred_mask = mask_key
		end
	else
		pol.losses = (pol.losses or 0) + 1
	end

	-- 1. Check active evolved policy for <1ms Auto-Rollback on regression
	if ev.active then
		ev.attempts = ev.attempts + 1
		if won then ev.wins = ev.wins + 1 end
		if ev.attempts >= 3 then
			local rate = ev.wins / ev.attempts
			if rate < 0.34 and AI_BRAIN.stable_policy and AI_BRAIN.stable_policy[proto] then
				AI_BRAIN.policy[proto] = deepcopy_tbl(AI_BRAIN.stable_policy[proto])
				ev.active = false
				ev.attempts = 0
				ev.wins = 0
				ev.rollback_count = ev.rollback_count + 1
				push_ring(proto, nil, "AUTO_ROLLBACK", mask_key, rtt_ms, "reverted_to_stable_policy")
				print(string.format("  [AI AUTO-ROLLBACK] %s reverted in <1ms (win_rate=%.0f%%)", proto, rate * 100))
				append_session_log(string.format("AUTO_ROLLBACK proto=%s rate=%.2f", proto, rate))
				return
			elseif rate >= 0.60 then
				AI_BRAIN.stable_policy[proto] = deepcopy_tbl(pol)
				ev.active = false
				ev.attempts = 0
				ev.wins = 0
			end
		end
		return
	end

	-- 2. Coordinate-Descent Parameter Mutation + Tactic Adoption
	local candidate = deepcopy_tbl(pol)
	local mutated = false
	local consec = AI_BRAIN.external.consec_failures[proto] or 0

	if consec >= 2 then
		-- Escalate packet count / size envelope / pacing dynamically
		local next_tactic = (consec % 2 == 0) and "heavy_shield" or "micro_stealth"
		candidate = build_tactic_candidate(proto, pol, next_tactic)
		mutated = true
	elseif won and rtt_ms then
		if used_tactic and used_tactic ~= pol.tactic then
			candidate = build_tactic_candidate(proto, pol, used_tactic)
			mutated = true
		elseif rtt_ms < 1400 and (pol.wins % 2 == 0) then
			-- Speed optimization: tighten pacing & shave 1 max packet if fast lock
			if candidate.pace_max > (candidate.pace_min + 140) then
				candidate.pace_max = candidate.pace_max - 60
				mutated = true
			end
			if rtt_ms < 950 and candidate.jc_max > candidate.jc_min + 1 then
				candidate.jc_max = candidate.jc_max - 1
				mutated = true
			end
		end
	end

	if mutated then
		local ok_c = ai_brain_validate_policy_contract({ [proto] = candidate })
		if ok_c then
			AI_BRAIN.stable_policy[proto] = deepcopy_tbl(pol)
			AI_BRAIN.policy[proto] = candidate
			ev.active = true
			ev.attempts = 0
			ev.wins = 0
			push_ring(proto, nil, "POLICY_EVOLVED", mask_key, rtt_ms,
				string.format("tac=%s,jc=%d..%d,pace=%d..%d,scale=%.2f",
					tostring(candidate.tactic), candidate.jc_min, candidate.jc_max,
					candidate.pace_min, candidate.pace_max, candidate.size_bias or 1.0))
			print(string.format("  [AI EVOLUTION] %s mutated -> tactic=%s jc=%d..%d pace=%d..%dms scale=%.2fx (Contract OK)",
				proto, tostring(candidate.tactic), candidate.jc_min, candidate.jc_max,
				candidate.pace_min, candidate.pace_max, candidate.size_bias or 1.0))
		end
	end
end

-- =============================================================================
-- 4. Joint Discounted UCB1 (gamma=0.90) + Affinity + Tactics
-- =============================================================================
local function update_discounted_table(root_tbl, bucket, proto, arm_key, reward)
	root_tbl[bucket] = root_tbl[bucket] or {}
	root_tbl[bucket][proto] = root_tbl[bucket][proto] or {}
	local arms = root_tbl[bucket][proto]

	for _, arm in pairs(arms) do
		arm.n = (arm.n or 0) * GAMMA
		arm.reward_sum = (arm.reward_sum or 0) * GAMMA
	end

	local arm = arms[arm_key]
	if not arm then
		arm = { n = 0, reward_sum = 0, wins = 0, losses = 0 }
		arms[arm_key] = arm
	end
	arm.n = arm.n + 1.0
	arm.reward_sum = arm.reward_sum + reward
	if reward >= 0.35 then
		arm.wins = (arm.wins or 0) + 1
	else
		arm.losses = (arm.losses or 0) + 1
	end
end

local function update_affinity(proto, flow_key, mask_key, won)
	local port, subnet = extract_endpoint_keys(flow_key)
	local aff = AI_BRAIN.external.affinity
	for _, ep in ipairs({ port, subnet }) do
		if ep then
			local ak = proto .. ":" .. ep
			aff[ak] = aff[ak] or {}
			local m = aff[ak][mask_key]
			if not m then
				m = { n = 0, wins = 0 }
				aff[ak][mask_key] = m
			end
			m.n = m.n * GAMMA + 1.0
			m.wins = m.wins * GAMMA + (won and 1.0 or 0.0)
		end
	end
end

local function get_affinity_bonus(proto, flow_key, mask_key)
	local port, subnet = extract_endpoint_keys(flow_key)
	local aff = AI_BRAIN.external.affinity
	local bonus = 0.0
	for _, ep in ipairs({ port, subnet }) do
		if ep and aff[proto .. ":" .. ep] and aff[proto .. ":" .. ep][mask_key] then
			local m = aff[proto .. ":" .. ep][mask_key]
			if m.n >= 0.5 then
				bonus = bonus + 0.15 * (m.wins / m.n)
			end
		end
	end
	return bonus
end

function ai_brain_update_bandit(proto, mask_key, reward, bucket_override, tactic_name, flow_key)
	local bucket = bucket_override or ai_brain_get_circadian_bucket()
	update_discounted_table(AI_BRAIN.external.buckets, bucket, proto, mask_key, reward)
	if tactic_name and TACTICS[tactic_name] then
		update_discounted_table(AI_BRAIN.external.tactic_buckets, bucket, proto, tactic_name, reward)
	end
	if flow_key and mask_key and mask_key ~= "unknown" then
		update_affinity(proto, flow_key, mask_key, reward >= 0.35)
	end
end

function ai_brain_select_tactic(proto, bucket_override)
	local bucket = bucket_override or ai_brain_get_circadian_bucket()
	local consec = AI_BRAIN.external.consec_failures[proto] or 0
	if consec >= 2 then
		return (consec % 2 == 0) and "heavy_shield" or "micro_stealth"
	end

	local arms = (AI_BRAIN.external.tactic_buckets[bucket] and AI_BRAIN.external.tactic_buckets[bucket][proto]) or {}
	local total_n, untried = 0.0, {}
	for _, t in ipairs(TACTIC_LIST) do
		local a = arms[t]
		if a and (a.n or 0) >= 0.5 then total_n = total_n + a.n
		else table.insert(untried, t) end
	end
	if #untried > 0 then
		-- Try balanced first, then blitz_fast, etc.
		return untried[1]
	end
	local best_t, best_score = "balanced", -1
	local log_tot = math.log(math.max(1.0, total_n))
	for _, t in ipairs(TACTIC_LIST) do
		local a = arms[t]
		local ucb = (a.reward_sum / math.max(0.1, a.n)) + 0.65 * math.sqrt(log_tot / math.max(0.1, a.n))
		if ucb > best_score then best_score = ucb; best_t = t end
	end
	return best_t
end

function ai_brain_select_mask(proto, base_pool, last_profile, exclude_mask, bucket_override, flow_key)
	local t_start = now_sec()
	local bucket = bucket_override or ai_brain_get_circadian_bucket()
	local consec = AI_BRAIN.external.consec_failures[proto] or 0

	local pool, seen = {}, {}
	for _, m in ipairs(base_pool or {}) do
		if not seen[m] then table.insert(pool, m); seen[m] = true end
	end
	if consec >= 2 then
		for _, m in ipairs(ESCALATION_POOL) do
			if WG_PROTO_SPECS and WG_PROTO_SPECS[m] and not seen[m] then
				table.insert(pool, m); seen[m] = true
			end
		end
	end
	if #pool == 0 then pool = { "quic_v1" } end

	local arms = (AI_BRAIN.external.buckets[bucket] and AI_BRAIN.external.buckets[bucket][proto]) or {}
	local total_n, untried = 0.0, {}
	for _, m in ipairs(pool) do
		local a = arms[m]
		if a and (a.n or 0) >= 0.5 then
			total_n = total_n + a.n
		elseif m ~= exclude_mask then
			table.insert(untried, m)
		end
	end

	local chosen, strategy
	if #untried > 0 then
		-- Pick best affinity among untried if available, otherwise explore non-repeating
		local best_u, best_aff = nil, -1
		local filtered = {}
		for _, m in ipairs(untried) do
			if m ~= last_profile then
				table.insert(filtered, m)
				local ab = flow_key and get_affinity_bonus(proto, flow_key, m) or 0
				if ab > best_aff then best_aff = ab; best_u = m end
			end
		end
		if best_aff > 0 and best_u then
			chosen = best_u
			strategy = "UCB1-Affinity-Explore"
		else
			local pick_from = (#filtered > 0) and filtered or untried
			chosen = pick_from[math.random(1, #pick_from)]
			strategy = (consec >= 2) and "UCB1-Escalated-Explore" or "UCB1-Explore"
		end
	else
		local scores = {}
		local best_mask, best_score = nil, -1
		local log_tot = math.log(math.max(1.0, total_n))
		for _, m in ipairs(pool) do
			if m ~= exclude_mask or #pool == 1 then
				local a = arms[m]
				local mean_r = a.reward_sum / math.max(0.1, a.n)
				local aff_b = flow_key and get_affinity_bonus(proto, flow_key, m) or 0
				local ucb = mean_r + UCB_C * math.sqrt(log_tot / math.max(0.1, a.n)) + aff_b
				scores[m] = ucb
				if ucb > best_score then
					best_score = ucb
					best_mask = m
				end
			end
		end

		local inc_key = bucket .. ":" .. proto
		local inc = AI_BRAIN.external.incumbent[inc_key]
		if inc and inc ~= exclude_mask and scores[inc] then
			if best_mask ~= inc and best_score <= (scores[inc] * HYSTERESIS_MULT) then
				chosen = inc
				strategy = string.format("UCB1-Hysteresis15%% (score=%.2f)", scores[inc])
			else
				chosen = best_mask
				AI_BRAIN.external.incumbent[inc_key] = chosen
				strategy = string.format("UCB1-Promoted (score=%.2f)", best_score)
			end
		else
			chosen = best_mask or pool[1]
			AI_BRAIN.external.incumbent[inc_key] = chosen
			strategy = string.format("UCB1-Exploit (score=%.2f)", best_score or 0)
		end
	end

	record_hotpath_us(now_sec() - t_start)
	return chosen, strategy, bucket
end

-- =============================================================================
-- 5. RCA & Unified Telemetry Report
-- =============================================================================
function ai_brain_generate_rca(proto)
	local recent = get_recent_ring(30)
	local drops, attempts, locks = 0, 0, 0
	for _, ev in ipairs(recent) do
		if ev.proto == proto then
			if ev.event == "RETRY_DROP" then drops = drops + 1
			elseif ev.event == "ATTEMPT" then attempts = attempts + 1
			elseif ev.event == "LOCKED" then locks = locks + 1 end
		end
	end
	if locks > 0 and drops <= 1 then return "HEALTHY_FAST_LOCK"
	elseif drops >= 3 and locks == 0 then return "OVERLAP_RETRY_CONGESTION"
	elseif attempts >= 2 and locks == 0 then return "SILENT_DPI_DROP_ESCALATING"
	elseif locks > 0 then return "LOCKED_WITH_RETRIES"
	else return "PROBING" end
end

local function build_blueprint()
	local notes = {}
	if AI_BRAIN.internal.traces_aborted > 0 then
		table.insert(notes, string.format("LuaJIT cold-path trace aborts observed (%d, last=%s)",
			AI_BRAIN.internal.traces_aborted, tostring(AI_BRAIN.internal.last_abort)))
	end
	for proto, s in pairs(AI_BRAIN.external.welford_rtt) do
		local ws = ai_brain_welford_summary(s)
		if ws.n >= 2 and ws.mean > 2200 then
			table.insert(notes, string.format("%s avg lock RTT is %.0fms +/- %.0fms; fast tactic recommended",
				proto, ws.mean, ws.stddev))
		end
	end
	for proto, c in pairs(AI_BRAIN.external.consec_failures) do
		if c >= 2 then
			table.insert(notes, string.format("%s had %d consecutive unestablished attempts; tactic/pool escalation active", proto, c))
		end
	end
	if #notes == 0 then
		table.insert(notes, "All active UDP engines operate within contract latency & adaptive efficiency targets.")
	end
	return notes
end

function ai_brain_write_report(path_override)
	local target = path_override or REPORT_PATH
	local welford_out, mask_out = {}, {}
	for k, v in pairs(AI_BRAIN.external.welford_rtt) do welford_out[k] = ai_brain_welford_summary(v) end
	for k, v in pairs(AI_BRAIN.external.welford_mask) do mask_out[k] = ai_brain_welford_summary(v) end

	local avg_hot_us = (AI_BRAIN.internal.hotpath_samples > 0)
		and (AI_BRAIN.internal.hotpath_us_sum / AI_BRAIN.internal.hotpath_samples) or 0

	local report = {
		generated_at = os.date("%Y-%m-%d %H:%M:%S"),
		uptime_sec = os.time() - AI_BRAIN.started_at,
		internal_code_brain = {
			jit_attached = AI_BRAIN.internal.jit_attached,
			traces_compiled = AI_BRAIN.internal.traces_compiled,
			traces_aborted = AI_BRAIN.internal.traces_aborted,
			last_abort = AI_BRAIN.internal.last_abort,
			lua_memory_kb = collectgarbage("count"),
			avg_hotpath_decision_us = avg_hot_us,
			phase_transition_matrix = AI_BRAIN.internal.transitions,
			autonomous_upgrade_blueprint = build_blueprint()
		},
		external_network_brain = {
			circadian_bucket = ai_brain_get_circadian_bucket(),
			welford_protocol_rtt_ms = welford_out,
			welford_mask_rtt_ms = mask_out,
			incumbents = AI_BRAIN.external.incumbent,
			tactic_buckets = AI_BRAIN.external.tactic_buckets,
			affinity_memory = AI_BRAIN.external.affinity,
			consec_failures = AI_BRAIN.external.consec_failures,
			rca_by_protocol = {
				ikev2_500  = ai_brain_generate_rca("ikev2_500"),
				ikev2_4500 = ai_brain_generate_rca("ikev2_4500"),
				wireguard  = ai_brain_generate_rca("wireguard"),
				openvpn    = ai_brain_generate_rca("openvpn")
			},
			ring_buffer_count = AI_BRAIN.external.ring_count,
			recent_events = get_recent_ring(25)
		},
		evolved_policies = AI_BRAIN.policy,
		evolution_eval = AI_BRAIN.evolution_eval
	}

	local f = io.open(target, "w")
	if not f then return false end
	f:write(to_json(report, 0))
	f:write("\n")
	f:close()
	return true
end

-- =============================================================================
-- 6. Public Lifecycle Hooks Called by WireGuard / OpenVPN / IKEv2 Modules
-- =============================================================================
function ai_brain_get_envelope_opts(proto, fallback_opts, flow_key)
	local pol = AI_BRAIN.policy and AI_BRAIN.policy[proto]
	if not pol then return fallback_opts end

	local consec = AI_BRAIN.external.consec_failures[proto] or 0
	local chosen_tactic = ai_brain_select_tactic(proto)
	local cand = (consec >= 2 or chosen_tactic ~= pol.tactic)
		and build_tactic_candidate(proto, pol, chosen_tactic) or pol

	local opts = {
		tactic    = cand.tactic or "balanced",
		jc_min    = cand.jc_min or (fallback_opts and fallback_opts.jc_min) or 4,
		jc_max    = cand.jc_max or (fallback_opts and fallback_opts.jc_max) or 8,
		pace_min  = cand.pace_min or (fallback_opts and fallback_opts.pace_min) or 1500,
		pace_max  = cand.pace_max or (fallback_opts and fallback_opts.pace_max) or 2500,
		size_bias = cand.size_bias or 1.0,
		trail1_ms = cand.trail1_ms or (fallback_opts and fallback_opts.trail1_ms) or 80,
		trail2_ms = cand.trail2_ms or (fallback_opts and fallback_opts.trail2_ms) or 220
	}
	return opts
end

function ai_brain_select_spec(proto, raw_mode, last_profile, exclude_mask, flow_key)
	raw_mode = tostring(raw_mode or "auto"):lower()
	local mapped = (NUM_TO_PROTO and NUM_TO_PROTO[raw_mode]) or raw_mode

	if mapped ~= "auto" then
		local spec = (WG_PROTO_SPECS and WG_PROTO_SPECS[mapped]) or (WG_PROTO_SPECS and WG_PROTO_SPECS.junk)
		return mapped, spec, false, "Manual"
	end

	local pool = (TIER1_PROTO_LIST and #TIER1_PROTO_LIST > 0) and TIER1_PROTO_LIST or (PROTOCOL_LIST or { "quic_v1" })
	if not exclude_mask then
		local pend = AI_BRAIN.external.last_pending[proto]
		if pend and AI_BRAIN.external.active_flows[pend.flow_key] and (now_sec() - (pend.start_time or 0)) < 30 then
			exclude_mask = pend.mask
		end
	end
	local chosen, strategy, bucket = ai_brain_select_mask(proto, pool, last_profile, exclude_mask, nil, flow_key)
	local tactic = ai_brain_select_tactic(proto, bucket)
	local spec = (WG_PROTO_SPECS and WG_PROTO_SPECS[chosen]) or (WG_PROTO_SPECS and WG_PROTO_SPECS.quic_v1)
	return chosen, spec, true, string.format("%s|%s [%s]", strategy, tactic, bucket)
end

local function prune_stale_brain_flows(now_t)
	local ext = AI_BRAIN.external
	local internal = AI_BRAIN.internal
	for fk, info in pairs(ext.active_flows) do
		if (now_t - (info.start_time or now_t)) > 60 then
			ext.active_flows[fk] = nil
			internal.last_phase[fk] = nil
		end
	end
end

function ai_brain_on_attempt(proto, flow_key, mask_key, attempt_num, start_time, env_opts)
	local ext = AI_BRAIN.external
	local now_t = start_time or now_sec()
	prune_stale_brain_flows(now_t)
	local prev = ext.active_flows[flow_key]
	local pend = ext.last_pending[proto]
	local had_failure = false

	if prev and prev.mask and attempt_num > 1 then
		ext.consec_failures[proto] = (ext.consec_failures[proto] or 0) + 1
		ai_brain_update_bandit(proto, prev.mask, 0.0, nil, prev.tactic, flow_key)
		maybe_evolve_or_rollback(proto, prev.mask, false, nil, prev.tactic)
		push_ring(proto, flow_key, "ATTEMPT_FAIL_RETRY", prev.mask, nil, "attempt_" .. tostring(attempt_num))
		had_failure = true
	elseif pend and pend.flow_key ~= flow_key and ext.active_flows[pend.flow_key] and (now_t - (pend.start_time or 0)) < 30 then
		ext.consec_failures[proto] = (ext.consec_failures[proto] or 0) + 1
		ai_brain_update_bandit(proto, pend.mask, 0.0, nil, pend.tactic, pend.flow_key)
		maybe_evolve_or_rollback(proto, pend.mask, false, nil, pend.tactic)
		push_ring(proto, pend.flow_key, "PORT_ROTATE_FAIL", pend.mask, nil, "rotated_to_" .. tostring(flow_key))
		ext.active_flows[pend.flow_key] = nil
		AI_BRAIN.internal.last_phase[pend.flow_key] = nil
		had_failure = true
	end

	local tac_name = (env_opts and env_opts.tactic) or (AI_BRAIN.policy[proto] and AI_BRAIN.policy[proto].tactic) or "balanced"
	ext.active_flows[flow_key] = {
		proto      = proto,
		mask       = mask_key,
		tactic     = tac_name,
		jc_range   = env_opts and (tostring(env_opts.jc_min) .. ".." .. tostring(env_opts.jc_max)) or "-",
		pace_range = env_opts and (tostring(env_opts.pace_min) .. ".." .. tostring(env_opts.pace_max)) or "-",
		size_bias  = env_opts and env_opts.size_bias or 1.0,
		attempt    = attempt_num or 1,
		start_time = now_t
	}
	ext.last_pending[proto] = {
		flow_key   = flow_key,
		mask       = mask_key,
		tactic     = tac_name,
		start_time = now_t
	}
	ai_brain_record_transition(proto, flow_key, "ENVELOPE_SENT", false)
	push_ring(proto, flow_key, "ATTEMPT", mask_key, nil,
		string.format("attempt_%d|tac=%s", attempt_num or 1, tac_name))

	if had_failure and (now_t - (AI_BRAIN.last_persist_at or 0)) >= 2.0 then
		AI_BRAIN.last_persist_at = now_t
		ai_brain_save_policy()
		ai_brain_write_report()
	end
end

function ai_brain_on_retry_drop(proto, flow_key, detail)
	ai_brain_record_transition(proto, flow_key, "RETRY_DROP", true)
	local active = AI_BRAIN.external.active_flows[flow_key]
	push_ring(proto, flow_key, "RETRY_DROP", active and active.mask or "-", nil, detail)
end

function ai_brain_on_lock(proto, flow_key, response_bytes)
	local t_start = now_sec()
	local ext = AI_BRAIN.external
	local active = ext.active_flows[flow_key]
	local mask_key = (active and active.mask) or "unknown"
	local tac_name = (active and active.tactic) or "balanced"
	local attempt = (active and active.attempt) or 1
	local rtt_ms = active and ((t_start - active.start_time) * 1000.0) or 0.0
	if rtt_ms < 0 then rtt_ms = 0.0 end

	ext.consec_failures[proto] = 0
	ext.active_flows[flow_key] = nil
	if ext.last_pending[proto] and ext.last_pending[proto].flow_key == flow_key then
		ext.last_pending[proto] = nil
	end

	ai_brain_record_transition(proto, flow_key, "LOCKED", false)
	local w_proto = ai_brain_welford_update(ext.welford_rtt, proto, rtt_ms)
	ai_brain_welford_update(ext.welford_mask, proto .. ":" .. mask_key, rtt_ms)

	local reward = math.max(0.25, math.min(1.0, 1.0 - (rtt_ms / 12000.0) - (0.15 * (attempt - 1))))
	if mask_key ~= "unknown" then
		ai_brain_update_bandit(proto, mask_key, reward, nil, tac_name, flow_key)
		local bucket = ai_brain_get_circadian_bucket()
		local inc_key = bucket .. ":" .. proto
		if reward >= 0.70 and not ext.incumbent[inc_key] then
			ext.incumbent[inc_key] = mask_key
		end
		maybe_evolve_or_rollback(proto, mask_key, true, rtt_ms, tac_name)
	end

	push_ring(proto, flow_key, "LOCKED", mask_key, rtt_ms,
		string.format("resp=%dB,tac=%s,reward=%.2f", response_bytes or 0, tac_name, reward))
	record_hotpath_us(now_sec() - t_start)

	local ws = ai_brain_welford_summary(w_proto)
	local pol = AI_BRAIN.policy[proto]
	local win_total = (pol and pol.wins or 0) + (pol and pol.losses or 0)
	local win_pct = (win_total > 0) and math.floor(((pol.wins or 0) / win_total) * 100) or 100
	print(string.format("  [AI BRAIN]    : Mask=%s | Tac=%s | LockRTT=%.0fms (Avg=%.0f+/-%.0fms) | Reward=+%.2f | Win=%d%% | Mem=%.0fKB",
		mask_key, tac_name, rtt_ms, ws.mean, ws.stddev, reward, win_pct, collectgarbage("count")))

	append_session_log(string.format("LOCK proto=%s flow=%s mask=%s tac=%s rtt=%.0fms avg=%.0fms reward=%.2f rca=%s",
		proto, tostring(flow_key), mask_key, tac_name, rtt_ms, ws.mean, reward, ai_brain_generate_rca(proto)))

	AI_BRAIN.last_persist_at = t_start
	ai_brain_save_policy()
	ai_brain_write_report()
end

-- Keep cold-path serializers off JIT compilation so hot-path traces have minimal aborts
if jit and type(jit.off) == "function" then
	pcall(jit.off, to_json)
	pcall(jit.off, serialize_lua_value)
	pcall(jit.off, ai_brain_save_policy)
	pcall(jit.off, ai_brain_write_report)
end

init_jit_profiler()
ai_brain_load_policy()
