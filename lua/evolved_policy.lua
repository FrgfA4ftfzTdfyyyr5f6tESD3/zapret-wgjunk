-- =============================================================================
-- evolved_policy.lua - Contract-Verified Self-Evolved Policy & Brain Memory
-- =============================================================================
return {
	version = 2,
	updated_at = 0,
	policies = {
		ikev2_500 = { jc_min = 2, jc_max = 3, pace_min = 600, pace_max = 950, size_bias = 1.0, trail1_ms = 60, trail2_ms = 180, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 },
		ikev2_4500 = { jc_min = 4, jc_max = 6, pace_min = 1300, pace_max = 1850, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 },
		wireguard = { jc_min = 4, jc_max = 8, pace_min = 1500, pace_max = 2500, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 },
		openvpn = { jc_min = 4, jc_max = 8, pace_min = 1500, pace_max = 2500, size_bias = 1.0, trail1_ms = 80, trail2_ms = 220, tactic = "balanced", preferred_mask = nil, wins = 0, losses = 0 }
	},
	buckets = {},
	tactic_buckets = {},
	affinity = {},
	incumbents = {}
}
