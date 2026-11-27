-- =============================================================================
-- ikev2_state.lua - Dual-Stack (IPv4/IPv6) Flow State Machine for IKEv2 NAT-T
-- =============================================================================
-- Architecture:
--   * UDP 500 (IKE_SA_INIT) & IP Protocol 50 (Raw ESP) bypass WinDivert
--     completely for native kernel speed when IPsec Passthrough is active.
--   * UDP 4500 (NAT-T, RFC 3948) is monitored for IKE_SA_INIT / IKE_AUTH
--     control packets (prefixed with 4-byte Non-ESP Marker 0x00000000).
--   * Fragment-aware (RFC 7383 SKF 0x35): Fragment 1 triggers Cover Envelope,
--     subsequent fragments (2/3, 3/3...) pass immediately without drops.
--   * Session Lock (LOCKED_ESTABLISHED): Disengages completely once inbound
--     IKE_AUTH response or ESP traffic arrives on UDP 4500.
-- =============================================================================

IKEV2_FLOW_TABLE = IKEV2_FLOW_TABLE or {}

function ikev2_get_flow_key(dis, is_inbound)
	if not dis or not dis.udp then return nil end

	local src_ip, dst_ip
	if dis.ip then
		src_ip = ntop(dis.ip.ip_src)
		dst_ip = ntop(dis.ip.ip_dst)
	elseif dis.ip6 then
		src_ip = ntop(dis.ip6.ip6_src)
		dst_ip = ntop(dis.ip6.ip6_dst)
	else
		return nil
	end

	local sport = dis.udp.uh_sport or 0
	local dport = dis.udp.uh_dport or 0

	if is_inbound then
		return string.format("%s:%d->%s:%d", dst_ip, dport, src_ip, sport)
	else
		return string.format("%s:%d->%s:%d", src_ip, sport, dst_ip, dport)
	end
end

function ikev2_flow_cleanup()
	local now = clock_getfloattime()
	for k, v in pairs(IKEV2_FLOW_TABLE) do
		if v.state == "TRIED" and (now - (v.last_seen or now) > 45) then
			IKEV2_FLOW_TABLE[k] = nil
		elseif v.state == "ESTABLISHED" and (now - (v.last_seen or now) > 360) then
			IKEV2_FLOW_TABLE[k] = nil
		end
	end
end

function ikev2_flow_get_entry(flow_key)
	local entry = IKEV2_FLOW_TABLE[flow_key]
	if not entry then return nil end

	local now = clock_getfloattime()
	if entry.state == "ESTABLISHED" then
		if now - (entry.last_seen or now) < 300 then
			entry.last_seen = now
			return entry
		else
			IKEV2_FLOW_TABLE[flow_key] = nil
			return nil
		end
	end
	return entry
end

function ikev2_flow_register_attempt(flow_key, hs_id, mid)
	ikev2_flow_cleanup()
	local now = clock_getfloattime()
	local entry = IKEV2_FLOW_TABLE[flow_key]
	if entry then
		entry.state = "TRIED"
		entry.attempt = (entry.attempt or 0) + 1
		entry.last_seen = now
		entry.last_envelope = now
		entry.last_mid = mid
		entry.hs_fire_at = nil
		entry.frags_sent = {}
		entry.hs_id = hs_id
		return entry
	end

	entry = {
		flow_key      = flow_key,
		state         = "TRIED",
		attempt       = 1,
		first_seen    = now,
		last_seen     = now,
		last_envelope = now,
		last_mid      = mid,
		hs_fire_at    = nil,
		frags_sent    = {},
		hs_id         = hs_id
	}
	IKEV2_FLOW_TABLE[flow_key] = entry
	return entry
end

function ikev2_flow_set_established(flow_key)
	local now = clock_getfloattime()
	local entry = IKEV2_FLOW_TABLE[flow_key]
	if entry then
		entry.state = "ESTABLISHED"
		entry.established_time = now
		entry.last_seen = now
	else
		IKEV2_FLOW_TABLE[flow_key] = {
			flow_key         = flow_key,
			state            = "ESTABLISHED",
			attempt          = 1,
			first_seen       = now,
			established_time = now,
			last_seen        = now
		}
	end
end
