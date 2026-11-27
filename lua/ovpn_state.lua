-- =============================================================================
-- ovpn_state.lua - Dual-Stack (IPv4/IPv6) Flow State Machine for OpenVPN UDP
-- =============================================================================
-- Features:
--   1. Zero-NAT Architecture:
--      Client's authentic ephemeral port stays 100% untouched. Data channel
--      packets (P_DATA_V2 / 0x48) and TLS control packets (0x20/0x28) never
--      suffer from NAT mismatch.
--   2. Smart Retry Cooldown (Overlap Protection):
--      Unlike WireGuard, OpenVPN reuses the same UDP socket across retries
--      (~t+2.3s, t+5.8s, t+13.8s). Retries arriving < 3.0s after an envelope
--      starts are dropped to prevent overlapping bursts; retries >= 3.0s
--      trigger a fresh Cover Envelope with a newly rotated protocol.
--   3. Session-Locked Disengagement (LOCKED_ESTABLISHED):
--      As soon as the server's Hard Reset response (0x40 / 0x58) arrives,
--      the flow locks and the desync engine disengages completely.
-- =============================================================================

OVPN_FLOW_TABLE = OVPN_FLOW_TABLE or {}

function ovpn_get_flow_key(dis, is_inbound)
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

function ovpn_flow_cleanup()
	local now = clock_getfloattime()
	for k, v in pairs(OVPN_FLOW_TABLE) do
		if v.state == "TRIED" and (now - (v.last_seen or now) > 45) then
			OVPN_FLOW_TABLE[k] = nil
		elseif v.state == "ESTABLISHED" and (now - (v.last_seen or now) > 360) then
			OVPN_FLOW_TABLE[k] = nil
		end
	end
end

function ovpn_flow_get_entry(flow_key)
	local entry = OVPN_FLOW_TABLE[flow_key]
	if not entry then return nil end

	local now = clock_getfloattime()
	if entry.state == "ESTABLISHED" then
		if now - (entry.last_seen or now) < 300 then
			entry.last_seen = now
			return entry
		else
			OVPN_FLOW_TABLE[flow_key] = nil
			return nil
		end
	end
	return entry
end

function ovpn_flow_register_attempt(flow_key, hs_id)
	ovpn_flow_cleanup()
	local now = clock_getfloattime()
	local entry = OVPN_FLOW_TABLE[flow_key]
	if entry then
		entry.state = "TRIED"
		entry.attempt = (entry.attempt or 0) + 1
		entry.last_seen = now
		entry.last_envelope = now
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
		hs_id         = hs_id
	}
	OVPN_FLOW_TABLE[flow_key] = entry
	return entry
end

function ovpn_flow_set_established(flow_key)
	local now = clock_getfloattime()
	local entry = OVPN_FLOW_TABLE[flow_key]
	if entry then
		entry.state = "ESTABLISHED"
		entry.established_time = now
		entry.last_seen = now
	else
		OVPN_FLOW_TABLE[flow_key] = {
			flow_key         = flow_key,
			state            = "ESTABLISHED",
			attempt          = 1,
			first_seen       = now,
			established_time = now,
			last_seen        = now
		}
	end
end
