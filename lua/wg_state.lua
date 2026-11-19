-- =============================================================================
-- wg_state.lua - Dual-Stack (IPv4/IPv6) Event-Driven Flow State Machine
-- =============================================================================
-- Features:
--   1. Zero-Timer & Zero-NAT Architecture:
--      No background timers, no sleep threads, and NO port masquerading.
--      Client's authentic ephemeral port stays 100% untouched so Type 4 data packets
--      never suffer from NAT mismatch or 15-second keepalive drops.
--   2. Drop Duplicates on Dead Ports (Rapid Port Rotation):
--      Attempt 1: Fresh flow (SrcIP:SrcPort -> DstIP:DstPort) runs Cover Envelope.
--      Attempt 2+: If client retries on the same unestablished port, the duplicate
--                  packet is immediately DROPPED (VERDICT_DROP) without wasting
--                  2.5 seconds on a dead port. This forces the client (Windscribe /
--                  WireGuard) to immediately rotate to a fresh ephemeral port.
--   3. Dual-Stack Native (IPv4 & IPv6):
--      Flow keys are symmetrically normalized for both IPv4 and IPv6 5-tuples.
--   4. Session-Locked Disengagement (LOCKED_ESTABLISHED):
--      As soon as the server's 92B response (Type 2) arrives, the flow is locked:
--      engine completely disengages, and all subsequent re-keys (every 120s)
--      pass through directly (VERDICT_PASS) with zero latency.
-- =============================================================================

FLOW_TABLE = FLOW_TABLE or {}

-- Generates a symmetric normalized flow key for both IPv4 and IPv6
-- Outbound: Client -> Server => "ClientIP:ClientPort->ServerIP:ServerPort"
-- Inbound : Server -> Client => "ClientIP:ClientPort->ServerIP:ServerPort"
function get_flow_key(dis, is_inbound)
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
		-- Inbound packet arrived from Server to Client
		-- Normalize to Client -> Server orientation
		return string.format("%s:%d->%s:%d", dst_ip, dport, src_ip, sport)
	else
		-- Outbound packet from Client to Server
		return string.format("%s:%d->%s:%d", src_ip, sport, dst_ip, dport)
	end
end

-- Looks up current flow state: "TRIED", "ESTABLISHED", or nil
function flow_get_state(flow_key)
	local entry = FLOW_TABLE[flow_key]
	if not entry then return nil end

	local now = clock_getfloattime()
	-- If established, verify not expired (active within 300 seconds)
	if entry.state == "ESTABLISHED" then
		if now - (entry.last_seen or now) < 300 then
			entry.last_seen = now
			return "ESTABLISHED"
		else
			FLOW_TABLE[flow_key] = nil
			return nil
		end
	end

	return entry.state
end

-- Registers initial handshake attempt on a fresh flow key (Attempt 1)
function flow_register_attempt(flow_key, hs_id)
	flow_cleanup()

	local now = clock_getfloattime()
	local entry = {
		flow_key   = flow_key,
		state      = "TRIED",
		attempt    = 1,
		first_seen = now,
		last_seen  = now,
		hs_id      = hs_id
	}
	FLOW_TABLE[flow_key] = entry
	return entry
end

-- Sets flow state to LOCKED_ESTABLISHED upon receiving 92B response
function flow_set_established(flow_key)
	local now = clock_getfloattime()
	local entry = FLOW_TABLE[flow_key]
	if entry then
		entry.state = "ESTABLISHED"
		entry.established_time = now
		entry.last_seen = now
	else
		FLOW_TABLE[flow_key] = {
			flow_key         = flow_key,
			state            = "ESTABLISHED",
			attempt          = 1,
			first_seen       = now,
			established_time = now,
			last_seen        = now
		}
	end
end

-- Prunes stale unestablished entries to keep memory footprint close to zero
function flow_cleanup()
	local now = clock_getfloattime()
	for k, v in pairs(FLOW_TABLE) do
		if v.state == "TRIED" and (now - (v.last_seen or now) > 30) then
			FLOW_TABLE[k] = nil
		elseif v.state == "ESTABLISHED" and (now - (v.last_seen or now) > 360) then
			FLOW_TABLE[k] = nil
		end
	end
end
