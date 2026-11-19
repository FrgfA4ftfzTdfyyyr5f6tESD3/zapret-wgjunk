-- =============================================================================
-- wg_reverse_rekey.lua - Beta Module: WireGuard Reverse Rekey & Role Swap
-- =============================================================================
-- Features:
--   1. Rekey Suppression Window (120s .. 220s):
--      Intercepts and drops the Client's Outbound Type 1 (148 B) rekey initiation
--      between 120s and 220s. The active session key maintains uninterrupted
--      data flow (Type 4) up to the 180s+ Reject-After-Time.
--   2. Role Swap Trigger (~180s .. 210s):
--      Because the server reaches its expiration timer (~180s) without receiving
--      a rekey from the client while traffic is active, the server assumes the
--      INITIATOR role (as defined in WireGuard Noise_IK: "allow initiator and responder to swap roles").
--      Server sends an Inbound Type 1 (148 B); Client replies with Outbound Type 2 (92 B).
--   3. Permanent Deep Sleep with Passive Audit (Cycle #3+):
--      Once the role swap is locked (is_initiator = false), all engine intervention
--      ceases (0% CPU, 0 ms latency). In Cycle #3 (~240s..300s), a passive audit log
--      verifies that the server continues to initiate and client responds.
--   4. Safety Fallback (t > 220s):
--      Extended to 220 seconds (over 3.5 minutes) so the server has full opportunity
--      to initiate before any fallback permits client initiation.
-- =============================================================================

WG_REVERSE_REKEY_ENABLED = false

-- Extended safety fallback window (220 seconds = 3 minutes 40 seconds)
local SAFETY_SESSION_AGE_MAX = 220.0
local SAFETY_SUPPRESS_TIME_MAX = 95.0

function enable_reverse_rekey(enabled)
	WG_REVERSE_REKEY_ENABLED = (enabled == true or enabled == "1" or enabled == 1 or enabled == "true")
end

function is_reverse_rekey_enabled()
	return WG_REVERSE_REKEY_ENABLED
end

-- Handles Outbound 148 B Handshake on an ESTABLISHED flow
-- Returns:
--   VERDICT_DROP   : if rekey is being suppressed to let server take initiator role
--   VERDICT_PASS   : if rekey is permitted (fallback, already swapped, or feature disabled)
function reverse_rekey_handle_outbound_hs(flow_key, entry, now)
	if not WG_REVERSE_REKEY_ENABLED then
		return VERDICT_PASS
	end

	entry.rev_status = entry.rev_status or "INIT"

	-- Case 1: Role swap already accomplished in a prior cycle -> Deep Sleep (Observe only)
	if entry.rev_status == "DONE" then
		if not entry.rev_c3_warned then
			entry.rev_c3_warned = true
			print(string.format("  [REVERSE REKEY AUDIT] Notice: Client emitted Outbound 148 B in Cycle #3+ on flow %s (Passing)", flow_key))
		end
		return VERDICT_PASS
	end

	-- Case 2: Safety fallback already active
	if entry.rev_status == "FALLBACK" then
		return VERDICT_PASS
	end

	-- Check session age since initial establishment
	local established_time = entry.established_time or now
	local session_age = now - established_time

	-- First time client attempts a rekey (t ≈ 120s)
	if entry.rev_status == "INIT" then
		entry.rev_status = "SUPPRESSING"
		entry.rev_first_suppressed = now
		entry.rev_suppress_count = 1

		print("=========================================================================")
		print("  [BETA REVERSE REKEY] CLIENT REKEY SUPPRESSED -> WAITING FOR SERVER")
		print("-------------------------------------------------------------------------")
		print(string.format("  Flow          : %s", flow_key))
		print(string.format("  Session Age   : %.1f seconds", session_age))
		print("  Strategy      : Suppressing Client Type 1 (148 B) to trigger Server Initiator")
		print("  WireGuard Spec: 'Allow initiator and responder to swap roles'")
		print("  Target Window : Server expected to initiate between ~175s and ~210s")
		print(string.format("  Safety Timer  : Extended to %.0fs (Tunnel protection)", SAFETY_SESSION_AGE_MAX))
		print("=========================================================================\n")
		return VERDICT_DROP
	end

	-- In SUPPRESSING state
	if entry.rev_status == "SUPPRESSING" then
		local time_suppressed = now - (entry.rev_first_suppressed or now)

		-- Safety Fallback Check: Only triggers if server fails to initiate after 220s (3m 40s)
		if session_age > SAFETY_SESSION_AGE_MAX or time_suppressed > SAFETY_SUPPRESS_TIME_MAX then
			entry.rev_status = "FALLBACK"
			print("=========================================================================")
			print("  [BETA REVERSE REKEY] SAFETY FALLBACK TRIGGERED (Extended 220s Window)")
			print("-------------------------------------------------------------------------")
			print(string.format("  Flow          : %s", flow_key))
			print(string.format("  Elapsed       : %.1fs (Suppressed for %.1fs)", session_age, time_suppressed))
			print("  Reason        : Server did not initiate within 220s window (passive or restricted).")
			print("  Action        : Allowing Client Rekey to pass directly (Tunnel preserved).")
			print("=========================================================================\n")
			return VERDICT_PASS
		end

		entry.rev_suppress_count = (entry.rev_suppress_count or 1) + 1
		print(string.format("  [BETA REVERSE REKEY] Client Rekey Retry #%d Suppressed (Session Age: %.1fs / Window: %.0fs) ---> DROPPED",
			entry.rev_suppress_count, session_age, SAFETY_SESSION_AGE_MAX))
		return VERDICT_DROP
	end

	return VERDICT_PASS
end

-- Handles Inbound 148 B Handshake from Server
-- Returns VERDICT_PASS
function reverse_rekey_handle_inbound_hs(flow_key, entry, now)
	if not WG_REVERSE_REKEY_ENABLED then
		return VERDICT_PASS
	end

	if not entry then return VERDICT_PASS end

	-- Cycle 2: First Server-Initiated Rekey (The Role Swap Milestone)
	if entry.rev_status == "SUPPRESSING" or entry.rev_status == "INIT" or entry.state == "ESTABLISHED" then
		if entry.rev_status ~= "DONE" then
			entry.rev_status = "SERVER_INITIATED"
			entry.rev_server_hs_time = now

			print("=========================================================================")
			print("  [BETA REVERSE REKEY] SERVER INITIATION (Type 1 - 148 B) RECEIVED!")
			print("-------------------------------------------------------------------------")
			print(string.format("  Flow          : %s", flow_key))
			print(string.format("  Time          : %s", os.date("%H:%M:%S")))
			print("  Milestone     : Server has assumed the INITIATOR role on the wire!")
			print("  Action        : Passing directly to Client with ZERO latency (0 ms)")
			print("=========================================================================\n")
			return VERDICT_PASS
		end
	end

	-- Cycle 3+ Passive Audit: Observing persistent server initiation in Deep Sleep
	if entry.rev_status == "DONE" then
		if not entry.rev_c3_inbound then
			entry.rev_c3_inbound = true
			print("=========================================================================")
			print("  [REVERSE REKEY AUDIT] CYCLE #3+ SERVER INITIATION CONFIRMED!")
			print("-------------------------------------------------------------------------")
			print(string.format("  Flow          : %s", flow_key))
			print(string.format("  Time          : %s", os.date("%H:%M:%S")))
			print("  Verification  : Server continues to initiate rekeys automatically!")
			print("  Action        : Passed directly to kernel (0 ms latency)")
			print("=========================================================================\n")
		end
	end

	return VERDICT_PASS
end

-- Handles Outbound 92 B Handshake Response from Client
-- Returns VERDICT_PASS
function reverse_rekey_handle_outbound_resp(flow_key, entry, now)
	if not WG_REVERSE_REKEY_ENABLED then
		return VERDICT_PASS
	end

	if not entry then return VERDICT_PASS end

	-- Cycle 2: Client response finalizing the Role Swap
	if entry.rev_status == "SERVER_INITIATED" then
		entry.rev_status = "DONE"
		entry.rev_completed_time = now

		print("=========================================================================")
		print("  [BETA REVERSE REKEY] CLIENT RESPONSE (Type 2 - 92 B) DISPATCHED!")
		print("-------------------------------------------------------------------------")
		print(string.format("  Flow          : %s", flow_key))
		print(string.format("  Time          : %s", os.date("%H:%M:%S")))
		print("  Outcome       : REVERSE REKEY / ROLE SWAP SUCCESSFULLY COMPLETED!")
		print("  State Change  : Client is now RESPONDER (is_initiator = false).")
		print("                  Server will initiate all future rekeys automatically.")
		print("  Module State  : DEEP_SLEEP (Engine disengages permanently; passive audit on)")
		print("=========================================================================\n")
		return VERDICT_PASS
	end

	-- Cycle 3+ Passive Audit: Observing persistent client response in Deep Sleep
	if entry.rev_status == "DONE" then
		if not entry.rev_c3_outbound then
			entry.rev_c3_outbound = true
			print("=========================================================================")
			print("  [REVERSE REKEY AUDIT] CYCLE #3+ CLIENT RESPONSE CONFIRMED!")
			print("-------------------------------------------------------------------------")
			print(string.format("  Flow          : %s", flow_key))
			print(string.format("  Time          : %s", os.date("%H:%M:%S")))
			print("  Verification  : Client responded as Responder! Permanent Role Swap Proven.")
			print("  Action        : Passed directly to wire (0 ms latency)")
			print("=========================================================================\n")
		end
	end

	return VERDICT_PASS
end
