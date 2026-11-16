# A legitimate user was restricted or blocked

**Notice:** a user reports errors or HTTP 429/403; the dashboard shows an active policy on
their address. The system runs in `monitor` mode: only manual or approved actions apply.

1. Identify: `api /api/policies | python3 -m json.tool | less`, or the dashboard policy list.
   `api /api/policies/<id>/explain` shows the evidence behind it.
2. Release: dashboard "Revoke", or
   `curl -s --cacert $CA -H "Authorization: Bearer <operator token>" -X POST https://10.77.50.10:8080/api/policies/<id>/revoke -H 'content-type: application/json' -d '{"reason":"false positive"}'`
   Enforcement is level-triggered: the reconciler brings the devices back in line with the policy state.
3. Teach the system: `POST /api/feedback` with `{"label":"false_positive","source_ip":"<ip>","policy_id":"<id>","note":"..."}`.
   Feedback is audited and feeds drift monitoring. It does not by itself retrain anything.
4. Storm (many users at once): `POST /api/mode {"mode":"monitor"}` (admin) stops automatic
   actions immediately; then revoke the policies. Consider `model-rollback.md` if a recent
   promotion preceded the storm.

**Verify:** `api /api/policies` shows the policy `revoked`; the user can connect; `api /api/audit` records who did what.
