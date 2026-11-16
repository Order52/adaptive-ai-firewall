# Roll back a promoted model or profile

Promotion needs a passing gate and a human admin, and probation rolls back automatically.
Use this when you decide to back out manually.

- Profile: `POST /api/profiles/<app_id>/<version>/rollback` with `{"note":"<why, 3+ chars>"}` (admin)
  rolls the trusted profile back to `<version>` (the version to return to).
- Challenger (online-learning HST): `POST /api/learning/challenger/rollback` with
  `{"note":"<why>"}` (admin).
- Both write to the audit log and reload the controller's models.

**Verify:** `api /api/models` and `api /api/overview` show the expected version/hash;
`api /api/readyz` still `ready`. Rolling back a profile never deletes the newer one, so the
decision can be reversed.
