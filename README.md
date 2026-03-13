# PayeeProof MVP

Verify stablecoin payout details before funds move.

PayeeProof is a non-custodial verification and payout-control layer for stablecoin disbursements. It is not a wallet, not a custody product, and not a payment processor. The MVP issues signed verification artifacts that clients validate locally before allowing payout.

## Current MVP status
Implemented and tested:
- Health endpoint
- Auth-protected public key endpoint
- Verification request creation
- Verification session completion
- Signed artifact issuance
- Local verification with Ed25519 public key
- Happy-path test (`ALLOW_PAYOUT / OK`)
- Mismatch-path test (`ASSET_MISMATCH`, `BLOCK_AND_REVERIFY`)
- Idempotency enforcement on request creation

## Core principle
Do not trust PayeeProof blindly. Verify what PayeeProof says independently.

A payout should be allowed only if:
1. the client has its own expected payout data,
2. the PayeeProof artifact is signed and valid,
3. the artifact matches the client’s expected data,
4. the artifact is unexpired,
5. policy status is allowed.

## Architecture at a glance
- **API / Issuer:** creates verification requests, completes sessions, issues signed artifacts
- **Public keys endpoint:** exposes active verification keys
- **Reference verifier:** validates artifact signature, TTL, payload hash, and expected-field match locally
- **Audit path:** request / session / artifact flow is observable and fail-closed

## Main endpoints
### `GET /health`
Service liveness check.

### `GET /v1/public-keys`
Returns active verification public keys. Requires Bearer token.

### `POST /v1/verification-requests`
Creates a verification request. Requires:
- Bearer token
- `Idempotency-Key` header
- JSON body with expected payout details

### `POST /v1/verification-sessions/{session_id}/complete`
Completes a verification session with provided values and ownership proof. Requires:
- Bearer token
- `Idempotency-Key` header
- JSON body with provided payout details and proof status

## Example happy-path flow
1. Client creates verification request with expected network, asset, and address.
2. Session is completed with matching provided values.
3. Server returns a signed artifact.
4. Client fetches public key.
5. Client runs local verifier.
6. If result is `ALLOW_PAYOUT / OK`, payout may proceed.

## Example mismatch flow
1. Client creates verification request with expected asset `USDC`.
2. Session is completed with provided asset `USDT`.
3. Server returns:
- `status = mismatch_detected`
- `reason_code = ASSET_MISMATCH`
- `next_action = BLOCK_AND_REVERIFY`
4. Payout must not proceed.

## Local verifier
The verifier is the trust anchor on the client side.

It must reject artifacts when:
- signature is invalid,
- key is wrong or unknown,
- artifact TTL has expired,
- payload hash does not match expected data,
- key business fields differ from expected values.

## Security notes
- Fail-closed by default
- Signed artifact is required
- Short TTL is enforced
- Session flow should be treated as single-use
- Client must store expected payout data locally
- API status alone is not sufficient to authorize payout

## Known MVP constraints
- Demo-grade token auth
- Minimal policy engine
- Reference verifier is local/manual for now
- Replay protections and audit depth are still moving toward fuller hardening
- No production HSM / tenant keys in MVP

## Demo checklist
Before any live demo:
1. Confirm `/health` returns OK
2. Confirm `/v1/public-keys` returns 200 with Bearer token
3. Run happy path end-to-end
4. Run one mismatch scenario
5. Keep demo window short enough to avoid artifact expiry

## Recommended next polish steps
1. Add structured negative test runs to the repo
2. Improve README with curl/PowerShell examples
3. Add demo script for client calls
4. Add one-click script for create → complete → verify
5. Add clear mismatch matrix in docs

## Disclaimer
This MVP is for validation and pilot demos. It is not yet a production-grade authorization system for high-value disbursements without additional operational and security hardening.
