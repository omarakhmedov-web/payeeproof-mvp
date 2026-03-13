# PayeeProof MVP Issuer - GitHub + Render Deploy Guide

This package is the minimal issuer/API layer for the PayeeProof MVP on Render.

## Included files
- `app.py` - Flask API
- `requirements.txt` - Python dependencies
- `render.yaml` - Render configuration
- `.env.example` - environment variables example

## Implemented endpoints
- `GET /health`
- `GET /v1/public-keys`
- `POST /v1/verification-requests`
- `POST /v1/verification-sessions/<session_id>/complete`
- `GET /v1/verification-requests/<request_id>/artifact`

## Important
- This is the **issuer/API layer**, not the reference verifier.
- The client must still verify the signed artifact locally with `verifier.py` or `verifier.js`.
- If `SIGNING_PRIVATE_KEY_PEM_B64` is not provided, the app will start with a temporary demo key. Do not keep that behavior for production or a real pilot.

---

## Part 1 - Create a GitHub repository

1. Open `https://github.com`.
2. In the top-right corner, click **+** -> **New repository**.
3. In **Repository name**, enter `payeeproof-mvp`.
4. Choose **Public** or **Private**.
   - For a quick test, **Public** is fine.
   - For a cleaner pilot setup, **Private** is better.
5. Click **Create repository**.

---

## Part 2 - Upload files to the repository in the browser

### Option without Git on your computer
1. Open the new repository.
2. Click **Add file** -> **Upload files**.
3. Drag these 4 files from this package into the upload area:
   - `app.py`
   - `requirements.txt`
   - `render.yaml`
   - `.env.example`
4. At the bottom, click **Commit changes**.

### Files you can also add to the same repository later
From the previous MVP pack, you can add:
- `artifact_schema.json`
- `verifier.py`
- `verifier.js`
- `sample_artifact.json`
- `README_MVP.md`

For the first Render deployment, the 4 files above are enough.

---

## Part 3 - Create the service on Render

1. Open `https://dashboard.render.com/`.
2. Click **New +**.
3. Choose **Web Service**.
4. Connect GitHub if Render asks you to do so.
5. Select the `payeeproof-mvp` repository.
6. Make sure Render picks up these values:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
7. Click **Create Web Service**.

---

## Part 4 - Add environment variables in Render

After the service is created:

1. Open the service.
2. Go to the **Environment** tab.
3. Click **Add Environment Variable** and add the following values.

### Required minimum
- `BASE_URL` = the URL of your Render service  
  Example: `https://payeeproof-mvp.onrender.com`
- `API_BEARER_TOKEN` = any long secret string  
  Example: `pp_local_demo_2026_secret`
- `DB_PATH` = `/tmp/payeeproof_mvp.db`
- `DEFAULT_TTL_MINUTES` = `10`
- `KEY_VERSION` = `ed25519-dev-v1`

### Optional for the first demo deployment
- `SIGNING_PRIVATE_KEY_PEM_B64`

If you do not provide a private key, the service will generate a demo key on boot.

4. Click **Save Changes**.
5. If Render does not redeploy automatically, click **Manual Deploy** -> **Deploy latest commit**.

---

## Part 5 - Check that the service is running

When the deployment finishes:

1. Open this URL in the browser:
   - `https://YOUR-SERVICE.onrender.com/health`
2. You should see JSON similar to this:

```json
{"ok": true, "service": "payeeproof-issuer", "version": "0.1.0-mvp-issuer"}
```

---

## Part 6 - Test the API from PowerShell

Open PowerShell.

### 6.1 Set variables

```powershell
$BASE="https://YOUR-SERVICE.onrender.com"
$TOKEN="pp_local_demo_2026_secret"
$IDEM1="create-001"
$IDEM2="complete-001"
```

### 6.2 Create a verification request

```powershell
$body = @{
  client_request_id = "client-001"
  order_id = "ord-1001"
  invoice_id = "inv-1001"
  payer_id = "payer-demo-001"
  payee_id = "payee-demo-001"
  expected = @{
    network = "ethereum"
    asset = "USDC"
    address = "0x1111111111111111111111111111111111111111"
  }
  policy = @{
    ownership_proof_required = $true
    ttl_minutes = 10
  }
  metadata = @{
    note = "first-demo"
  }
} | ConvertTo-Json -Depth 5

$r1 = Invoke-RestMethod -Method POST `
  -Uri "$BASE/v1/verification-requests" `
  -Headers @{Authorization="Bearer $TOKEN"; "Idempotency-Key"=$IDEM1} `
  -ContentType "application/json" `
  -Body $body

$r1 | ConvertTo-Json -Depth 10
```

From the response, note these values:
- `request_id`
- `verification_session.session_id`

### 6.3 Save them into variables

```powershell
$REQUEST_ID = $r1.request_id
$SESSION_ID = $r1.verification_session.session_id
```

### 6.4 Complete the verification session

```powershell
$body2 = @{
  provided = @{
    network = "ethereum"
    asset = "USDC"
    address = "0x1111111111111111111111111111111111111111"
  }
  ownership_proof = @{
    method = "wallet_signature"
    status = "verified"
    proof_ref = "demo-proof-001"
  }
} | ConvertTo-Json -Depth 5

$r2 = Invoke-RestMethod -Method POST `
  -Uri "$BASE/v1/verification-sessions/$SESSION_ID/complete" `
  -Headers @{Authorization="Bearer $TOKEN"; "Idempotency-Key"=$IDEM2} `
  -ContentType "application/json" `
  -Body $body2

$r2 | ConvertTo-Json -Depth 20
```

If everything is correct, you should see:
- `status = verified`
- `artifact`

### 6.5 Fetch the artifact separately

```powershell
$r3 = Invoke-RestMethod -Method GET `
  -Uri "$BASE/v1/verification-requests/$REQUEST_ID/artifact" `
  -Headers @{Authorization="Bearer $TOKEN"}

$r3 | ConvertTo-Json -Depth 20
```

---

## Part 7 - Verify the artifact locally with the reference verifier

1. Copy the `artifact` object from `$r3` into a file named `artifact_from_render.json`.
2. Copy the PEM public key from `GET /v1/public-keys`.
3. Add that public key to the reference verifier keyring.
4. Run:

```powershell
python .\verifier.py --artifact .\artifact_from_render.json --expected expected.json
```

---

## Current limitations of this version
- no full payee verification page
- no webhooks
- no KMS or HSM
- SQLite instead of Postgres
- no real client-side anti-replay store
- no multi-tenant model
- no production-grade key rotation logic

Even with those limits, this is already a valid MVP backbone: request -> complete -> signed artifact -> local verification.
