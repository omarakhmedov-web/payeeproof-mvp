from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP_VERSION = "0.1.0-mvp-issuer"
ARTIFACT_VERSION = "pp_v1"
ALGORITHM = "Ed25519"
PAYLOAD_FIELDS = [
    "request_id",
    "order_id",
    "invoice_id",
    "payer_id",
    "payee_id",
    "network",
    "asset",
    "address",
    "ownership_proof_status",
    "policy_status",
    "reason_code",
    "session_id",
    "session_binding",
    "payload_hash",
]
EVM_NETWORKS = {"ethereum", "polygon", "arbitrum", "base", "bsc"}
SUPPORTED_NETWORKS = {"ethereum", "polygon", "arbitrum", "base", "bsc", "solana"}
SUPPORTED_ASSETS = {"USDC", "USDT"}
RETRY_ALLOWED_CODES = {"ADDRESS_MISMATCH", "NETWORK_MISMATCH", "ASSET_MISMATCH"}

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
API_BEARER_TOKEN = os.getenv("API_BEARER_TOKEN", "")
DB_PATH = os.getenv("DB_PATH", "/tmp/payeeproof_mvp.db")
DEFAULT_TTL_MINUTES = int(os.getenv("DEFAULT_TTL_MINUTES", "10"))
DEFAULT_KEY_VERSION = os.getenv("KEY_VERSION", "ed25519-dev-v1")

app = Flask(__name__)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso8601(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timezone required")
    return dt.astimezone(timezone.utc)


def normalize_network(network: str) -> str:
    return str(network or "").strip().lower()


def normalize_asset(asset: str) -> str:
    return str(asset or "").strip().upper()


def normalize_address(network: str, address: str) -> str:
    addr = str(address or "").strip()
    if normalize_network(network) in EVM_NETWORKS:
        return addr.lower()
    return addr


def canonical_expected_string(expected: Dict[str, Any]) -> str:
    network = normalize_network(expected.get("network", ""))
    asset = normalize_asset(expected.get("asset", ""))
    address = normalize_address(network, expected.get("address", ""))
    items = [
        ("order_id", expected.get("order_id", "")),
        ("invoice_id", expected.get("invoice_id", "")),
        ("payee_id", expected.get("payee_id", "")),
        ("network", network),
        ("asset", asset),
        ("address", address),
    ]
    return "\n".join(f"{k}={v}" for k, v in items)


def compute_payload_hash(expected: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_expected_string(expected).encode("utf-8")).hexdigest()


def canonical_payload_string(payload: Dict[str, Any]) -> str:
    payload_n = dict(payload)
    payload_n["network"] = normalize_network(payload_n["network"])
    payload_n["asset"] = normalize_asset(payload_n["asset"])
    payload_n["address"] = normalize_address(payload_n["network"], payload_n["address"])
    return "\n".join(f"{field}={payload_n[field]}" for field in PAYLOAD_FIELDS)


def load_private_key() -> Ed25519PrivateKey:
    pem_b64 = os.getenv("SIGNING_PRIVATE_KEY_PEM_B64", "")
    if pem_b64:
        pem = base64.b64decode(pem_b64)
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("SIGNING_PRIVATE_KEY_PEM_B64 must contain an Ed25519 private key")
        return key
    return Ed25519PrivateKey.generate()


PRIVATE_KEY = load_private_key()
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_PEM = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS verification_requests (
            request_id TEXT PRIMARY KEY,
            client_request_id TEXT,
            order_id TEXT NOT NULL,
            invoice_id TEXT NOT NULL,
            payer_id TEXT NOT NULL,
            payee_id TEXT NOT NULL,
            network TEXT NOT NULL,
            asset TEXT NOT NULL,
            address TEXT NOT NULL,
            ownership_proof_required INTEGER NOT NULL,
            ttl_minutes INTEGER NOT NULL,
            request_status TEXT NOT NULL,
            session_id TEXT NOT NULL UNIQUE,
            session_status TEXT NOT NULL,
            session_binding TEXT NOT NULL,
            created_at TEXT NOT NULL,
            session_expires_at TEXT NOT NULL,
            expected_payload_hash TEXT NOT NULL,
            metadata_json TEXT,
            provided_network TEXT,
            provided_asset TEXT,
            provided_address TEXT,
            ownership_method TEXT,
            ownership_status TEXT,
            ownership_proof_ref TEXT,
            artifact_json TEXT,
            completed_at TEXT,
            idempotency_key_create TEXT,
            idempotency_key_complete TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT,
            event_type TEXT NOT NULL,
            event_data_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


def audit(conn: sqlite3.Connection, request_id: Optional[str], event_type: str, event_data: Dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO audit_events (request_id, event_type, event_data_json, created_at) VALUES (?, ?, ?, ?)",
        (request_id, event_type, json.dumps(event_data, ensure_ascii=False), iso_z(now_utc())),
    )


def require_auth() -> Optional[tuple[Any, int]]:
    if not API_BEARER_TOKEN:
        return None
    auth_header = request.headers.get("Authorization", "")
    expected = f"Bearer {API_BEARER_TOKEN}"
    if auth_header != expected:
        return jsonify({"error": "UNAUTHORIZED"}), 401
    return None


def require_idempotency() -> Optional[tuple[Any, int]]:
    if not request.headers.get("Idempotency-Key"):
        return jsonify({"error": "IDEMPOTENCY_KEY_REQUIRED"}), 400
    return None


def json_body() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def validate_expected(network: str, asset: str, address: str) -> Optional[str]:
    if network not in SUPPORTED_NETWORKS:
        return "UNSUPPORTED_NETWORK"
    if asset not in SUPPORTED_ASSETS:
        return "UNSUPPORTED_ASSET"
    if not address:
        return "ADDRESS_REQUIRED"
    return None


def build_artifact(row: sqlite3.Row) -> Dict[str, Any]:
    issued_at = now_utc()
    expires_at = min(parse_iso8601(row["session_expires_at"]), issued_at + timedelta(minutes=row["ttl_minutes"]))
    payload = {
        "request_id": row["request_id"],
        "order_id": row["order_id"],
        "invoice_id": row["invoice_id"],
        "payer_id": row["payer_id"],
        "payee_id": row["payee_id"],
        "network": row["network"],
        "asset": row["asset"],
        "address": row["address"],
        "ownership_proof_status": "verified",
        "policy_status": "allowed",
        "reason_code": "OK",
        "session_id": row["session_id"],
        "session_binding": "single_use",
        "payload_hash": row["expected_payload_hash"],
    }
    canonical = canonical_payload_string(payload)
    signature = PRIVATE_KEY.sign(canonical.encode("utf-8"))
    return {
        "artifact_version": ARTIFACT_VERSION,
        "algorithm": ALGORITHM,
        "key_version": DEFAULT_KEY_VERSION,
        "issued_at": iso_z(issued_at),
        "expires_at": iso_z(expires_at),
        "nonce": secrets.token_urlsafe(16),
        "payload": payload,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }


@app.get("/health")
def health() -> Any:
    return jsonify({"ok": True, "service": "payeeproof-issuer", "version": APP_VERSION})


@app.get("/")
def root() -> Any:
    return jsonify({
        "service": "PayeeProof MVP Issuer",
        "version": APP_VERSION,
        "endpoints": [
            "GET /health",
            "GET /v1/public-keys",
            "POST /v1/verification-requests",
            "POST /v1/verification-sessions/<session_id>/complete",
            "GET /v1/verification-requests/<request_id>/artifact",
        ],
    })


@app.get("/v1/public-keys")
def public_keys() -> Any:
    auth_error = require_auth()
    if auth_error:
        return auth_error
    return jsonify({
        "keys": [
            {
                "key_version": DEFAULT_KEY_VERSION,
                "algorithm": ALGORITHM,
                "public_key_pem": PUBLIC_KEY_PEM,
                "status": "active",
            }
        ]
    })


@app.post("/v1/verification-requests")
def create_verification_request() -> Any:
    auth_error = require_auth()
    if auth_error:
        return auth_error
    idem_error = require_idempotency()
    if idem_error:
        return idem_error

    body = json_body()
    order_id = str(body.get("order_id") or "")
    invoice_id = str(body.get("invoice_id") or "")
    if not order_id and not invoice_id:
        return jsonify({"error": "ORDER_OR_INVOICE_REQUIRED"}), 400

    payer_id = str(body.get("payer_id") or "")
    payee_id = str(body.get("payee_id") or "")
    if not payer_id or not payee_id:
        return jsonify({"error": "PAYER_ID_AND_PAYEE_ID_REQUIRED"}), 400

    expected = body.get("expected") or {}
    network = normalize_network(expected.get("network"))
    asset = normalize_asset(expected.get("asset"))
    address = normalize_address(network, expected.get("address"))
    validation_error = validate_expected(network, asset, address)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    policy = body.get("policy") or {}
    ownership_proof_required = bool(policy.get("ownership_proof_required", True))
    ttl_minutes = int(policy.get("ttl_minutes", DEFAULT_TTL_MINUTES))
    if ttl_minutes < 5 or ttl_minutes > 15:
        return jsonify({"error": "TTL_MINUTES_OUT_OF_RANGE", "allowed_range": [5, 15]}), 400

    request_id = f"req_{uuid.uuid4().hex[:12]}"
    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    created_at = now_utc()
    expires_at = created_at + timedelta(minutes=ttl_minutes)
    client_request_id = str(body.get("client_request_id") or "")
    metadata_json = json.dumps(body.get("metadata") or {}, ensure_ascii=False)
    expected_hash = compute_payload_hash({
        "order_id": order_id,
        "invoice_id": invoice_id,
        "payee_id": payee_id,
        "network": network,
        "asset": asset,
        "address": address,
    })

    conn = get_db()
    conn.execute(
        """
        INSERT INTO verification_requests (
            request_id, client_request_id, order_id, invoice_id, payer_id, payee_id,
            network, asset, address, ownership_proof_required, ttl_minutes,
            request_status, session_id, session_status, session_binding,
            created_at, session_expires_at, expected_payload_hash, metadata_json,
            idempotency_key_create
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            client_request_id,
            order_id,
            invoice_id,
            payer_id,
            payee_id,
            network,
            asset,
            address,
            1 if ownership_proof_required else 0,
            ttl_minutes,
            "pending_verification",
            session_id,
            "awaiting_payee_action",
            "single_use",
            iso_z(created_at),
            iso_z(expires_at),
            expected_hash,
            metadata_json,
            request.headers.get("Idempotency-Key"),
        ),
    )
    audit(conn, request_id, "verification_request_created", {"session_id": session_id})
    audit(conn, request_id, "verification_session_started", {"session_id": session_id})
    conn.commit()
    conn.close()

    return jsonify({
        "request_id": request_id,
        "status": "pending_verification",
        "verification_session": {
            "session_id": session_id,
            "status": "awaiting_payee_action",
            "expires_at": iso_z(expires_at),
            "session_binding": "single_use",
        },
        "verification_url": f"{BASE_URL}/verify/{session_id}",
        "expected_payload_hash": expected_hash,
        "created_at": iso_z(created_at),
    }), 201


@app.post("/v1/verification-sessions/<session_id>/complete")
def complete_session(session_id: str) -> Any:
    auth_error = require_auth()
    if auth_error:
        return auth_error
    idem_error = require_idempotency()
    if idem_error:
        return idem_error

    body = json_body()
    conn = get_db()
    row = conn.execute("SELECT * FROM verification_requests WHERE session_id = ?", (session_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "SESSION_NOT_FOUND"}), 404

    now = now_utc()
    if row["session_status"] == "consumed":
        conn.close()
        return jsonify({"status": "blocked", "reason_code": "SESSION_ALREADY_USED", "retry_allowed": False}), 409
    if now > parse_iso8601(row["session_expires_at"]):
        conn.execute(
            "UPDATE verification_requests SET request_status = ?, session_status = ? WHERE session_id = ?",
            ("expired", "expired", session_id),
        )
        audit(conn, row["request_id"], "session_expired", {"session_id": session_id})
        audit(conn, row["request_id"], "request_expired", {"session_id": session_id})
        conn.commit()
        conn.close()
        return jsonify({"status": "expired", "reason_code": "REQUEST_EXPIRED", "retry_allowed": False}), 410

    provided = body.get("provided") or {}
    provided_network = normalize_network(provided.get("network"))
    provided_asset = normalize_asset(provided.get("asset"))
    provided_address = normalize_address(provided_network, provided.get("address"))
    validation_error = validate_expected(provided_network, provided_asset, provided_address)
    if validation_error:
        conn.close()
        return jsonify({"error": validation_error}), 400

    ownership = body.get("ownership_proof") or {}
    ownership_method = str(ownership.get("method") or "wallet_signature")
    ownership_status = str(ownership.get("status") or "failed")
    ownership_proof_ref = str(ownership.get("proof_ref") or "")

    expected_triplet = {
        "network": row["network"],
        "asset": row["asset"],
        "address": row["address"],
    }
    provided_triplet = {
        "network": provided_network,
        "asset": provided_asset,
        "address": provided_address,
    }

    reason_code = "OK"
    retry_allowed = False
    next_action = "ALLOW_PAYOUT_IF_ARTIFACT_VALID"
    status = "verified"

    if bool(row["ownership_proof_required"]) and ownership_status != "verified":
        reason_code = "OWNERSHIP_PROOF_FAILED"
        status = "blocked"
        next_action = "BLOCK_AND_REVERIFY"
        retry_allowed = False
    elif provided_network != row["network"]:
        reason_code = "NETWORK_MISMATCH"
        status = "mismatch_detected"
        next_action = "BLOCK_AND_REVERIFY"
        retry_allowed = True
    elif provided_asset != row["asset"]:
        reason_code = "ASSET_MISMATCH"
        status = "mismatch_detected"
        next_action = "BLOCK_AND_REVERIFY"
        retry_allowed = True
    elif provided_address != row["address"]:
        reason_code = "ADDRESS_MISMATCH"
        status = "mismatch_detected"
        next_action = "BLOCK_AND_REVERIFY"
        retry_allowed = True

    conn.execute(
        """
        UPDATE verification_requests
        SET provided_network = ?, provided_asset = ?, provided_address = ?,
            ownership_method = ?, ownership_status = ?, ownership_proof_ref = ?,
            idempotency_key_complete = ?, completed_at = ?,
            request_status = ?, session_status = ?
        WHERE session_id = ?
        """,
        (
            provided_network,
            provided_asset,
            provided_address,
            ownership_method,
            ownership_status,
            ownership_proof_ref,
            request.headers.get("Idempotency-Key"),
            iso_z(now),
            status,
            "completed" if status == "verified" else row["session_status"],
            session_id,
        ),
    )

    if status == "verified":
        refreshed = conn.execute("SELECT * FROM verification_requests WHERE session_id = ?", (session_id,)).fetchone()
        artifact = build_artifact(refreshed)
        conn.execute(
            "UPDATE verification_requests SET artifact_json = ? WHERE session_id = ?",
            (json.dumps(artifact, ensure_ascii=False), session_id),
        )
        audit(conn, row["request_id"], "verification_session_completed", {"session_id": session_id, "status": status})
        audit(conn, row["request_id"], "artifact_issued", {"session_id": session_id, "reason_code": reason_code})
        conn.commit()
        conn.close()
        return jsonify({
            "status": "verified",
            "next_action": next_action,
            "artifact_id": f"art_{row['request_id']}",
            "artifact": artifact,
        })

    if status == "mismatch_detected":
        audit(conn, row["request_id"], "mismatch_detected", {"reason_code": reason_code, "session_id": session_id})
    elif status == "blocked":
        audit(conn, row["request_id"], "policy_blocked", {"reason_code": reason_code, "session_id": session_id})
    conn.commit()
    conn.close()

    return jsonify({
        "status": status,
        "next_action": next_action,
        "reason_code": reason_code,
        "retry_allowed": retry_allowed,
        "expected": expected_triplet,
        "provided": provided_triplet,
    })


@app.get("/v1/verification-requests/<request_id>/artifact")
def get_artifact(request_id: str) -> Any:
    auth_error = require_auth()
    if auth_error:
        return auth_error
    conn = get_db()
    row = conn.execute("SELECT * FROM verification_requests WHERE request_id = ?", (request_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "REQUEST_NOT_FOUND"}), 404
    if not row["artifact_json"]:
        conn.close()
        return jsonify({"error": "ARTIFACT_NOT_AVAILABLE", "status": row["request_status"]}), 409
    audit(conn, request_id, "artifact_fetched", {"request_id": request_id})
    conn.commit()
    artifact = json.loads(row["artifact_json"])
    conn.close()
    return jsonify({"request_id": request_id, "artifact": artifact})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
