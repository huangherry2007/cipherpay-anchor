#!/usr/bin/env bash
set -euo pipefail

# generateProof.sh
# Usage:
#   ./scripts/generateProof.sh [input_json] [proof_json] [public_json]
# Defaults:
#   input_json  -> proofs/input_deposit.json
#   proof_json  -> proofs/deposit_proof.json
#   public_json -> proofs/deposit_public.json
#
# This script tries fullprove first. If it fails (e.g., WASM LinkError),
# it falls back to: witness -> prove -> verify.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROOFS_DIR="$PROJECT_DIR/proofs"

INPUT_JSON="${1:-$PROOFS_DIR/input_deposit.json}"
PROOF_JSON="${2:-$PROOFS_DIR/deposit_proof.json}"
PUBLIC_JSON="${3:-$PROOFS_DIR/deposit_public.json}"
VKEY_JSON="$PROOFS_DIR/vkey_deposit.json"
WITNESS_WTNS="$PROOFS_DIR/witness_deposit.wtns"
PROOF_BIN="$PROOFS_DIR/deposit_proof.bin"
PUBLIC_BIN="$PROOFS_DIR/deposit_public_inputs.bin"

WASM="$PROJECT_DIR/../cipherpay-circuits/build/deposit/deposit_js/deposit.wasm"
WITNESS_JS="$PROJECT_DIR/../cipherpay-circuits/build/deposit/deposit_js/generate_witness.js"
ZKEY="$PROJECT_DIR/../cipherpay-circuits/build/deposit/deposit.zkey"

# Helpers
function info() { echo -e "[INFO]  $*"; }
function warn() { echo -e "[WARN]  $*"; }
function err()  { echo -e "[ERROR] $*" 1>&2; }

# Preflight checks
if [[ ! -f "$INPUT_JSON" ]]; then
  err "Input JSON not found: $INPUT_JSON"; exit 1;
fi
if [[ ! -f "$WASM" ]]; then
  err "WASM not found: $WASM"; exit 1;
fi
if [[ ! -f "$ZKEY" ]]; then
  err "ZKey not found: $ZKEY"; exit 1;
fi
if [[ ! -f "$WITNESS_JS" ]]; then
  err "Witness generator not found: $WITNESS_JS"; exit 1;
fi

info "Node: $(node -v 2>/dev/null || echo 'unknown')"
info "snarkjs: $(npx snarkjs --version 2>/dev/null | head -n1 || echo 'unknown')"
info "Input:  $INPUT_JSON"
info "WASM:   $WASM"
info "ZKEY:   $ZKEY"

mkdir -p "$PROOFS_DIR"

# Try fullprove first
FULLPROVE_OK=false
info "Attempting fullprove..."
if npx snarkjs groth16 fullprove "$INPUT_JSON" "$WASM" "$ZKEY" "$PROOF_JSON" "$PUBLIC_JSON"; then
  FULLPROVE_OK=true
  info "fullprove succeeded"
else
  warn "fullprove failed; falling back to split flow (witness -> prove)"
fi

# Fallback to split flow if needed
if [[ "$FULLPROVE_OK" != "true" ]]; then
  info "Calculating witness..."
  node "$WITNESS_JS" "$WASM" "$INPUT_JSON" "$WITNESS_WTNS"

  info "Proving..."
  npx snarkjs groth16 prove "$ZKEY" "$WITNESS_WTNS" "$PROOF_JSON" "$PUBLIC_JSON"
fi

# Always export verification key before verify
info "Exporting verification key..."
npx snarkjs zkey export verificationkey "$ZKEY" "$VKEY_JSON"

# Verify proof
info "Verifying proof..."
npx snarkjs groth16 verify "$VKEY_JSON" "$PUBLIC_JSON" "$PROOF_JSON"
info "Verification OK"

# Emit binary artifacts (simple JSON->bytes for now)
if [[ -f "$PROOF_JSON" ]]; then
  info "Converting proof JSON -> BIN: $(basename "$PROOF_JSON") -> $(basename "$PROOF_BIN")"
  node "$SCRIPT_DIR/toBytes.js" "$PROOF_JSON" "$PROOF_BIN"
fi
if [[ -f "$PUBLIC_JSON" ]]; then
  info "Converting public JSON -> BIN: $(basename "$PUBLIC_JSON") -> $(basename "$PUBLIC_BIN")"
  node "$SCRIPT_DIR/toBytes.js" "$PUBLIC_JSON" "$PUBLIC_BIN"
fi

info "Done. Outputs:"
info "  Proof JSON:   $PROOF_JSON"
info "  Public JSON:  $PUBLIC_JSON"
info "  VKey JSON:    $VKEY_JSON"
info "  Witness:      $WITNESS_WTNS"
info "  Proof BIN:    $PROOF_BIN"
info "  Public BIN:   $PUBLIC_BIN"
