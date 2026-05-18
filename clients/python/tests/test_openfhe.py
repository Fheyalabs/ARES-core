"""End-to-end tests for the Python OpenFHEHelper IPC client.

Builds the helper binary (-tags openfhe) on demand and exercises
keygen, encryption, the new decomposable primitives, and argmax
against real OpenFHE. Skipped if the helper can't be built (no
OpenFHE on PATH).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from ares_client.openfhe import (
    ContractParams,
    OpenFHEHelper,
    sharpen_indicator_degree3,
)


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    # tests/ → clients/python/ → ARES-core/
    return here.parent.parent.parent.parent


@pytest.fixture(scope="session")
def helper_binary() -> str:
    if shutil.which("go") is None:
        pytest.skip("go not on PATH")
    out_dir = Path(tempfile.mkdtemp(prefix="ares-helper-"))
    binary = out_dir / "openfhe-contract-helper"
    repo = _repo_root()
    proc = subprocess.run(
        ["go", "build", "-tags", "openfhe", "-o", str(binary),
         "./cmd/openfhe-contract-helper"],
        cwd=repo,
        capture_output=True,
    )
    if proc.returncode != 0:
        msg = proc.stderr.decode(errors="replace")
        pytest.skip(f"OpenFHE helper build failed (missing OpenFHE?): {msg[:300]}")
    yield str(binary)
    try:
        os.unlink(binary)
        os.rmdir(out_dir)
    except OSError:
        pass


@pytest.mark.asyncio
async def test_keygen_chain_two_party(helper_binary):
    params = ContractParams(ring_dim=8192, depth=4)
    async with OpenFHEHelper(helper_binary) as h:
        first = await h.keygen_first(params)
        assert first.public_key
        assert first.secret_key_share
        assert first.lead is True

        second = await h.keygen_next(params, first.public_key)
        assert second.public_key
        assert second.secret_key_share
        assert second.lead is False


@pytest.mark.asyncio
async def test_encrypt_partial_decrypt_fuse_roundtrip(helper_binary):
    params = ContractParams(ring_dim=8192, depth=4)
    values = [1.5, -2.0, 3.25, 0.5]
    async with OpenFHEHelper(helper_binary) as h:
        first = await h.keygen_first(params)
        second = await h.keygen_next(params, first.public_key)
        ct = await h.encrypt(params, second.public_key, values)
        p1 = await h.partial_decrypt(params, ct, first.secret_key_share, first.lead)
        p2 = await h.partial_decrypt(params, ct, second.secret_key_share, second.lead)
        recovered = await h.fuse_partials(params, [p1, p2], len(values))
        for i, want in enumerate(values):
            assert abs(recovered[i] - want) < 1e-2, f"slot {i}: {recovered[i]} vs {want}"


@pytest.mark.asyncio
async def test_argmax_picks_winner(helper_binary):
    """End-to-end argmax over three encrypted scalars driven entirely
    from Python. Builds the full N-party threshold keygen chain via the
    new combine_evalkey_round1 / combine_evalkey_round2 ops, encrypts
    three normalized scalar scores, runs argmax with the [0, 1]-
    indicator sharpening polynomial, threshold-decrypts each returned
    mask, and verifies the highest score wins.
    """
    params = ContractParams(ring_dim=8192, depth=10, scaling_mod_size=50)
    scores = [0.5, -0.3, 0.0]
    expected_winner = 0

    async with OpenFHEHelper(helper_binary) as h:
        shares, eval_keys = await h.run_full_keygen(params, n_participants=2)
        joint = shares[-1].public_key

        cts = []
        for s in scores:
            ct = await h.encrypt(params, joint, [s, 0.0, 0.0, 0.0])
            cts.append(ct)

        masks = await h.argmax(
            params, eval_keys.eval_mult_final, cts,
            sharpening_poly=sharpen_indicator_degree3(),
        )
        assert len(masks) == len(scores)

        # Threshold-decrypt every mask and pick the largest.
        mask_values: list[float] = []
        for m in masks:
            p1 = await h.partial_decrypt(params, m, shares[0].secret_key_share, shares[0].lead)
            p2 = await h.partial_decrypt(params, m, shares[1].secret_key_share, shares[1].lead)
            values = await h.fuse_partials(params, [p1, p2], n_slots=4)
            mask_values.append(values[0])

        winner_idx = max(range(len(mask_values)), key=lambda i: mask_values[i])
        assert winner_idx == expected_winner, (
            f"argmax picked {winner_idx} (mask={mask_values[winner_idx]}); "
            f"masks={mask_values}"
        )


@pytest.mark.asyncio
async def test_helper_propagates_op_errors(helper_binary):
    """Sending a malformed op should surface as HelperError, not a
    silent hang or process crash."""
    from ares_client.openfhe import HelperError
    params = ContractParams(ring_dim=8192, depth=4)
    async with OpenFHEHelper(helper_binary) as h:
        with pytest.raises(HelperError):
            # encrypt_profile with empty values should fail server-side.
            await h.encrypt(params, b"\x00", [])
