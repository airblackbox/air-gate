"""Tests for pluggable signers and asymmetric (Ed25519) audit chains."""

import pytest

from air_gate.events import EventStore, GateEvent
from air_gate.signing import HMACSigner, Ed25519Signer, build_signer

cryptography = pytest.importorskip("cryptography")


def _record(store, n=1):
    for i in range(n):
        store.record(GateEvent(agent_id="a", action_type="email", tool_name="send",
                               payload={"i": i}, result="pending"))


class TestHMACBackCompat:

    def test_default_is_hmac(self, tmp_path):
        store = EventStore(signing_key="k", storage_path=str(tmp_path / "c.jsonl"))
        _record(store)
        assert store.algorithm == "HMAC-SHA256"
        assert store.public_key_hex is None
        assert store.events[0].signature_algorithm == "HMAC-SHA256"
        assert store.verify_chain()["valid"] is True

    def test_hmac_content_excludes_algorithm_field(self, tmp_path):
        """Signed bytes must not include signature_algorithm (compat guarantee)."""
        store = EventStore(signing_key="k", storage_path=str(tmp_path / "c.jsonl"))
        _record(store)
        content = store._signed_content(store.events[0])
        assert b"signature_algorithm" not in content


class TestEd25519:

    def test_sign_and_verify(self, tmp_path):
        signer = Ed25519Signer.generate()
        store = EventStore(signer=signer, storage_path=str(tmp_path / "c.db"))
        _record(store, 3)
        assert store.algorithm == "Ed25519"
        assert store.verify_chain()["valid"] is True
        assert len(store.public_key_hex) == 64  # 32 bytes hex

    def test_verify_with_public_key_only(self, tmp_path):
        path = str(tmp_path / "c.db")
        signer = Ed25519Signer.generate()
        store = EventStore(signer=signer, storage_path=path)
        _record(store, 2)
        pub = signer.public_key_hex

        verifier = EventStore(signer=Ed25519Signer.from_public_hex(pub), storage_path=path)
        assert verifier.verify_chain()["valid"] is True
        assert verifier._signer.can_sign is False

    def test_public_only_cannot_forge(self, tmp_path):
        signer = Ed25519Signer.generate()
        verifier = Ed25519Signer.from_public_hex(signer.public_key_hex)
        store = EventStore(signer=verifier, storage_path=str(tmp_path / "c.db"))
        with pytest.raises(RuntimeError):
            store.record(GateEvent(agent_id="a", action_type="email", tool_name="send"))

    def test_wrong_public_key_fails(self, tmp_path):
        path = str(tmp_path / "c.db")
        store = EventStore(signer=Ed25519Signer.generate(), storage_path=path)
        _record(store)
        other = Ed25519Signer.generate().public_key_hex
        verifier = EventStore(signer=Ed25519Signer.from_public_hex(other), storage_path=path)
        assert verifier.verify_chain()["valid"] is False

    def test_tamper_detected(self, tmp_path):
        store = EventStore(signer=Ed25519Signer.generate(), storage_path=str(tmp_path / "c.db"))
        _record(store, 2)
        store.events[0].payload = {"tampered": True}
        assert store.verify_chain()["valid"] is False

    def test_algorithm_downgrade_detected(self, tmp_path):
        store = EventStore(signer=Ed25519Signer.generate(), storage_path=str(tmp_path / "c.db"))
        _record(store)
        store.events[0].signature_algorithm = "HMAC-SHA256"
        report = store.verify_chain()
        assert report["valid"] is False
        assert any("algorithm mismatch" in e for e in report["errors"])

    def test_hex_roundtrip(self):
        signer = Ed25519Signer.generate()
        reloaded = Ed25519Signer.from_private_hex(signer.private_key_hex)
        assert reloaded.public_key_hex == signer.public_key_hex


class TestBuildSigner:

    def test_default_hmac(self):
        assert build_signer(signing_key="k").algorithm == "HMAC-SHA256"

    def test_ed25519_requires_key(self):
        with pytest.raises(ValueError):
            build_signer(algorithm="Ed25519")

    def test_unknown_algorithm(self):
        with pytest.raises(ValueError):
            build_signer(signing_key="k", algorithm="RSA-9000")
