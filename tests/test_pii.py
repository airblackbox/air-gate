"""
tests/test_pii.py

Tests for gate.pii — PII detection, redaction, manifests, erasure reports,
and multi-vertical regulatory coverage.

Run with:  pytest tests/test_pii.py -v
"""

import hashlib
import re
import pytest

from gate.events import EventStore, GateEvent
from gate.pii import (
    DataRegion,
    LawfulBasis,
    PIICategory,
    PIIManifest,
    PIIDetection,
    PIIRedactionPolicy,
    PIIRedactor,
    RedactionMethod,
    RegulatoryVertical,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fresh_store() -> EventStore:
    store = EventStore(signing_key="test-pii-key", storage_path="/tmp/test_pii_events.jsonl")
    store.events = []  # always start clean
    return store


def _policy(store=None, **kwargs) -> PIIRedactionPolicy:
    if store is None:
        store = _fresh_store()
    return PIIRedactionPolicy(
        store,
        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# PIIRedactor — string pattern tests
# ---------------------------------------------------------------------------

class TestPIIRedactorPatterns:

    def setup_method(self):
        self.redactor = PIIRedactor(method=RedactionMethod.HASH_SHA256)

    def test_detects_email(self):
        text, detections = self.redactor.redact("Contact jane@example.com today")
        assert any(d.category == PIICategory.EMAIL.value for d in detections)
        assert "jane@example.com" not in text
        assert "[REDACTED:sha256:" in text

    def test_detects_phone_us(self):
        text, detections = self.redactor.redact("Call me at 415-555-0192")
        assert any(d.category == PIICategory.PHONE.value for d in detections)
        assert "415-555-0192" not in text

    def test_detects_ssn(self):
        text, detections = self.redactor.redact("SSN: 123-45-6789")
        assert any(d.category == PIICategory.SSN.value for d in detections)
        assert "123-45-6789" not in text

    def test_detects_linkedin_url(self):
        text, detections = self.redactor.redact("Profile: linkedin.com/in/janesmith")
        assert any(d.category == PIICategory.LINKEDIN_URL.value for d in detections)
        assert "linkedin.com/in/janesmith" not in text

    def test_detects_ip_address(self):
        text, detections = self.redactor.redact("Request from 192.168.1.100")
        assert any(d.category == PIICategory.IP_ADDRESS.value for d in detections)

    def test_detects_protected_characteristic(self):
        text, detections = self.redactor.redact("Looking for native speaker, age 30")
        assert any(d.category == PIICategory.PROTECTED_CHAR.value for d in detections)

    def test_detects_credit_card(self):
        text, detections = self.redactor.redact("Card: 4111111111111111")
        assert any(d.category == PIICategory.CREDIT_CARD.value for d in detections)
        assert "4111111111111111" not in text

    def test_detects_ssn_as_tin(self):
        _, detections = self.redactor.redact("SSN on file: 987-65-4321")
        assert any(d.category == PIICategory.SSN.value for d in detections)

    def test_detects_medical_record_number(self):
        _, detections = self.redactor.redact("MRN: AB123456 admitted today")
        assert any(d.category == PIICategory.MEDICAL_RECORD_NUMBER.value for d in detections)

    def test_detects_case_number(self):
        _, detections = self.redactor.redact("Case #2024-CV-00123 is active")
        assert any(d.category == PIICategory.CASE_NUMBER.value for d in detections)

    def test_multiple_pii_types_in_one_string(self):
        text, detections = self.redactor.redact(
            "jane@example.com | 415-555-0192 | linkedin.com/in/janesmith"
        )
        categories = {d.category for d in detections}
        assert PIICategory.EMAIL.value in categories
        assert PIICategory.LINKEDIN_URL.value in categories

    def test_no_false_positive_on_clean_text(self):
        text, detections = self.redactor.redact(
            "Candidate has strong Python skills and 5 years experience."
        )
        assert detections == []
        assert "[REDACTED" not in text

    def test_original_hash_matches_raw_value(self):
        raw_email = "jane@example.com"
        _, detections = self.redactor.redact(f"Email: {raw_email}")
        assert len(detections) >= 1
        email_detection = next(d for d in detections if d.category == PIICategory.EMAIL.value)
        assert email_detection.original_hash == sha256(raw_email)


# ---------------------------------------------------------------------------
# PIIRedactor — dict / nested structure tests
# ---------------------------------------------------------------------------

class TestPIIRedactorDict:

    def setup_method(self):
        self.redactor = PIIRedactor(method=RedactionMethod.HASH_SHA256)

    def test_redacts_sensitive_key_email(self):
        payload = {"email": "jane@example.com", "role": "Engineer"}
        result, detections = self.redactor.redact(payload)
        assert result["email"] != "jane@example.com"
        assert "[REDACTED" in result["email"]
        assert result["role"] == "Engineer"

    def test_redacts_sensitive_key_phone(self):
        payload = {"phone": "415-555-0192"}
        result, _ = self.redactor.redact(payload)
        assert result["phone"] != "415-555-0192"

    def test_redacts_nested_dict(self):
        payload = {
            "candidate": {
                "name": "Jane Smith",
                "email": "jane@example.com",
            },
            "job_id": "eng-042",
        }
        result, detections = self.redactor.redact(payload)
        assert "[REDACTED" in result["candidate"]["email"]
        assert result["job_id"] == "eng-042"

    def test_redacts_items_in_list(self):
        payload = {"emails": ["a@example.com", "b@example.com"]}
        result, _ = self.redactor.redact(payload)
        for item in result["emails"]:
            assert "[REDACTED" in item

    def test_field_path_tracking(self):
        payload = {"candidate": {"email": "jane@example.com"}}
        _, detections = self.redactor.redact(payload)
        paths = {d.field_path for d in detections}
        assert any("candidate" in p for p in paths)

    def test_non_string_values_unchanged(self):
        payload = {"score": 95, "active": True, "tags": None}
        result, detections = self.redactor.redact(payload)
        assert result["score"] == 95
        assert result["active"] is True
        assert result["tags"] is None
        assert detections == []

    # Finance vertical
    def test_redacts_credit_card_key(self):
        payload = {"credit_card": "4111111111111111", "amount": 100}
        result, detections = self.redactor.redact(payload)
        assert "4111111111111111" not in result["credit_card"]
        assert result["amount"] == 100

    def test_redacts_bank_account_key(self):
        payload = {"bank_account": "00123456789", "bank": "Chase"}
        result, detections = self.redactor.redact(payload)
        assert "[REDACTED" in result["bank_account"]

    # Healthcare vertical
    def test_redacts_mrn_key(self):
        payload = {"mrn": "MRN-7890123", "ward": "3B"}
        result, _ = self.redactor.redact(payload)
        assert "[REDACTED" in result["mrn"]
        assert result["ward"] == "3B"

    def test_redacts_patient_id_key(self):
        payload = {"patient_id": "PAT-001234"}
        result, _ = self.redactor.redact(payload)
        assert "[REDACTED" in result["patient_id"]

    # Legal vertical
    def test_redacts_case_number_key(self):
        payload = {"case_number": "2024-CV-00999", "attorney": "Smith LLP"}
        result, _ = self.redactor.redact(payload)
        assert "[REDACTED" in result["case_number"]

    def test_redacts_bar_number_key(self):
        payload = {"bar_number": "CA98765"}
        result, _ = self.redactor.redact(payload)
        assert "[REDACTED" in result["bar_number"]


# ---------------------------------------------------------------------------
# Redaction method tests
# ---------------------------------------------------------------------------

class TestRedactionMethods:

    def test_mask_method(self):
        redactor = PIIRedactor(method=RedactionMethod.MASK)
        text, _ = redactor.redact("jane@example.com")
        assert text == "***"

    def test_remove_method(self):
        redactor = PIIRedactor(method=RedactionMethod.REMOVE)
        text, _ = redactor.redact("jane@example.com")
        assert text == "[REMOVED]"

    def test_tokenise_method(self):
        redactor = PIIRedactor(method=RedactionMethod.TOKENISE)
        text, _ = redactor.redact("jane@example.com")
        assert text.startswith("tok_")

    def test_tokenise_stable(self):
        """Same input must produce the same token."""
        redactor = PIIRedactor(method=RedactionMethod.TOKENISE)
        t1, _ = redactor.redact("jane@example.com")
        t2, _ = redactor.redact("jane@example.com")
        assert t1 == t2


# ---------------------------------------------------------------------------
# PIIManifest tests
# ---------------------------------------------------------------------------

class TestPIIManifest:

    def test_categories_deduplicated(self):
        manifest = PIIManifest(
            lawful_basis=LawfulBasis.CONSENT.value,
            detections=[
                PIIDetection("email", "email", "hash_sha256", "aaa"),
                PIIDetection("email", "body", "hash_sha256", "bbb"),
                PIIDetection("phone", "phone", "hash_sha256", "ccc"),
            ],
        )
        cats = manifest.categories_detected
        assert cats.count("email") == 1
        assert "phone" in cats

    def test_erasure_hashes(self):
        manifest = PIIManifest(
            lawful_basis=LawfulBasis.CONTRACT.value,
            detections=[
                PIIDetection("email", "email", "hash_sha256", "hash_aaa"),
                PIIDetection("phone", "phone", "hash_sha256", "hash_bbb"),
            ],
        )
        assert manifest.erasure_hashes == ["hash_aaa", "hash_bbb"]

    def test_to_dict_required_keys(self):
        manifest = PIIManifest(lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS.value)
        d = manifest.to_dict()
        required = {
            "lawful_basis", "categories_detected", "detections",
            "data_subject_regions", "cross_border_transfer",
            "transfer_safeguard", "retention_days", "erasure_eligible",
            "pii_count", "vertical",
        }
        assert required.issubset(d.keys())


# ---------------------------------------------------------------------------
# PIIRedactionPolicy integration tests
# ---------------------------------------------------------------------------

class TestPIIRedactionPolicy:

    def test_record_redacts_email_in_payload(self):
        policy = _policy()
        policy.record(
            agent_id="sourcing-agent",
            action_type="email",
            tool_name="send_email",
            payload={"email": "jane@example.com", "role": "Engineer"},
        )
        event = policy.store.events[0]
        assert event.payload["email"] != "jane@example.com"
        assert "[REDACTED" in event.payload["email"]

    def test_pii_manifest_embedded_in_payload(self):
        policy = _policy()
        policy.record(
            agent_id="sourcing-agent",
            action_type="email",
            tool_name="send_email",
            payload={"email": "jane@example.com"},
        )
        event = policy.store.events[0]
        assert "_pii_manifest" in event.payload
        manifest = event.payload["_pii_manifest"]
        assert manifest["lawful_basis"] == LawfulBasis.LEGITIMATE_INTERESTS.value
        assert "email" in manifest["categories_detected"]

    def test_chain_still_verifies_after_redaction(self):
        policy = _policy()
        for i in range(3):
            policy.record(
                agent_id="sales-agent",
                action_type="email",
                tool_name="send_email",
                payload={"to": f"prospect{i}@company.com", "subject": "Hello"},
            )
        result = policy.verify_chain()
        assert result["valid"] is True
        assert result["events_checked"] == 3

    def test_cross_border_transfer_recorded(self):
        store = _fresh_store()
        policy = PIIRedactionPolicy(
            store,
            lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
            cross_border_transfer=True,
            transfer_safeguard="SCCs",
            data_subject_regions=[DataRegion.EU],
        )
        policy.record(
            agent_id="screening-agent",
            action_type="llm_call",
            tool_name="openai",
            payload={"resume": "Jane Smith, Berlin. jane@example.de"},
        )
        manifest = policy.store.events[0].payload["_pii_manifest"]
        assert manifest["cross_border_transfer"] is True
        assert manifest["transfer_safeguard"] == "SCCs"
        assert "EU" in manifest["data_subject_regions"]

    def test_block_on_missing_lawful_basis(self):
        store = _fresh_store()
        policy = PIIRedactionPolicy(
            store,
            lawful_basis=LawfulBasis.NOT_SPECIFIED,
            block_on_missing_lawful_basis=True,
        )
        policy.record(
            agent_id="agent",
            action_type="resume_parse",
            tool_name="parser",
            payload={"email": "jane@example.com"},
            result="approved",
        )
        event = store.events[0]
        assert event.result == "blocked"

    def test_erasure_report_finds_affected_events(self):
        policy = _policy()
        target_email = "target@example.com"
        other_email = "other@example.com"

        policy.record("agent", "email", "send", {"email": target_email})
        policy.record("agent", "email", "send", {"email": other_email})
        policy.record("agent", "email", "send", {"email": target_email})

        target_hash = sha256(target_email)
        report = policy.erasure_report(target_hash)

        assert len(report) == 2
        for entry in report:
            assert entry["action_type"] == "email"

    def test_erasure_report_empty_for_unknown_hash(self):
        policy = _policy()
        policy.record("agent", "action", "tool", {"email": "a@b.com"})
        report = policy.erasure_report("0" * 64)
        assert report == []

    def test_non_pii_result_preserved(self):
        policy = _policy()
        policy.record(
            agent_id="agent",
            action_type="search",
            tool_name="find",
            payload={"query": "python developer", "location": "remote"},
            result="auto_allowed",
        )
        event = policy.store.events[0]
        assert event.result == "auto_allowed"
        assert event.payload.get("query") == "python developer"


# ---------------------------------------------------------------------------
# Vertical-specific integration tests
# ---------------------------------------------------------------------------

class TestRecruitingVertical:

    def test_resume_full_scenario(self):
        policy = _policy(vertical=RegulatoryVertical.RECRUITING, retention_days=90)
        policy.record(
            agent_id="ats-agent",
            action_type="resume_ingest",
            tool_name="parser",
            payload={
                "email": "jane.smith@gmail.com",
                "phone": "415-555-0192",
                "linkedin": "linkedin.com/in/janesmith",
                "resume_text": (
                    "Jane Smith | jane.smith@gmail.com | 415-555-0192\n"
                    "linkedin.com/in/janesmith\n"
                    "5 years Python experience."
                ),
                "job_id": "eng-042",
            },
        )
        event = policy.store.events[0]
        payload = event.payload

        # Raw PII must not appear anywhere
        assert "jane.smith@gmail.com" not in str(payload)
        assert "415-555-0192" not in str(payload)
        assert "linkedin.com/in/janesmith" not in str(payload)

        # Non-PII fields intact
        assert payload["job_id"] == "eng-042"

        # Manifest records all categories
        cats = payload["_pii_manifest"]["categories_detected"]
        assert "email" in cats
        assert "phone" in cats
        assert "linkedin_url" in cats or "resume_text" in cats

        # Chain valid
        assert policy.verify_chain()["valid"] is True


class TestFinanceVertical:

    def test_payment_record_redacts_card_and_account(self):
        policy = _policy(vertical=RegulatoryVertical.FINANCE)
        policy.record(
            agent_id="billing-agent",
            action_type="payment",
            tool_name="stripe",
            payload={
                "credit_card": "4111111111111111",
                "bank_account": "00123456789",
                "routing_number": "021000021",
                "amount": 2500,
                "currency": "USD",
            },
        )
        event = policy.store.events[0]
        p = event.payload
        assert "4111111111111111" not in str(p)
        assert "00123456789" not in str(p)
        assert p["amount"] == 2500  # non-PII intact
        cats = p["_pii_manifest"]["categories_detected"]
        assert "credit_card" in cats or "account_number" in cats

    def test_tax_id_redacted(self):
        policy = _policy(vertical=RegulatoryVertical.FINANCE)
        policy.record(
            agent_id="payroll-agent",
            action_type="tax_filing",
            tool_name="irs_api",
            payload={"tax_id": "12-3456789", "fiscal_year": 2025},
        )
        event = policy.store.events[0]
        assert "12-3456789" not in str(event.payload)


class TestHealthcareVertical:

    def test_hipaa_phi_redacted(self):
        policy = _policy(vertical=RegulatoryVertical.HEALTHCARE, retention_days=365)
        policy.record(
            agent_id="ehr-agent",
            action_type="record_access",
            tool_name="ehr_api",
            payload={
                "mrn": "MRN-0012345",
                "patient_id": "PAT-98765",
                "email": "patient@hospital.org",
                "phone": "212-555-7890",
                "diagnosis": "J18.9",
                "ward": "ICU-3",
            },
        )
        event = policy.store.events[0]
        p = event.payload
        assert "MRN-0012345" not in str(p)
        assert "patient@hospital.org" not in str(p)
        assert p["ward"] == "ICU-3"  # non-PII intact
        cats = p["_pii_manifest"]["categories_detected"]
        assert "medical_record_number" in cats or "email" in cats


class TestLegalVertical:

    def test_legal_pii_redacted(self):
        policy = _policy(vertical=RegulatoryVertical.LEGAL)
        policy.record(
            agent_id="legal-agent",
            action_type="document_access",
            tool_name="dms",
            payload={
                "case_number": "2024-CV-00999",
                "bar_number": "CA12345",
                "client_matter": "Smith v. Corp / 2024-001",
                "attorney_email": "counsel@lawfirm.com",
                "motion_type": "Summary Judgment",
            },
        )
        event = policy.store.events[0]
        p = event.payload
        assert "2024-CV-00999" not in str(p)
        assert "CA12345" not in str(p)
        assert p["motion_type"] == "Summary Judgment"


# ---------------------------------------------------------------------------
# Custom pattern tests
# ---------------------------------------------------------------------------

class TestCustomPatterns:

    def test_custom_employee_id_detected(self):
        store = _fresh_store()
        policy = PIIRedactionPolicy(
            store,
            lawful_basis=LawfulBasis.CONTRACT,
            custom_patterns={"employee_id": re.compile(r'\bEMP-\d{6}\b')},
        )
        policy.record(
            agent_id="hr-agent",
            action_type="hr_lookup",
            tool_name="hris",
            payload={"body": "Employee EMP-123456 submitted a request."},
        )
        event = store.events[0]
        assert "EMP-123456" not in str(event.payload)
        cats = event.payload["_pii_manifest"]["categories_detected"]
        assert "employee_id" in cats


# ---------------------------------------------------------------------------
# Compliance summary tests
# ---------------------------------------------------------------------------

class TestComplianceSummary:

    def test_summary_structure(self):
        policy = _policy(vertical=RegulatoryVertical.RECRUITING)
        policy.record("agent", "email", "send", {"email": "a@b.com"})
        policy.record("agent", "email", "send", {"email": "c@d.com"})
        summary = policy.compliance_summary()
        assert summary["total_events"] == 2
        assert summary["chain_valid"] is True
        assert "email" in summary["pii_by_category"]
        assert summary["total_pii_detections"] >= 2

    def test_summary_chain_invalid_after_tamper(self):
        policy = _policy()
        policy.record("agent", "action", "tool", {"email": "x@y.com"})
        # Tamper
        policy.store.events[0].payload["extra"] = "injected"
        summary = policy.compliance_summary()
        assert summary["chain_valid"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
