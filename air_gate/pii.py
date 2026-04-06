"""
gate/pii.py

PII detection, redaction, and GDPR/HIPAA/PCI-DSS/EEOC audit manifests
for the AIR Gate tamper-evident event chain.

Regulatory verticals covered:
  Outbound email / recruiting  — GDPR Art. 6/17/25/30, CAN-SPAM, CASL, EEOC
  Finance                      — PCI-DSS, SOX (Sarbanes-Oxley)
  Healthcare                   — HIPAA, HITECH (18 PHI identifiers)
  Legal                        — Attorney-client privilege, bar regulations
  General data subjects        — CCPA/CPRA, PIPEDA

Usage::

    from air_gate.events import EventStore
    from air_gate.pii import PIIRedactionPolicy, LawfulBasis, DataRegion

    store = EventStore(signing_key="...")
    policy = PIIRedactionPolicy(
        store,
        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
        data_subject_regions=[DataRegion.EU, DataRegion.US],
        vertical="recruiting",
    )

    policy.record(
        agent_id="sourcing-agent",
        action_type="email",
        tool_name="send_email",
        payload={"to": "jane@example.com", "body": "Hi Jane, ..."},
        result="approved",
    )

    # GDPR Art. 17 erasure support
    report = policy.erasure_report("sha256_hash_of_target_email")
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from air_gate.events import EventStore, GateEvent


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PIICategory(str, Enum):
    # Universal
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    POSTAL_ADDRESS = "postal_address"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    NATIONAL_ID = "national_id"
    PROTECTED_CHAR = "protected_characteristic"  # age, race, religion, etc.

    # Recruiting / outbound email
    LINKEDIN_URL = "linkedin_url"
    RESUME_TEXT = "resume_text"

    # Finance (PCI-DSS)
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    ROUTING_NUMBER = "routing_number"
    TAX_ID = "tax_id"        # EIN, ITIN, SSN-as-TIN
    SSN = "ssn"

    # Healthcare (HIPAA 18 PHI identifiers — aggregated into categories)
    MEDICAL_RECORD_NUMBER = "medical_record_number"
    HEALTH_PLAN_NUMBER = "health_plan_number"
    DEVICE_SERIAL = "device_serial"
    BIOMETRIC = "biometric"
    ACCOUNT_NUMBER = "account_number"

    # Legal
    CASE_NUMBER = "case_number"
    BAR_NUMBER = "bar_number"

    # Custom / catch-all
    CUSTOM = "custom"


class LawfulBasis(str, Enum):
    """GDPR Article 6 lawful bases for processing personal data."""
    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTERESTS = "vital_interests"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTERESTS = "legitimate_interests"
    NOT_APPLICABLE = "not_applicable"
    NOT_SPECIFIED = "not_specified"


class RedactionMethod(str, Enum):
    HASH_SHA256 = "hash_sha256"   # [REDACTED:sha256:<first16>]  — default
    MASK = "mask"                  # ***
    REMOVE = "remove"              # [REMOVED]
    TOKENISE = "tokenise"          # tok_<uuid>


class DataRegion(str, Enum):
    """Jurisdiction of data subjects (for cross-border transfer tracking)."""
    EU = "EU"
    UK = "UK"
    CA = "CA"     # Canada (PIPEDA)
    US = "US"
    AU = "AU"
    UNKNOWN = "UNKNOWN"


class RegulatoryVertical(str, Enum):
    RECRUITING = "recruiting"
    OUTBOUND_EMAIL = "outbound_email"
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    LEGAL = "legal"
    GENERAL = "general"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PIIDetection:
    """One instance of PII detected and redacted."""
    category: str          # PIICategory value
    field_path: str        # e.g. "payload.email" or "payload.body"
    redaction_method: str  # RedactionMethod value
    original_hash: str     # SHA-256 of the raw PII value (for erasure cascade)


@dataclass
class PIIManifest:
    """
    GDPR Article 30 Record of Processing Activities (RoPA) embedded per event.
    Also used to satisfy HIPAA minimum-necessary and PCI-DSS logging requirements.
    """
    lawful_basis: str
    vertical: str = RegulatoryVertical.GENERAL.value
    detections: List[PIIDetection] = field(default_factory=list)
    data_subject_regions: List[str] = field(default_factory=list)
    cross_border_transfer: bool = False
    transfer_safeguard: Optional[str] = None   # e.g. "SCCs", "BCRs", "adequacy"
    retention_days: Optional[int] = None
    erasure_eligible: bool = True

    @property
    def categories_detected(self) -> List[str]:
        """Deduplicated list of PII category strings found."""
        seen = []
        for d in self.detections:
            if d.category not in seen:
                seen.append(d.category)
        return seen

    @property
    def erasure_hashes(self) -> List[str]:
        """All original_hash values — used for GDPR Art. 17 cascade lookup."""
        return [d.original_hash for d in self.detections]

    def to_dict(self) -> dict:
        return {
            "lawful_basis": self.lawful_basis,
            "vertical": self.vertical,
            "categories_detected": self.categories_detected,
            "detections": [
                {
                    "category": d.category,
                    "field_path": d.field_path,
                    "redaction_method": d.redaction_method,
                    "original_hash": d.original_hash,
                }
                for d in self.detections
            ],
            "data_subject_regions": self.data_subject_regions,
            "cross_border_transfer": self.cross_border_transfer,
            "transfer_safeguard": self.transfer_safeguard,
            "retention_days": self.retention_days,
            "erasure_eligible": self.erasure_eligible,
            "pii_count": len(self.detections),
        }


# ---------------------------------------------------------------------------
# Regex pattern library (multi-vertical)
# ---------------------------------------------------------------------------

_PATTERNS: List[Tuple[PIICategory, re.Pattern]] = [
    # ── Universal ───────────────────────────────────────────────────────
    (PIICategory.EMAIL,
     re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
    (PIICategory.PHONE,
     re.compile(
         r'\b(?:\+1[\s\-]?)?'
         r'(?:\(?\d{3}\)?[\s\-]?)\d{3}[\s\-]?\d{4}\b'
         r'|'
         r'\+\d{1,3}[\s\-]?\d{6,14}\b'
     )),
    (PIICategory.IP_ADDRESS,
     re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    (PIICategory.DATE_OF_BIRTH,
     re.compile(
         r'\b(?:dob|date of birth|born)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b',
         re.IGNORECASE,
     )),
    (PIICategory.PASSPORT,
     re.compile(r'\b[A-Z]{1,2}\d{6,9}\b')),

    # Protected characteristics (EEOC / EU Art. 9 sensitive)
    (PIICategory.PROTECTED_CHAR,
     re.compile(
         r'\b(?:age[d]?\s+\d+|native speaker|religion|race|ethnicity|'
         r'disability|pregnant|maternity|gender|sexual orientation|'
         r'national origin)\b',
         re.IGNORECASE,
     )),

    # ── Recruiting / outbound email ─────────────────────────────────────
    (PIICategory.LINKEDIN_URL,
     re.compile(r'(?:https?://)?(?:www\.)?linkedin\.com/in/[\w\-]+', re.IGNORECASE)),

    # ── Finance / PCI-DSS ───────────────────────────────────────────────
    # Credit card (Luhn-valid detection is expensive; use structural pattern)
    (PIICategory.CREDIT_CARD,
     re.compile(
         r'\b(?:4\d{12}(?:\d{3})?'          # Visa
         r'|5[1-5]\d{14}'                    # MC
         r'|3[47]\d{13}'                     # Amex
         r'|6(?:011|5\d{2})\d{12})\b'        # Discover
     )),
    (PIICategory.BANK_ACCOUNT,
     re.compile(r'\baccount[\s#:]+\d{6,17}\b', re.IGNORECASE)),
    (PIICategory.ROUTING_NUMBER,
     re.compile(r'\b(?:routing|ABA|RTN)[\s#:]+\d{9}\b', re.IGNORECASE)),
    (PIICategory.TAX_ID,
     re.compile(r'\b(?:EIN|ITIN)[\s:]+\d{2}-\d{7}\b', re.IGNORECASE)),
    # SSN (also used as TIN)
    (PIICategory.SSN,
     re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),

    # ── Healthcare / HIPAA ──────────────────────────────────────────────
    (PIICategory.MEDICAL_RECORD_NUMBER,
     re.compile(r'\b(?:MRN|medical record|patient id)[\s#:]+\w{4,12}\b', re.IGNORECASE)),
    (PIICategory.HEALTH_PLAN_NUMBER,
     re.compile(r'\b(?:member id|plan id|NPI|insurance id)[\s#:]+\w{5,15}\b', re.IGNORECASE)),

    # ── Legal ───────────────────────────────────────────────────────────
    (PIICategory.CASE_NUMBER,
     re.compile(r'\b(?:case|docket|matter)[\s#:]+[\w\-\/]{4,20}\b', re.IGNORECASE)),
    (PIICategory.BAR_NUMBER,
     re.compile(r'\b(?:bar|attorney)[\s#:]+\d{4,8}\b', re.IGNORECASE)),
]

# Sensitive dict keys that trigger redaction regardless of pattern match
_SENSITIVE_KEYS = {
    # universal
    "email", "phone", "mobile", "cell", "fax",
    "address", "street", "city", "zip", "postal_code",
    "dob", "birth_date", "birthdate", "ssn", "national_id", "passport",
    "ip", "ip_address",
    # recruiting
    "linkedin", "linkedin_url", "resume", "resume_text", "cv",
    # finance
    "credit_card", "card_number", "pan", "cvv", "cvc", "expiry",
    "account_number", "routing_number", "bank_account",
    "tax_id", "ein", "itin",
    # healthcare
    "mrn", "medical_record", "patient_id", "npi", "health_plan",
    "diagnosis", "icd_code", "medication",
    # legal
    "case_number", "docket", "bar_number", "client_matter",
}


# ---------------------------------------------------------------------------
# PIIRedactor
# ---------------------------------------------------------------------------

class PIIRedactor:
    """
    Scans strings and dicts for PII and redacts in-place.

    Parameters
    ----------
    method : RedactionMethod
        How to replace detected PII.
    custom_patterns : dict[str, re.Pattern], optional
        Additional patterns keyed by category name.
    """

    def __init__(
        self,
        method: RedactionMethod = RedactionMethod.HASH_SHA256,
        custom_patterns: Optional[Dict[str, re.Pattern]] = None,
    ):
        self.method = method
        self._custom: Dict[str, re.Pattern] = custom_patterns or {}
        self._token_cache: Dict[str, str] = {}

    # ── Public API ──────────────────────────────────────────────────────

    def redact(
        self,
        value: Any,
        field_path: str = "payload",
    ) -> Tuple[Any, List[PIIDetection]]:
        """
        Recursively scan and redact PII from *value*.

        Returns
        -------
        (redacted_value, detections)
        """
        if isinstance(value, str):
            return self._scan_string(value, field_path)
        if isinstance(value, dict):
            return self._scan_dict(value, field_path)
        if isinstance(value, list):
            return self._scan_list(value, field_path)
        return value, []

    # ── Internal scanners ───────────────────────────────────────────────

    def _scan_string(self, text: str, path: str) -> Tuple[str, List[PIIDetection]]:
        """
        Scan *text* for all PII patterns, then apply non-overlapping replacements
        from right-to-left so that span positions remain valid.

        Collecting all matches on the original text before any replacement prevents
        earlier (more generic) patterns from consuming tokens that belong to later
        (more specific) patterns (e.g. passport regex eating an MRN value).
        """
        # Collect (start, end, raw, category_str) across all patterns
        all_matches: List[Tuple[int, int, str, str]] = []

        for category, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                all_matches.append(
                    (match.start(), match.end(), match.group(0), category.value)
                )

        for cat_name, pattern in self._custom.items():
            for match in pattern.finditer(text):
                all_matches.append(
                    (match.start(), match.end(), match.group(0), cat_name)
                )

        if not all_matches:
            return text, []

        # Sort by start position; on ties, prefer longer (more specific) match
        all_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

        # Greedily select non-overlapping matches
        selected: List[Tuple[int, int, str, str]] = []
        covered_end = -1
        for start, end, raw, cat in all_matches:
            if start >= covered_end:
                selected.append((start, end, raw, cat))
                covered_end = end

        # Build detections list
        detections: List[PIIDetection] = [
            PIIDetection(
                category=cat,
                field_path=path,
                redaction_method=self.method.value,
                original_hash=_sha256(raw),
            )
            for _, _, raw, cat in selected
        ]

        # Apply replacements right-to-left so earlier spans stay valid
        for start, end, raw, _ in reversed(selected):
            replacement = self._replace(raw)
            text = text[:start] + replacement + text[end:]

        return text, detections

    def _scan_dict(self, d: dict, path: str) -> Tuple[dict, List[PIIDetection]]:
        result = {}
        detections: List[PIIDetection] = []

        for k, v in d.items():
            child_path = f"{path}.{k}"

            if not isinstance(v, str):
                # Recurse for nested dicts/lists/etc.
                redacted_v, child_dets = self.redact(v, child_path)
                result[k] = redacted_v
                detections.extend(child_dets)
                continue

            # String value — check sensitive key first
            key_lower = k.lower().replace("-", "_")
            if key_lower in _SENSITIVE_KEYS:
                replacement = self._replace(v)
                category = _key_to_category(key_lower)
                detections.append(PIIDetection(
                    category=category,
                    field_path=child_path,
                    redaction_method=self.method.value,
                    original_hash=_sha256(v),
                ))
                result[k] = replacement
            else:
                # Pattern scan on the string value
                redacted_v, child_dets = self._scan_string(v, child_path)
                result[k] = redacted_v
                detections.extend(child_dets)

        return result, detections

    def _scan_list(self, lst: list, path: str) -> Tuple[list, List[PIIDetection]]:
        result = []
        detections: List[PIIDetection] = []
        for i, item in enumerate(lst):
            redacted_item, child_dets = self.redact(item, f"{path}[{i}]")
            result.append(redacted_item)
            detections.extend(child_dets)
        return result, detections

    # ── Replacement helpers ─────────────────────────────────────────────

    def _replace(self, raw: str) -> str:
        if self.method == RedactionMethod.HASH_SHA256:
            return f"[REDACTED:sha256:{_sha256(raw)[:16]}]"
        if self.method == RedactionMethod.MASK:
            return "***"
        if self.method == RedactionMethod.REMOVE:
            return "[REMOVED]"
        if self.method == RedactionMethod.TOKENISE:
            if raw not in self._token_cache:
                self._token_cache[raw] = f"tok_{uuid.uuid4().hex[:12]}"
            return self._token_cache[raw]
        return "[REDACTED]"


# ---------------------------------------------------------------------------
# PIIRedactionPolicy — wraps EventStore
# ---------------------------------------------------------------------------

class PIIRedactionPolicy:
    """
    Drop-in wrapper around EventStore that redacts PII from every payload
    before it reaches the HMAC chain, then embeds a GDPR/HIPAA/PCI manifest.

    Parameters
    ----------
    store : EventStore
        The underlying event store to delegate to.
    lawful_basis : LawfulBasis
        GDPR Art. 6 lawful basis for processing.
    vertical : RegulatoryVertical | str
        Regulatory context (recruiting, finance, healthcare, legal, general).
    redaction_method : RedactionMethod
        How PII values are replaced.
    data_subject_regions : list[DataRegion]
        Regions whose data subjects' data may appear (for cross-border tracking).
    cross_border_transfer : bool
        Whether data crosses jurisdictions.
    transfer_safeguard : str | None
        e.g. "SCCs", "BCRs", "EU-US DPF", "adequacy decision".
    retention_days : int | None
        Configured retention period for GDPR Art. 5(e).
    block_on_missing_lawful_basis : bool
        If True and lawful_basis == NOT_SPECIFIED, override result to "blocked".
    custom_patterns : dict[str, re.Pattern] | None
        Extra regex patterns to detect domain-specific PII.
    """

    def __init__(
        self,
        store: EventStore,
        lawful_basis: LawfulBasis = LawfulBasis.LEGITIMATE_INTERESTS,
        vertical: RegulatoryVertical | str = RegulatoryVertical.GENERAL,
        redaction_method: RedactionMethod = RedactionMethod.HASH_SHA256,
        data_subject_regions: Optional[List[DataRegion]] = None,
        cross_border_transfer: bool = False,
        transfer_safeguard: Optional[str] = None,
        retention_days: Optional[int] = None,
        block_on_missing_lawful_basis: bool = False,
        custom_patterns: Optional[Dict[str, re.Pattern]] = None,
    ):
        self.store = store
        self.lawful_basis = lawful_basis if isinstance(lawful_basis, LawfulBasis) else LawfulBasis(lawful_basis)
        self.vertical = vertical if isinstance(vertical, str) else vertical.value
        self.data_subject_regions = [
            r.value if isinstance(r, DataRegion) else r
            for r in (data_subject_regions or [])
        ]
        self.cross_border_transfer = cross_border_transfer
        self.transfer_safeguard = transfer_safeguard
        self.retention_days = retention_days
        self.block_on_missing_lawful_basis = block_on_missing_lawful_basis
        self._redactor = PIIRedactor(method=redaction_method, custom_patterns=custom_patterns)

    # ── Primary API ─────────────────────────────────────────────────────

    def record(
        self,
        agent_id: str,
        action_type: str,
        tool_name: str,
        payload: dict,
        result: str = "pending",
        authorized_by: str = "auto-policy",
        input_context: str = "",
        result_detail: str = "",
    ) -> GateEvent:
        """
        Redact PII from *payload*, embed a ``_pii_manifest``, then chain the event.

        If ``block_on_missing_lawful_basis`` is True and lawful_basis is
        NOT_SPECIFIED, the result is forced to ``"blocked"`` regardless of the
        caller's intent.
        """
        # PII redaction
        redacted_payload, detections = self._redactor.redact(payload)

        # Build manifest
        manifest = PIIManifest(
            lawful_basis=self.lawful_basis.value,
            vertical=self.vertical,
            detections=detections,
            data_subject_regions=self.data_subject_regions,
            cross_border_transfer=self.cross_border_transfer,
            transfer_safeguard=self.transfer_safeguard,
            retention_days=self.retention_days,
        )
        redacted_payload["_pii_manifest"] = manifest.to_dict()

        # Lawful-basis gate
        effective_result = result
        if (
            self.block_on_missing_lawful_basis
            and self.lawful_basis == LawfulBasis.NOT_SPECIFIED
            and detections
        ):
            effective_result = "blocked"
            redacted_payload["_pii_manifest"]["block_reason"] = (
                "No lawful basis specified for personal data processing"
            )

        event = GateEvent(
            agent_id=agent_id,
            action_type=action_type,
            tool_name=tool_name,
            payload=redacted_payload,
            result=effective_result,
            authorized_by=authorized_by,
            input_context=input_context,
            result_detail=result_detail,
        )
        return self.store.record(event)

    def verify_chain(self) -> dict:
        """Proxy to EventStore.verify_chain()."""
        return self.store.verify_chain()

    def erasure_report(self, original_hash: str) -> List[dict]:
        """
        GDPR Article 17 — Right to Erasure.

        Given the SHA-256 hash of a data subject's PII value (e.g. their email),
        return every event in the chain that processed that value. The caller can
        then flag those events for erasure/anonymisation in downstream systems.

        Parameters
        ----------
        original_hash : str
            SHA-256 hex digest of the raw PII value to locate.

        Returns
        -------
        list of dicts with event metadata for each affected event.
        """
        results = []
        for event in self.store.events:
            manifest = event.payload.get("_pii_manifest", {})
            hashes = [d.get("original_hash", "") for d in manifest.get("detections", [])]
            if original_hash in hashes:
                results.append({
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "action_type": event.action_type,
                    "tool_name": event.tool_name,
                    "agent_id": event.agent_id,
                    "result": event.result,
                })
        return results

    def compliance_summary(self) -> dict:
        """
        High-level compliance report across all chained events.

        Returns per-vertical PII counts, erasure-eligible events, and
        chain integrity status — useful for audits and SOC2/ISO27001 reviews.
        """
        total_pii = 0
        by_category: dict = {}
        erasure_eligible = 0
        verticals_seen = set()

        for event in self.store.events:
            manifest = event.payload.get("_pii_manifest", {})
            total_pii += manifest.get("pii_count", 0)
            verticals_seen.add(manifest.get("vertical", "unknown"))
            if manifest.get("erasure_eligible", False):
                erasure_eligible += 1
            for cat in manifest.get("categories_detected", []):
                by_category[cat] = by_category.get(cat, 0) + 1

        chain_status = self.store.verify_chain()

        return {
            "total_events": len(self.store.events),
            "total_pii_detections": total_pii,
            "pii_by_category": by_category,
            "erasure_eligible_events": erasure_eligible,
            "verticals": list(verticals_seen),
            "chain_valid": chain_status["valid"],
            "chain_errors": chain_status.get("errors", []),
            "lawful_basis": self.lawful_basis.value,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _key_to_category(key: str) -> str:
    """Map a sensitive dict key to a PIICategory value string."""
    _map = {
        "email": PIICategory.EMAIL,
        "phone": PIICategory.PHONE,
        "mobile": PIICategory.PHONE,
        "cell": PIICategory.PHONE,
        "fax": PIICategory.PHONE,
        "address": PIICategory.POSTAL_ADDRESS,
        "street": PIICategory.POSTAL_ADDRESS,
        "city": PIICategory.POSTAL_ADDRESS,
        "zip": PIICategory.POSTAL_ADDRESS,
        "postal_code": PIICategory.POSTAL_ADDRESS,
        "dob": PIICategory.DATE_OF_BIRTH,
        "birth_date": PIICategory.DATE_OF_BIRTH,
        "birthdate": PIICategory.DATE_OF_BIRTH,
        "ssn": PIICategory.SSN,
        "national_id": PIICategory.NATIONAL_ID,
        "passport": PIICategory.PASSPORT,
        "ip": PIICategory.IP_ADDRESS,
        "ip_address": PIICategory.IP_ADDRESS,
        "linkedin": PIICategory.LINKEDIN_URL,
        "linkedin_url": PIICategory.LINKEDIN_URL,
        "resume": PIICategory.RESUME_TEXT,
        "resume_text": PIICategory.RESUME_TEXT,
        "cv": PIICategory.RESUME_TEXT,
        "credit_card": PIICategory.CREDIT_CARD,
        "card_number": PIICategory.CREDIT_CARD,
        "pan": PIICategory.CREDIT_CARD,
        "cvv": PIICategory.CREDIT_CARD,
        "cvc": PIICategory.CREDIT_CARD,
        "expiry": PIICategory.CREDIT_CARD,
        "account_number": PIICategory.ACCOUNT_NUMBER,
        "routing_number": PIICategory.ROUTING_NUMBER,
        "bank_account": PIICategory.BANK_ACCOUNT,
        "tax_id": PIICategory.TAX_ID,
        "ein": PIICategory.TAX_ID,
        "itin": PIICategory.TAX_ID,
        "mrn": PIICategory.MEDICAL_RECORD_NUMBER,
        "medical_record": PIICategory.MEDICAL_RECORD_NUMBER,
        "patient_id": PIICategory.MEDICAL_RECORD_NUMBER,
        "npi": PIICategory.HEALTH_PLAN_NUMBER,
        "health_plan": PIICategory.HEALTH_PLAN_NUMBER,
        "diagnosis": PIICategory.MEDICAL_RECORD_NUMBER,
        "icd_code": PIICategory.MEDICAL_RECORD_NUMBER,
        "medication": PIICategory.MEDICAL_RECORD_NUMBER,
        "case_number": PIICategory.CASE_NUMBER,
        "docket": PIICategory.CASE_NUMBER,
        "bar_number": PIICategory.BAR_NUMBER,
        "client_matter": PIICategory.CASE_NUMBER,
    }
    cat = _map.get(key, PIICategory.CUSTOM)
    return cat.value
