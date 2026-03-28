# ares_cli/cvss.py
"""
CVSS 3.1 Scoring Engine for ARES
Implements Base + Temporal scoring with Exploit Code Maturity focus
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Tuple
import math

class AttackVector(Enum):
    """CVSS Attack Vector (AV)"""
    NETWORK = 0.85      # N - Remotely exploitable
    ADJACENT = 0.62     # A - Adjacent network
    LOCAL = 0.55        # L - Local access required
    PHYSICAL = 0.2      # P - Physical access required

class AttackComplexity(Enum):
    """CVSS Attack Complexity (AC)"""
    LOW = 0.77          # L - No special conditions
    HIGH = 0.44         # H - Specific conditions required

class PrivilegesRequired(Enum):
    """CVSS Privileges Required (PR)"""
    NONE = 0.85         # N - No auth needed
    LOW = 0.62          # L - Basic user access
    HIGH = 0.27         # H - Admin/elevated access

class UserInteraction(Enum):
    """CVSS User Interaction (UI)"""
    NONE = 0.85         # N - No user action needed
    REQUIRED = 0.62     # R - User must perform action

class Scope(Enum):
    """CVSS Scope (S)"""
    UNCHANGED = "U"     # Exploit stays in vulnerable component
    CHANGED = "C"       # Exploit can affect other components

class Impact(Enum):
    """CVSS Impact metrics (C/I/A)"""
    NONE = 0.0          # N - No impact
    LOW = 0.22          # L - Limited impact
    HIGH = 0.56         # H - Total compromise

class ExploitCodeMaturity(Enum):
    """CVSS Temporal - Exploit Code Maturity (E)"""
    NOT_DEFINED = 1.0   # X - Assume worst case
    HIGH = 1.0          # H - Functional exploit available
    FUNCTIONAL = 0.97   # F - Exploit works in most situations
    POC = 0.94          # P - Proof of concept exists
    UNPROVEN = 0.91     # U - No known exploit

class RemediationLevel(Enum):
    """CVSS Temporal - Remediation Level (RL)"""
    NOT_DEFINED = 1.0   # X - Assume worst case
    UNAVAILABLE = 1.0   # U - No solution available
    WORKAROUND = 0.97   # W - Unofficial workaround
    TEMPORARY = 0.96    # T - Temporary fix
    OFFICIAL = 0.95     # O - Official patch available

class ReportConfidence(Enum):
    """CVSS Temporal - Report Confidence (RC)"""
    NOT_DEFINED = 1.0   # X - Assume worst case
    CONFIRMED = 1.0     # C - Confirmed vulnerability
    REASONABLE = 0.96   # R - Reasonable confidence
    UNKNOWN = 0.92      # U - Unconfirmed

@dataclass
class CVSSVector:
    """Complete CVSS 3.1 Vector"""
    # Base metrics (required)
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.HIGH
    integrity: Impact = Impact.HIGH
    availability: Impact = Impact.HIGH
    
    # Temporal metrics (optional - for "hackability" focus)
    exploit_maturity: ExploitCodeMaturity = ExploitCodeMaturity.NOT_DEFINED
    remediation_level: RemediationLevel = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence = ReportConfidence.NOT_DEFINED
    
    def to_vector_string(self) -> str:
        """Generate CVSS vector string"""
        av = self.attack_vector.name[0]
        ac = self.attack_complexity.name[0]
        pr = self.privileges_required.name[0]
        ui = self.user_interaction.name[0]
        s = self.scope.value
        c = self.confidentiality.name[0]
        i = self.integrity.name[0]
        a = self.availability.name[0]
        
        base = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        
        # Add temporal if not default
        temporal = ""
        if self.exploit_maturity != ExploitCodeMaturity.NOT_DEFINED:
            temporal += f"/E:{self.exploit_maturity.name[0]}"
        if self.remediation_level != RemediationLevel.NOT_DEFINED:
            temporal += f"/RL:{self.remediation_level.name[0]}"
        if self.report_confidence != ReportConfidence.NOT_DEFINED:
            temporal += f"/RC:{self.report_confidence.name[0]}"
            
        return base + temporal

class CVSSCalculator:
    """
    CVSS 3.1 Score Calculator
    Focuses on Base + Temporal for exploit prioritization
    """
    
    # Known vulnerability patterns mapped to CVSS vectors
    VULN_PATTERNS = {
        "sql-injection": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "xss": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "rce": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "remote-code-execution": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "code-execution": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "command-injection": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "path-traversal": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "ssrf": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "weak-credentials": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "info-disclosure": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.NONE,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "directory-traversal": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "file-inclusion": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "xxe": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.LOW,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "csrf": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "clickjacking": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "cors": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.POC,
        ),
        "deserialization": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "idor": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "authentication-bypass": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "cookie": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.POC,
        ),
        "debug": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "misconfiguration": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "file-upload": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_maturity=ExploitCodeMaturity.FUNCTIONAL,
        ),
        "open-redirect": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.HIGH,
        ),
        "missing-header": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.POC,
        ),
        "end-of-life": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.LOW,
            exploit_maturity=ExploitCodeMaturity.POC,
        ),
        "default": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
            exploit_maturity=ExploitCodeMaturity.UNPROVEN,
        ),
    }
    
    @staticmethod
    def calculate_base_score(vector: CVSSVector) -> float:
        """
        Calculate CVSS 3.1 Base Score
        Formula: https://www.first.org/cvss/v3.1/specification-document
        """
        # Impact Sub-Score
        isc_base = 1 - (
            (1 - vector.confidentiality.value) *
            (1 - vector.integrity.value) *
            (1 - vector.availability.value)
        )
        
        if vector.scope == Scope.UNCHANGED:
            isc = 6.42 * isc_base
        else:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Exploitability Sub-Score
        # Adjust PR based on scope
        pr_value = vector.privileges_required.value
        if vector.scope == Scope.CHANGED:
            if vector.privileges_required == PrivilegesRequired.LOW:
                pr_value = 0.68
            elif vector.privileges_required == PrivilegesRequired.HIGH:
                pr_value = 0.50
        
        exploitability = 8.22 * vector.attack_vector.value * vector.attack_complexity.value * pr_value * vector.user_interaction.value
        
        # Base Score
        if isc <= 0:
            return 0.0
        
        if vector.scope == Scope.UNCHANGED:
            base = min(isc + exploitability, 10)
        else:
            base = min(1.08 * (isc + exploitability), 10)
        
        return math.ceil(base * 10) / 10
    
    @staticmethod
    def calculate_temporal_score(base_score: float, vector: CVSSVector) -> float:
        """
        Calculate CVSS 3.1 Temporal Score
        Focuses on Exploit Code Maturity for "hackability"
        """
        temporal = base_score * vector.exploit_maturity.value * vector.remediation_level.value * vector.report_confidence.value
        return math.ceil(temporal * 10) / 10
    
    @classmethod
    def calculate_full_score(cls, vector: CVSSVector) -> Tuple[float, float, str]:
        """
        Calculate both Base and Temporal scores
        Returns: (base_score, temporal_score, severity_level)
        """
        base = cls.calculate_base_score(vector)
        temporal = cls.calculate_temporal_score(base, vector)
        severity = cls.severity_from_score(temporal)
        return base, temporal, severity
    
    @staticmethod
    def severity_from_score(score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        return "NONE"
    
    @classmethod
    def score_vulnerability(cls, vuln_name: str, has_exploit: bool = False, has_patch: bool = False) -> Dict:
        """
        Score a vulnerability by name with temporal adjustments
        
        Args:
            vuln_name: Vulnerability identifier (e.g., "sql-injection", "xss")
            has_exploit: Whether a working exploit is known to exist
            has_patch: Whether an official patch is available
        
        Returns:
            Dict with scores and metadata
        """
        # Find matching pattern
        vuln_lower = vuln_name.lower().replace(" ", "-").replace("_", "-")
        vector = None
        
        for pattern, v in cls.VULN_PATTERNS.items():
            if pattern in vuln_lower:
                vector = CVSSVector(
                    attack_vector=v.attack_vector,
                    attack_complexity=v.attack_complexity,
                    privileges_required=v.privileges_required,
                    user_interaction=v.user_interaction,
                    scope=v.scope,
                    confidentiality=v.confidentiality,
                    integrity=v.integrity,
                    availability=v.availability,
                    exploit_maturity=v.exploit_maturity,
                    remediation_level=v.remediation_level,
                    report_confidence=v.report_confidence,
                )
                break
        
        if not vector:
            vector = cls.VULN_PATTERNS["default"]
        
        # Adjust temporal based on runtime knowledge
        if has_exploit:
            vector.exploit_maturity = ExploitCodeMaturity.HIGH
        if has_patch:
            vector.remediation_level = RemediationLevel.OFFICIAL
        
        base, temporal, severity = cls.calculate_full_score(vector)
        
        return {
            "cvss_base": base,
            "cvss_temporal": temporal,
            "cvss_vector": vector.to_vector_string(),
            "severity": severity,
            "exploitable": vector.exploit_maturity in [ExploitCodeMaturity.HIGH, ExploitCodeMaturity.FUNCTIONAL],
            "patched": vector.remediation_level == RemediationLevel.OFFICIAL,
        }

def calculate_aggregate_score(vulnerabilities: list) -> Tuple[float, str]:
    """
    Calculate aggregate CVSS score for multiple vulnerabilities
    Uses modified formula: highest_score + log(sum of others)
    
    This prioritizes the most critical vuln while still accounting
    for attack surface breadth.
    """
    if not vulnerabilities:
        return 0.0, "NONE"
    
    scores = []
    for vuln in vulnerabilities:
        if isinstance(vuln, dict):
            # Exclude informational findings from aggregate score calculation
            if vuln.get("severity", "").lower() == "info":
                continue
                
            score = vuln.get("cvss_temporal") or vuln.get("cvss_base") or vuln.get("cvss_score") or vuln.get("severity_score", 0)
            if isinstance(score, (int, float)):
                scores.append(float(score))
    
    if not scores:
        return 0.0, "NONE"
    
    scores.sort(reverse=True)
    highest = scores[0]
    
    # Add diminishing contribution from other vulns
    if len(scores) > 1:
        others_sum = sum(scores[1:])
        aggregate = min(10.0, highest + math.log1p(others_sum) * 0.5)
    else:
        aggregate = highest
    
    aggregate = round(aggregate, 1)
    severity = CVSSCalculator.severity_from_score(aggregate)
    
    return aggregate, severity
