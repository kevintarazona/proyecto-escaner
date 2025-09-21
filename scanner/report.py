from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Finding:
    vuln_type: str
    target: str
    payload: str
    evidence: str

@dataclass
class ScanReport:
    target_url: str
    findings: List[Finding] = field(default_factory=list)

    def add(self, vuln_type: str, target: str, payload: str, evidence: str):
        self.findings.append(Finding(vuln_type, target, payload, evidence))

    def summary(self) -> Dict:
        return {
            'target': self.target_url,
            'count': len(self.findings),
            'findings': [f.__dict__ for f in self.findings]
        }
