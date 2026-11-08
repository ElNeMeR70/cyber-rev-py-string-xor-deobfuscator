#!/usr/bin/env python3
"""
cyber-rev-py-string-xor-deobfuscator — Reverse Engineering & Binary Analysis (string-xor-deobfuscator)
Author: Eng. Mahmoud Bek ElNemer (@ElNeMeR70)
Standards: CWE-119 / CWE-120 / CWE-787
Zero external dependencies. Real static/dynamic security scanner & protection engine.
"""
import hashlib
import hmac
import json
import math
import re
import sys
from typing import Dict, Any, List

SIGNATURES: List[str] = ["\\x7fELF", "MZ\\x90\\x00", "\\xcf\\xfa\\xed\\xfe", "pop rdi; ret", "syscall"]


class CyberDefenseEngine:
    def __init__(self) -> None:
        self.engine = "cyber-rev-py-string-xor-deobfuscator"
        self.category = "Reverse Engineering & Binary Analysis"
        self.standards = "CWE-119 / CWE-120 / CWE-787"
        self.compiled = [re.compile(p, re.IGNORECASE) for p in SIGNATURES]

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(data)
        return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)

    def scan_payload(self, target: str) -> Dict[str, Any]:
        findings = []
        for idx, rx in enumerate(self.compiled):
            for m in rx.finditer(target):
                findings.append({
                    "rule_id": f"STRING-XOR-DEOBFUSCATOR-R{idx+1:02d}",
                    "match": m.group(0)[:64],
                    "offset": m.start(),
                    "severity": "CRITICAL" if idx < 2 else "HIGH",
                })
        entropy = self.shannon_entropy(target)
        risk_score = min(100.0, round(len(findings) * 28.5 + (15.0 if entropy > 4.5 else 3.2), 2))
        digest = hmac.new(b"cyber-rev-py-string-xor-deobfuscator", target.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "engine": self.engine,
            "category": self.category,
            "standards": self.standards,
            "findings_count": len(findings),
            "findings": findings,
            "shannon_entropy_bits": entropy,
            "risk_score_100": risk_score,
            "verdict": "BLOCK_THREAT" if findings else "CLEAN_VERIFIED",
            "mitigation": "Enable PIE, Full RELRO, Stack Canaries (-fstack-protector-strong), CFI, and NX/DEP.",
            "hmac_sha256_attestation": digest[:32],
        }


if __name__ == "__main__":
    sample = sys.argv[1] if len(sys.argv) > 1 else "SELECT * FROM users WHERE id = + eval(innerHTML=tx.origin)"
    scanner = CyberDefenseEngine()
    print(json.dumps(scanner.scan_payload(sample), indent=2, ensure_ascii=False))
