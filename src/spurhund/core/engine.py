import regex
from typing import List, Dict
from spurhund.models import Rule, Finding
from spurhund.core.entropy import calculate_shannon_entropy
from spurhund.core.filter import should_ignore_path

SEVERITY_WEIGHT = {
    "CRITICAL": 4,
    "BLOCKER": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

class ScannerEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        self._compiled = {r.id: regex.compile(r.regex_pattern) for r in rules}
        self._excludes = {
            r.id: [regex.compile(p) for p in r.exclude_values] for r in rules
        }

    def scan_text(self, text: str, file_path: str = "<stdin>") -> List[Finding]:
        findings: List[Finding] = []

        for line_idx, line in enumerate(text.splitlines(), start=1):
            clean_line = line.strip()

            # Ignore empty lines and inline suppressions
            if not clean_line or "spurhund:ignore" in line:
                continue

            line_findings: List[Finding] = []

            for rule in self.rules:
                # Rule-specific path exclusions (e.g. skipping generic secret check on test files)
                if rule.path_excludes and should_ignore_path(file_path, rule.path_excludes):
                    continue

                # Stage A: Prefix trigger
                if rule.prefixes and not any(p.lower() in clean_line.lower() for p in rule.prefixes):
                    continue

                # Stage B: Regex matching
                pattern = self._compiled[rule.id]
                for match in pattern.finditer(clean_line):
                    try:
                        candidate = match.group(rule.capture_group) if rule.capture_group else match.group(0)
                    except IndexError:
                        candidate = match.group(0)

                    # Exclude mock/dummy patterns
                    if any(ex.search(candidate) for ex in self._excludes[rule.id]):
                        continue

                    # Stage C: Shannon Entropy gate
                    entropy = calculate_shannon_entropy(candidate)
                    if entropy < rule.min_entropy:
                        continue

                    masked = (
                        candidate[:4] + "*" * max(len(candidate) - 8, 4) + candidate[-4:]
                        if len(candidate) > 10
                        else "********"
                    )
                    line_findings.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_idx,
                        masked_secret=masked,
                        entropy=round(entropy, 2),
                        raw_match=candidate
                    ))

            # Deduplicate by raw matched token on this line: retain the highest severity
            best_by_token: Dict[str, Finding] = {}
            for f in line_findings:
                if f.raw_match not in best_by_token:
                    best_by_token[f.raw_match] = f
                else:
                    prev = best_by_token[f.raw_match]
                    if SEVERITY_WEIGHT.get(f.severity, 0) > SEVERITY_WEIGHT.get(prev.severity, 0):
                        best_by_token[f.raw_match] = f

            findings.extend(best_by_token.values())

        return findings