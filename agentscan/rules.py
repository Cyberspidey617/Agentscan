"""Text rules applied to skills, tool descriptions, scripts and command lines."""
import re
from dataclasses import dataclass
from typing import List

from .models import Finding, Severity

IGNORE_MARKER = "agentscan: ignore"


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: Severity
    pattern: "re.Pattern"
    fix: str


def _r(rule_id, title, severity, pattern, fix):
    return Rule(rule_id, title, severity, re.compile(pattern), fix)


SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                      # AWS access key
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),            # GitHub token
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),          # GitHub fine-grained
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}"), # Anthropic / OpenAI
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),         # Slack
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                # Google API
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
]

TEXT_RULES: List[Rule] = [
    # --- Prompt injection / tool poisoning -------------------------------
    _r("AS101", "Prompt injection: instruction override", Severity.HIGH,
       r"(?i)\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|system)\b.{0,20}\b(instructions?|rules|prompts?|guidelines)\b",
       "Remove text that tells the agent to drop its instructions; legitimate tools never need this."),
    _r("AS102", "Hidden instruction to conceal behavior from the user", Severity.HIGH,
       r"(?i)\b(do not|don't|never|without)\b.{0,25}\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting)\b.{0,15}\b(the )?user\b",
       "Agents should be transparent with users. Treat this tool/skill as malicious until reviewed."),
    _r("AS103", "Tool shadowing: tries to change how other tools behave", Severity.MEDIUM,
       r"(?i)\b(when|whenever|before|after)\b.{0,40}\b(using|calling|call|use|invoking)\b.{0,30}\b(other|any|another|all)\b.{0,10}\btools?\b",
       "A tool description should only describe its own tool. Review why it references other tools."),
    _r("AS104", "Suspicious hidden/system markup in description", Severity.MEDIUM,
       r"(?i)<\s*/?\s*(important|system|secret|hidden|instructions?)\s*>|\[\s*(system|hidden)\s*\]",
       "Markup like <IMPORTANT> or <system> is a common tool-poisoning trick. Inspect the surrounding text."),
    # --- Dangerous behaviour in scripts / commands -----------------------
    _r("AS201", "Remote script piped directly into a shell", Severity.CRITICAL,
       r"(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\b\s*\(?\s*(iwr|invoke-webrequest|\(new-object)",
       "Download the script, review it, pin it by hash, then run it."),
    _r("AS202", "Accesses sensitive credential files", Severity.HIGH,
       r"(?i)(~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/root|%USERPROFILE%)[/\\]\.(ssh|aws|gnupg|kube|docker|netrc|git-credentials|config[/\\]gcloud)\b|\bid_(rsa|ed25519|ecdsa)\b",
       "Skills and tools should never read SSH keys or cloud credentials. Remove or sandbox this."),
    _r("AS203", "Possible data exfiltration (uploads data to a remote host)", Severity.HIGH,
       r"(?i)\bcurl\b[^\n]*\s(-d|--data[a-z\-]*|-F|--form|--upload-file|-T)\s[^\n]*https?://|\b(requests|httpx|axios)\.post\s*\(|\bfetch\s*\([^)]*method\s*:\s*['\"]POST",
       "Confirm what data is sent and where. Unexpected outbound POSTs are a classic exfiltration channel."),
    _r("AS204", "Destructive command", Severity.HIGH,
       r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(--no-preserve-root\s+)?(/|~|\$HOME|/\*)(\s|$|\")|\bmkfs\.\w+|\bdd\s+if=\S+\s+of=/dev/(sd|nvme|disk)",
       "Remove destructive commands or scope them to a temp directory."),
    _r("AS205", "Dynamic code execution", Severity.MEDIUM,
       r"\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bchild_process\.exec\s*\(",
       "Avoid executing dynamic strings; pass argument lists and validate inputs."),
    _r("AS206", "Decodes and runs an obfuscated payload", Severity.CRITICAL,
       r"(?i)base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh\b|exec\s*\(\s*(base64\.)?b64decode|eval\s*\(\s*(atob|Buffer\.from)\s*\(",
       "Obfuscated execution is a strong malware signal. Do not install."),
    _r("AS207", "Persistence: modifies shell startup files or scheduled tasks", Severity.MEDIUM,
       r"(?i)>>?\s*\S*\.(bashrc|zshrc|profile|bash_profile)\b|\bcrontab\s+-|/etc/cron|\bschtasks\b|LaunchAgents",
       "Tools should not install persistence. Review why this is needed."),
]

INVISIBLE_ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff")
INVISIBLE_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def mask_secret(text: str) -> str:
    for pat in SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0)[:6] + "…" + "*" * 6, text)
    return text


def _evidence(line: str) -> str:
    line = mask_secret(line.strip())
    line = "".join(ch if ch.isprintable() else "?" for ch in line)
    return line[:117] + "..." if len(line) > 120 else line


def scan_invisible(line: str, path: str, lineno: int) -> List[Finding]:
    findings = []
    tags = [c for c in line if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        findings.append(Finding("AS110", "Hidden Unicode tag characters (ASCII smuggling)", Severity.CRITICAL,
                                path, lineno, f"decoded hidden text: {hidden[:100]!r}",
                                "This text is invisible to humans but read by the model. Remove it and distrust the source."))
    if any(c in INVISIBLE_BIDI for c in line):
        findings.append(Finding("AS111", "Bidirectional override characters (Trojan Source)", Severity.HIGH,
                                path, lineno, _evidence(line),
                                "Bidi controls can make text display differently than it is read. Remove them."))
    if any(c in INVISIBLE_ZERO_WIDTH for c in line):
        findings.append(Finding("AS112", "Zero-width characters hidden in text", Severity.MEDIUM,
                                path, lineno, _evidence(line),
                                "Zero-width characters can hide or split keywords to evade review. Remove them."))
    return findings


def scan_secrets(line: str, path: str, lineno: int) -> List[Finding]:
    for pat in SECRET_PATTERNS:
        if pat.search(line):
            return [Finding("AS301", "Hardcoded secret or private key", Severity.HIGH, path, lineno,
                            _evidence(line), "Move the secret to an environment variable or secret manager and rotate it.")]
    return []


def scan_text(text: str, path: str, line_offset: int = 0) -> List[Finding]:
    findings: List[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1 + line_offset):
        if IGNORE_MARKER in line:
            continue
        findings.extend(scan_invisible(line, path, i))
        findings.extend(scan_secrets(line, path, i))
        for rule in TEXT_RULES:
            if rule.pattern.search(line):
                findings.append(Finding(rule.rule_id, rule.title, rule.severity, path, i, _evidence(line), rule.fix))
    return findings
