import argparse
import glob
import json
import os
import sys
from collections import Counter
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

import yara

RULE_URL: str = (
    "https://raw.githubusercontent.com/joocer/fides/main/rules/" "Leaked%20Secrets%20(SECRETS).yar"
)

# Findings at these importance levels are reported but do not fail the scan.
WARN_IMPORTANCES = {"low", "medium", "info"}

# A rule at this importance is an allowlist, not a detection. Anything it
# matches is a credential that is public by design - a vendor's documented
# example key, an emulator's fixed key. Other rules still run against the
# line; their findings are suppressed and the suppression is reported, so an
# allowlisted credential is visibly accounted for rather than silently
# missing. See SECRETS00 in the ruleset.
IGNORE_IMPORTANCE = "ignored"


def _is_binary_file(file_path: str) -> bool:
    """Check if a file is binary by reading a small chunk."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\0" in chunk
    except (OSError, PermissionError):
        return True


def _should_skip_file(file_path: str) -> bool:
    """Check if a file should be skipped based on its extension or path."""
    skip_extensions = {
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".exe",
        ".bin",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".7z",
        ".rar",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wav",
    }

    skip_dirs = {
        ".git",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".coverage",
        "dist",
        "build",
        ".tox",
        ".venv",
        "venv",
        "site-packages",
        # Vendored third-party source. Upstream projects ship test
        # certificates and credential-shaped fixtures that are not the
        # scanned repository's secrets to rotate.
        "third_party",
        "third-party",
        "vendor",
        "vendored",
        "external",
    }

    # Check extension
    _, ext = os.path.splitext(file_path.lower())
    if ext in skip_extensions:
        return True

    # Check if file is in skip directories
    path_parts = file_path.split(os.sep)
    if any(part in skip_dirs for part in path_parts):
        return True

    return False


def download_file(url: str, timeout: int = 30) -> Optional[str]:
    """
    Downloads a file given a URL and returns its content as a string.

    Parameters:
        url: str
            URL of the file to download.
        timeout: int
            Timeout in seconds for the request (default: 30).

    Returns:
        Content of the file as a string if successful, otherwise None.
    """
    try:
        request = Request(url, headers={"User-Agent": "Fides-Scanner/1.0"})
        with urlopen(request, timeout=timeout) as response:
            if response.status == 200:
                return response.read().decode("utf-8")
    except URLError:
        return None
    return None


def redact(value: str) -> str:
    """
    Mask a matched value so a scan log never becomes a second copy of the
    secret, while leaving enough shape to find it in the file.
    """
    length = len(value)
    if length <= 4:
        return "*" * length
    keep = 4 if length >= 16 else 2
    # Cap the mask so a long token does not push the useful part off screen.
    stars = min(length - (2 * keep), 12)
    return f"{value[:keep]}{'*' * stars}{value[-keep:]}"


def iter_string_matches(match: Any) -> Iterator[Tuple[str, int, str]]:
    """
    Yield (pattern identifier, offset, matched text) for every string that
    triggered a rule.

    yara-python changed this API at 4.3: `match.strings` used to be a list of
    (offset, identifier, data) tuples and is now a list of StringMatch objects
    each holding several instances. Both shapes are handled so the scanner is
    not pinned to one yara-python release.
    """
    for string_match in match.strings:
        identifier = getattr(string_match, "identifier", None)
        if identifier is None:
            offset, identifier, data = string_match
            yield identifier, offset, _as_text(data)
            continue
        for instance in string_match.instances:
            yield identifier, instance.offset, _as_text(instance.matched_data)


def _as_text(data: Any) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def severity_of(importance: str) -> str:
    """Map a rule's `importance` meta onto how the scanner treats it."""
    if importance == IGNORE_IMPORTANCE:
        return "ignored"
    if importance in WARN_IMPORTANCES:
        return "warning"
    return "error"


def scan_line(
    rules: yara.Rules, file_name: str, line_number: int, raw_line: str
) -> List[Dict[str, Any]]:
    """
    Match one line and describe everything the rules found on it.

    A line matched by an allowlist rule still gets scanned by everything else;
    the resulting findings are downgraded to "ignored" and carry the allowlist
    entry that excused them, rather than being dropped on the floor.
    """
    stripped = raw_line.strip()
    if len(stripped) <= 1:
        return []

    findings: List[Dict[str, Any]] = []
    indent = len(raw_line) - len(raw_line.lstrip())
    seen = set()

    for match in rules.match(data=stripped):
        meta = match.meta
        description = meta.get("description", match.rule)
        importance = str(meta.get("importance", "high")).lower()
        reported = 0

        for identifier, offset, value in iter_string_matches(match):
            key = (match.rule, identifier, offset)
            if key in seen:
                continue
            seen.add(key)
            reported += 1
            redacted = redact(value)
            findings.append(
                {
                    "file": file_name,
                    "line": line_number,
                    "column": indent + offset + 1,
                    # The surrounding code, with the secret itself removed, so
                    # verbose output shows what the line is doing without
                    # copying the credential into the log.
                    "context": stripped.replace(value, redacted)[:200],
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "pattern": identifier,
                    "description": description,
                    "importance": importance,
                    "match": redacted,
                    "match_length": len(value),
                    "severity": severity_of(importance),
                    "ignored_by": "",
                }
            )

        if reported == 0:
            # A rule can fire on a condition with no reportable string (for
            # example an "all of" over anonymous patterns). Still report it.
            findings.append(
                {
                    "file": file_name,
                    "line": line_number,
                    "column": indent + 1,
                    "context": "",
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "pattern": "-",
                    "description": description,
                    "importance": importance,
                    "match": "",
                    "match_length": 0,
                    "severity": severity_of(importance),
                    "ignored_by": "",
                }
            )

    return apply_allowlist(findings)


def apply_allowlist(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Downgrade every finding on a line an allowlist rule claimed.

    The allowlist findings themselves are not returned - on their own they say
    nothing. What is worth reporting is the detection they excused.
    """
    allowlisted = [f for f in findings if f["severity"] == "ignored"]
    if not allowlisted:
        return findings

    excuse = ", ".join(sorted({f"{f['rule']} ({f['pattern']})" for f in allowlisted}))
    suppressed = []
    for finding in findings:
        if finding["severity"] == "ignored":
            continue
        finding["severity"] = "ignored"
        finding["ignored_by"] = excuse
        suppressed.append(finding)
    return suppressed


def format_finding(finding: Dict[str, Any], verbose: bool, use_color: bool) -> str:
    """
    Render one finding as a headline plus an indented explanation of what
    matched and why it was reported.
    """
    dim, reset = "\033[0;90m", "\033[0m"
    if finding["severity"] == "error":
        label, label_color, desc_color = "FAIL", "\033[0;31m", "\033[0;33m"
    elif finding["severity"] == "warning":
        label, label_color, desc_color = "WARN", "\033[0;34m", "\033[0;35m"
    else:
        label, label_color, desc_color = "SKIP", dim, dim

    if not use_color:
        label_color = desc_color = dim = reset = ""

    location = f"{finding['file']}:{finding['line']}:{finding['column']}"
    lines = [
        f"{label_color}{label}{reset} {desc_color}{finding['description']:40}{reset} {location}"
    ]

    detail = (
        f"rule {finding['rule']}"
        + (f" [{', '.join(finding['tags'])}]" if finding["tags"] else "")
        + f" | pattern {finding['pattern']}"
        + f" | importance {finding['importance']}"
    )
    lines.append(f"     {dim}{detail}{reset}")

    if finding["ignored_by"]:
        lines.append(f"     {dim}ignored by {finding['ignored_by']}{reset}")

    if finding["match"]:
        lines.append(
            f"     {dim}matched {finding['match']} "
            f"({finding['match_length']} chars, redacted){reset}"
        )

    if verbose and finding["context"] and finding["context"] != finding["match"]:
        lines.append(f"     {dim}context {finding['context']}{reset}")

    return "\n".join(lines)


def emit_github_annotation(finding: Dict[str, Any]) -> None:
    """
    Emit a workflow command so the finding is attached to the offending line
    in the GitHub UI instead of being buried in the job log.
    """
    message = f"{finding['description']} - rule {finding['rule']}, pattern {finding['pattern']}" + (
        f", matched {finding['match']} ({finding['match_length']} chars, redacted)"
        if finding["match"]
        else ""
    )
    # Workflow commands are newline and comma delimited; neither can survive
    # inside a property value.
    safe = message.replace("\r", " ").replace("\n", " ")
    print(
        f"::{finding['severity']} file={finding['file']},"
        f"line={finding['line']},col={finding['column']},"
        f"title=Fides: {finding['description']}::{safe}"
    )


def write_summary(
    findings: List[Dict[str, Any]],
    files_scanned: int,
    files_skipped: int,
    use_color: bool,
) -> None:
    """Tell the reader what was scanned and what came back, without counting."""
    bold, reset = ("\033[1m", "\033[0m") if use_color else ("", "")

    failures = [f for f in findings if f["severity"] == "error"]
    warnings = [f for f in findings if f["severity"] == "warning"]
    ignored = [f for f in findings if f["severity"] == "ignored"]

    print()
    print(f"{bold}Scan summary{reset}")
    print(f"  files scanned  {files_scanned}")
    print(f"  files skipped  {files_skipped}")
    print(f"  findings       {len(failures)} failing, {len(warnings)} warning")

    if ignored:
        # Always reported, even without --verbose: a clean scan that made a
        # judgement call should say so rather than look like it found nothing.
        rules_used = ", ".join(sorted({f["ignored_by"] for f in ignored}))
        print(f"  ignored        {len(ignored)} known public ({rules_used})")

    if failures:
        print(f"  files affected {len({f['file'] for f in failures})}")
        print()
        print(f"{bold}Findings by type{reset}")
        counts = Counter((f["description"], f["rule"]) for f in failures)
        for (description, rule), count in counts.most_common():
            print(f"  {count:>4}  {description} ({rule})")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Fides - Secret scanning tool for code repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Scan current directory
  %(prog)s --path /src        # Scan specific path
  %(prog)s --verbose          # Verbose output
  %(prog)s --json report.json # Write findings as JSON
        """,
    )

    parser.add_argument("--path", default=".", help="Path to scan (default: current directory)")

    parser.add_argument("--rules-url", default=RULE_URL, help="URL to download YARA rules from")

    parser.add_argument("--rules-file", help="Local YARA rules file (overrides --rules-url)")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument(
        "--timeout", type=int, default=30, help="Timeout for rule download (default: 30 seconds)"
    )

    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    parser.add_argument("--json", help="Write findings to this file as JSON")

    parser.add_argument(
        "--no-annotations",
        action="store_true",
        help="Do not emit GitHub Actions annotations when running in a workflow",
    )

    return parser.parse_args()


def load_rules(args: argparse.Namespace) -> yara.Rules:
    """Compile rules from a local file if given, otherwise from the rules URL."""
    if args.rules_file and os.path.exists(args.rules_file):
        try:
            rules = yara.compile(args.rules_file)
        except yara.Error as e:
            print(f"Error loading rules file {args.rules_file}: {e}")
            sys.exit(1)
        if args.verbose:
            print(f"Loaded rules from: {args.rules_file}")
        return rules

    rule_content = download_file(args.rules_url, args.timeout)
    if rule_content is None:
        print(f"Failed to download rule file from: {args.rules_url}")
        sys.exit(1)

    try:
        rules = yara.compile(source=rule_content)
    except yara.Error as e:
        print(f"Error compiling YARA rules: {e}")
        sys.exit(1)
    if args.verbose:
        print(f"Downloaded rules from: {args.rules_url}")
    return rules


def main():
    """Main execution function"""
    args = parse_arguments()

    rules = load_rules(args)

    scan_path = os.path.abspath(args.path)
    if not os.path.exists(scan_path):
        print(f"Scan path does not exist: {scan_path}")
        sys.exit(1)

    if args.verbose:
        print(f"Scanning path: {scan_path}")

    use_color = not args.no_color
    annotate = not args.no_annotations and os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

    findings: List[Dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0

    original_dir = os.getcwd()
    try:
        os.chdir(scan_path)

        for file_name in glob.iglob("**", recursive=True):
            if not os.path.isfile(file_name):
                continue

            # Skip binary files and common non-source files
            if _should_skip_file(file_name) or _is_binary_file(file_name):
                files_skipped += 1
                continue

            files_scanned += 1

            try:
                with open(file_name, "r", encoding="utf-8", errors="ignore") as contents:
                    for line_counter, line in enumerate(contents, start=1):
                        for finding in scan_line(rules, file_name, line_counter, line):
                            findings.append(finding)
                            # Warnings and allowlisted findings are counted in
                            # the summary but only listed when asked for - they
                            # are numerous and would drown the failures.
                            if finding["severity"] != "error" and not args.verbose:
                                continue
                            print(format_finding(finding, args.verbose, use_color))
                            # An allowlisted finding is not something to draw a
                            # reviewer's eye to in the diff.
                            if annotate and finding["severity"] != "ignored":
                                emit_github_annotation(finding)
            except (UnicodeDecodeError, PermissionError, OSError) as e:
                files_skipped += 1
                if args.verbose:
                    print(f"Warning: Could not read file {file_name}: {e}")
                continue

    finally:
        os.chdir(original_dir)

    write_summary(findings, files_scanned, files_skipped, use_color)

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as report:
                json.dump(
                    {
                        "path": scan_path,
                        "files_scanned": files_scanned,
                        "files_skipped": files_skipped,
                        "findings": findings,
                    },
                    report,
                    indent=2,
                )
        except OSError as e:
            print(f"Error writing JSON report to {args.json}: {e}")

    failures = [f for f in findings if f["severity"] == "error"]
    if failures:
        print()
        print("Secrets Found")
        fail_on_secrets = os.environ.get("FIDES_FAIL_ON_SECRETS", "true").lower() != "false"
        if fail_on_secrets:
            sys.exit(1)
        print("FIDES_FAIL_ON_SECRETS is false - not failing the run")
        return

    print()
    print("No Secrets Found")


if __name__ == "__main__":
    main()
