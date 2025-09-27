import argparse
import glob
import os
import sys
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

import yara

RULE_URL: str = (
    "https://raw.githubusercontent.com/joocer/fides/main/rules/" "Leaked%20Secrets%20(SECRETS).yar"
)


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

    return parser.parse_args()


def main():
    """Main execution function"""
    args = parse_arguments()

    found_secrets = False

    # Load rules
    if args.rules_file and os.path.exists(args.rules_file):
        try:
            rules = yara.compile(args.rules_file)
            if args.verbose:
                print(f"Loaded rules from: {args.rules_file}")
        except yara.Error as e:
            print(f"Error loading rules file {args.rules_file}: {e}")
            sys.exit(1)
    else:
        rule_content = download_file(args.rules_url, args.timeout)
        if rule_content is None:
            print(f"Failed to download rule file from: {args.rules_url}")
            sys.exit(1)

        try:
            rules = yara.compile(source=rule_content)
            if args.verbose:
                print(f"Downloaded rules from: {args.rules_url}")
        except yara.Error as e:
            print(f"Error compiling YARA rules: {e}")
            sys.exit(1)

    scan_path = os.path.abspath(args.path)
    if not os.path.exists(scan_path):
        print(f"Scan path does not exist: {scan_path}")
        sys.exit(1)

    if args.verbose:
        print(f"Scanning path: {scan_path}")

    # Change to scan directory
    original_dir = os.getcwd()
    try:
        os.chdir(scan_path)

        for file_name in glob.iglob("**", recursive=True):
            if not os.path.isfile(file_name):
                continue

            # Skip binary files and common non-source files
            if _is_binary_file(file_name) or _should_skip_file(file_name):
                continue

            try:
                with open(file_name, "r", encoding="utf-8", errors="ignore") as contents:
                    for line_counter, line in enumerate(contents):
                        line = line.strip()
                        if len(line) > 1:
                            matches = rules.match(data=line)
                            for match in matches:
                                description = match.meta["description"]
                                if description != "Token Appears to be a Random String":
                                    if not args.no_color:
                                        print(
                                            f"\033[0;33m{description:40}\033[0m "
                                            f"\033[0;31mFAIL\033[0m {file_name}:{line_counter + 1}"
                                        )
                                    else:
                                        print(
                                            f"{description:40} FAIL {file_name}:{line_counter + 1}"
                                        )
                                    found_secrets = True
                                else:
                                    if args.verbose:
                                        if not args.no_color:
                                            print(
                                                f"\033[0;35m{description:40}\033[0m "
                                                f"\033[0;34mWARN\033[0m "
                                                f"{file_name}:{line_counter + 1}"
                                            )
                                        else:
                                            print(
                                                f"{description:40} WARN "
                                                f"{file_name}:{line_counter + 1}"
                                            )
            except (UnicodeDecodeError, PermissionError, OSError) as e:
                if args.verbose:
                    print(f"Warning: Could not read file {file_name}: {e}")
                continue

    finally:
        os.chdir(original_dir)

    if found_secrets:
        print("\nSecrets Found")
        sys.exit(1)

    print("No Secrets Found")


if __name__ == "__main__":
    main()
