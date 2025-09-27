import glob
import os
import sys
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen
from urllib.request import Request

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


def main():
    found_secrets = False
    rule_file = download_file(RULE_URL)
    if rule_file is None:
        print("Failed to download rule file.")
        sys.exit(1)

    rules = yara.compile(source=rule_file)

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
                                print(
                                    f"\033[0;33m{description:40}\033[0m "
                                    f"\033[0;31mFAIL\033[0m {file_name}:{line_counter + 1}"
                                )
                                found_secrets = True
                            else:
                                print(
                                    f"\033[0;35m{description:40}\033[0m "
                                    f"\033[0;34mWARN\033[0m {file_name}:{line_counter + 1}"
                                )
        except (UnicodeDecodeError, PermissionError, OSError):
            # Skip files that can't be read
            continue

    if found_secrets:
        print("\nSecrets Found")
        sys.exit(1)

    print("No Secrets Found")


if __name__ == "__main__":
    main()
