import glob
import os
import sys
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen

import yara

RULE_URL: str = (
    "https://raw.githubusercontent.com/joocer/fides/main/rules/Leaked%20Secrets%20(SECRETS).yar"
)


def download_file(url: str) -> Optional[str]:
    """
    Downloads a file given a URL and returns its content as a string.

    Parameters:
        url: str
            URL of the file to download.

    Returns:
        Content of the file as a string if successful, otherwise None.
    """
    try:
        with urlopen(url) as response:
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
        with open(file_name, "rb") as contents:
            for line_counter, line in enumerate(contents.readlines()):
                if len(line) > 1:
                    matches = rules.match(data=line)
                    for match in matches:
                        description = match.meta["description"]
                        if description != "Token Appears to be a Random String":
                            print(
                                f"\033[0;33m{description:40}\033[0m \033[0;31mFAIL\033[0m {file_name}:{line_counter + 1}"
                            )
                            found_secrets = True
                        else:
                            print(
                                f"\033[0;35m{description:40}\033[0m \033[0;34mWARN\033[0m {file_name}:{line_counter + 1}"
                            )

    if found_secrets:
        print("\nSecrets Found")
        sys.exit(1)

    print("No Secrets Found")


if __name__ == "__main__":
    main()
