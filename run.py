import sys, os
import yara
import glob
import os.path

RULE_URL = "https://raw.githubusercontent.com/joocer/fides/master/rules/Leaked%20Secrets%20(SECRETS).yar"

def download_file(url):
    import requests
    r = requests.get(url, allow_redirects=True)
    if r.status_code == 200:
        return r.text
    return None

found_secrets = False
line_counter = 0
rule_file = download_file(RULE_URL)
rules = yara.compile(source=rule_file)

for file_name in glob.iglob("**", recursive=True):
    if not os.path.isfile(file_name):
        continue
    with open(file_name, "rb") as contents:
        line_counter = 0
        for line in contents.readlines():
            line_counter += 1
            if len(line) > 1:
                matches = rules.match(data=line)
                for match in matches:
                    if match.meta['description'] != "Token Appears to be a Random String":
                        print(
                            f"\033[0;33m{match.meta['description']:40}\033[0m \033[0;31mFAIL\033[0m {file_name}:{line_counter}"
                        )
                        found_secrets = True
                    else:
                        print(
                            f"\033[0;35m{match.meta['description']:40}\033[0m \033[0;34mWARN\033[0m {file_name}:{line_counter}"
                        )

# if there have been errors, exit with am ERRORLEVEL of 1
if found_secrets > 0:
    print(f"\nSecrets Found")
    sys.exit(1)

print("No Secrets Found")
