import sys, os
import yara
import glob
import os.path


found_secrets = False
line_counter = 0
for rule_file in glob.iglob("../../**/Leaked Secrets (SECRETS).yar", recursive=True):
    print(f"Working Directory {os.getcwd}")
    print(f"Reading rules from {rule_file}")
    rules = yara.compile(rule_file)
    break

for file_name in glob.iglob("**", recursive=True):
    if not os.path.isfile(file_name):
        continue
    with open(file_name, "r") as contents:
        line_counter = 0
        for line in contents.readlines():
            line_counter += 1
            line = line.rstrip("\n|\r\n").strip()
            if len(line) > 1:
                matches = rules.match(data=line)
                for match in matches:
                    print(
                        f"\033[0;33m{match.meta['description']:45}\033[0m {file_name}:{line_counter}"
                    )
                    found_secrets = True

# if there have been errors, exit with am ERRORLEVEL of 1
if found_secrets > 0:
    print(f"\nSecrets Found")
    sys.exit(1)

print("No Secrets Found")
