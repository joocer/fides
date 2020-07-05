import yara
import os
from pathlib import Path

class colors:
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    GREY = '\033[90m'

    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def collect_results(data):
    results.append(data)
    return yara.CALLBACK_CONTINUE

yara_directory = 'rules/'
test_subject_source = 'samples/www.google.com.txt'
#test_subject_source = 'samples/localhost.txt'

with open(test_subject_source, 'r') as file:
    test_subject = file.read().replace('\n', '')

results = []
fail_count = 0
pass_count = 0

def collect_results(data):
    results.append(data)
    data['subject'] = test_subject_source
    return yara.CALLBACK_CONTINUE

for filename in os.listdir(yara_directory):
    if filename.endswith(".yar"):
        ruleset = Path(filename).stem
        print('Rule Set:', ruleset)
        results = []
        rule = yara.compile(yara_directory + filename)
        matches = rule.match(data = test_subject, callback=collect_results)
        
        for result in results:
            if result['matches']:
                print(colors.GREEN + '✓ PASS:', '(' + result['rule'] + ')', result['meta']['description'] + colors.END)
                pass_count = pass_count + 1
            else:
                print(colors.RED + '✗ FAIL:', '(' + result['rule'] + ')', result['meta']['description'] + colors.END)
                fail_count = fail_count + 1
        print()

print('Test Summary:', colors.GREEN, pass_count, 'passed', colors.RED, fail_count, 'failed', colors.END)