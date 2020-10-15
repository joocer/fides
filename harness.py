import argparse, sys, os
import yara
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


def read_file(filename, chunk_size=1024*1024, delimiter='\n'):
    """
    Reads an arbitrarily long file, line by line
    """
    with open(filename, 'r', encoding="utf8") as f:
        carry_forward = ''
        chunk = 'INITIALIZED'
        while len(chunk) > 0:
            chunk = carry_forward + f.read(chunk_size)
            lines = chunk.split(delimiter)
            carry_forward = lines.pop()
            yield from lines
        if carry_forward:
            yield carry_forward

def collect_results(data):
    data['line_number'] = line_counter
    results.append(data)
    return yara.CALLBACK_CONTINUE

results = []
fail_count = 0
pass_count = 0
yara_directory = 'rules/'

parser = argparse.ArgumentParser(prog='ytf')
parser.add_argument('-i', '--input', help='File to execute tests against')
parser.add_argument('-o', '--output', help='File to save results to')
parser.add_argument('-q', '--quiet', help='Do not display test results to the screen')
args = parser.parse_args()

if not args.input:
    print("no input file specified, ytf --help for help")
    sys.exit(1)

print_results = not args.quiet
if not args.output and not print_results:
    print("Invalid options, not outputting results")
    sys.exit(1)

file_writer = None
if args.output:
    file_writer = open(args.output, 'w', encoding='utf8')

file_reader = read_file(args.input)
line_counter = 0

for filename in os.listdir(yara_directory):
    if filename.endswith(".yar"):
        results = []
        rule = yara.compile(yara_directory + filename)
        for line in file_reader:
            line_counter += 1
            matches = rule.match(data=line, callback=collect_results)
        
        for result in results:
            if result['matches']:
                pass_count = pass_count + 1
            else:
                if print_results:
                    print(colors.RED + "✗ FAIL: ({}) {}".format(result['rule'], result['meta']['description']) + colors.END)
                if file_writer:
                    file_writer.write("{} (line:{}) - ({}) {}".format(args.input, result['line_number'], result['rule'], result['meta']['description']))
                fail_count = fail_count + 1

if print_results:
    print('Test Summary:', colors.GREEN, pass_count, 'passed', colors.RED, fail_count, 'failed', colors.END)
if file_writer:
    file_writer.close()

if fail_count > 0:
    sys.exit(1)
sys.exit(0)
