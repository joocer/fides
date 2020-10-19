#!/usr/bin/env python
import sys, os
import yara
import os.path

"""
Script to test a file, line by line, against a set of YARA rules.

Intended to be used as an unattended script, for example in a
build or deployment pipeline.
"""


def collect_results(data):
    """
    Collector for YARA test results
    """
    data['line_number'] = line_counter
    data['line'] = line
    results.append(data)
    return yara.CALLBACK_CONTINUE


def get_input_stream():
    """
    If input is piped into this method, use that otherwise expect a
    filename as the first command-line parameter.

    Return a stream (or None) for processing.
    """
    if not sys.stdin.isatty():
        return sys.stdin                                          
    else:
        if len(sys.argv) > 1:
            input_filename = sys.argv[1]
            if os.path.isfile(input_filename):
                return open(input_filename, 'r')
    return None


def get_parameter_value(label):
    """
    Look for labelled parameters in the command line, the pattern is:

        -a value

    Where '-a' is the label, and 'value' is the returned value.
    """
    if label in sys.argv:
        idx = sys.argv.index(label)
        if (idx + 1) < len(sys.argv):
            return sys.argv[idx + 1]
    return None


def get_rule_files():
    """
    If there is a -r command-line parameter, try to use that for rules
    otherwise look for .yar files in the current folder.
    """
    rule_param = get_parameter_value('-r')
    if rule_param and os.path.isfile(rule_param):
        yield rule_param
    elif rule_param:
        print("Invalid rule file specified.")
        print(f"Try '{sys.argv[0]} --help' for usage information.")
        sys.exit(1)
    else:
        for filename in os.listdir('.'):
            if filename.endswith(".yar"):
                yield filename


def format_result(result, verbose):
    """
    Common code to format the results.
    """
    if verbose:
        return f"line: {result['line_number']} - ({result['rule']}) {result['meta']['description']} - {result['line']}"
    return f"line: {result['line_number']} - ({result['rule']}) {result['meta']['description']}"
    

# Initialize variables
verbose      = '--verbose' in sys.argv or '-v' in sys.argv
show_help    = '-?' in sys.argv or '-h' in sys.argv or '--help' in sys.argv # be lenient on people asking for help
rule_file    = get_parameter_value('-r')
out_file     = get_parameter_value('-o')
input_stream = get_input_stream()
rule_files   = get_rule_files()
rules        = []
results      = []
fail_count   = 0
pass_count   = 0
line_counter = 0
first_result = True


# if help requested, display help and exit with no error
if show_help:
    print("Usage: test [FILE] [-o OUTPUTFILE] [-r RULEFILE] [--verbose] [--help]")
    print("Test INPUTFILE against YARA rules in RULEFILE")
    print("Example: test zap_results.csv -o zap_critical_results.csv")
    print()
    print("  FILE\t\tfile to test")
    print("  -o\t\tfile to save results to, if omitted results printed to standard output")
    print("  -r\t\tfile containing rules, if omitted all .yar files in current directort used")
    print("  -v, --verbose\tflag to increase the amount of result information")
    print("  -h, --help\tdisplay this help text and exit")
    print()
    print("When FILE is omitted, standard input in read.")
    sys.exit(0)

# if we have nothing to processes, display an error and how to get help
if not input_stream:
    print("No input specified.")
    print(f"Try '{sys.argv[0]} --help' for usage information.")
    sys.exit(1)

# compile the rule set
for filename in rule_files:
    rule = yara.compile(filename)
    rules.append(rule)

# if we have an output file, open it now so we can save results
file_writer = None
if out_file:
    file_writer = open(out_file, 'w', encoding='utf8')
    
# execute the rules against the test file
for line in input_stream:
    line_counter += 1
    for rule in rules:
        # what isn't clear from this code is that the results 
        # are saved to the results list by the collect_results 
        # method
        rule.match(data=line, callback=collect_results)
    
# cycle through the results, handling pass/fail accordingly
for result in results:
    if result['matches']:
        pass_count += 1
    else:
        if not out_file:
            if first_result:
                first_result = False
                print('Rule Violations:')
            print(format_result(result, verbose))
        if file_writer:
            file_writer.write(format_result(result, verbose) + '\n')
        fail_count += 1

# close the output file, if we have one
if file_writer:
    file_writer.close()
        
# assume a human is reading screen output so, provide a summary 
# so they don't need to count
if not out_file:
    if not first_result:
        print()
    print(f'Summary: {pass_count} passes, {fail_count} fails')

# if there have been errors, exit with am ERRORLEVEL of 1
if fail_count > 0:
    sys.exit(1)
