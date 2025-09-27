#!/usr/bin/env python
import os
import os.path
import sys
import argparse
from typing import Optional, Iterator

import yara

"""
Script to test a file, line by line, against a set of YARA rules.

Intended to be used as an unattended script, for example in a
build or deployment pipeline.
"""


def get_input_stream(filename: Optional[str] = None):
    """
    If filename is - use standard in, if it's an existing
    file, open and use that

    Return a stream (or None) for processing.
    """
    if filename:
        if filename == "-":
            if not sys.stdin.isatty():
                return sys.stdin
        elif os.path.isfile(filename):
            return open(filename, "r", encoding="utf-8")
    return None


def get_rule_files(rule_file: Optional[str] = None) -> Iterator[str]:
    """
    If there is a rule file parameter, try to use that for rules
    otherwise look for .yar files in the current folder.
    """
    if rule_file and os.path.isfile(rule_file):
        yield rule_file
    elif rule_file:
        print("Invalid rule file specified.")
        print("Use --help for usage information.")
        sys.exit(1)
    else:
        found_rules = False
        for filename in os.listdir("."):
            if filename.endswith(".yar"):
                found_rules = True
                yield filename

        if not found_rules:
            print("No .yar rule files found in current directory.")
            print("Use -r to specify a rule file or --help for usage information.")
            sys.exit(1)


def format_result(result, verbose):
    """
    Common code to format the results.
    """
    if verbose:
        return (
            f"line: {result['line_number']} - ({result['rule']}) "
            f"{result['meta']['description']} - {result['line']}"
        )
    return f"line: {result['line_number']} - ({result['rule']}) " f"{result['meta']['description']}"


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Test a file, line by line, against a set of YARA rules.",
        epilog="When FILE is -, standard input is read.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("file", nargs="?", help="file to test (use - for stdin)")

    parser.add_argument(
        "-r",
        "--rules",
        help="file containing rules (if omitted, all .yar files in current directory used)",
    )

    parser.add_argument(
        "-o", "--output", help="file to save results to (if omitted, results printed to stdout)"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase the amount of result information"
    )

    return parser.parse_args()


def main():
    """Main execution function"""
    args = parse_arguments()

    # Initialize variables
    input_stream = get_input_stream(args.file)
    if not input_stream:
        print("No input specified.")
        print("Use --help for usage information.")
        sys.exit(1)

    rule_files = list(get_rule_files(args.rules))
    rules = []
    fail_count = 0
    pass_count = 0
    line_counter = 0
    first_result = True

    # compile the rule set
    try:
        for filename in rule_files:
            rule = yara.compile(filename)
            rules.append(rule)
    except yara.Error as e:
        print(f"Error compiling YARA rules: {e}")
        sys.exit(1)

    # if we have an output file, open it now so we can save results
    file_writer = None
    if args.output:
        try:
            file_writer = open(args.output, "w", encoding="utf8")
        except OSError as e:
            print(f"Error opening output file '{args.output}': {e}")
            sys.exit(1)

    # execute the rules against the test file
    try:
        for line in input_stream:
            line_counter += 1
            line = line.rstrip("\n\r")
            if len(line) > 1:
                for rule in rules:
                    # what isn't clear from this code is that the results
                    # are saved to the results list by the collect_results
                    # method
                    rule.match(
                        data=line, callback=lambda data: collect_results(data, line_counter, line)
                    )
    except Exception as e:
        print(f"Error processing input: {e}")
        sys.exit(1)
    finally:
        # Close input stream if it's a file
        if input_stream and hasattr(input_stream, "close") and input_stream != sys.stdin:
            input_stream.close()

    # cycle through the results, handling pass/fail accordingly
    for result in results:
        if not result["matches"]:
            pass_count += 1
        else:
            if not args.output:
                if first_result:
                    first_result = False
                    print("Rule Violations:")
                print(format_result(result, args.verbose))
            if file_writer:
                file_writer.write(format_result(result, args.verbose) + "\n")
            fail_count += 1

    # close the output file, if we have one
    if file_writer:
        file_writer.close()

    # assume a human is reading screen output so, provide a summary
    # so they don't need to count
    if not args.output:
        if not first_result:
            print()
        print(f"Summary: {pass_count} passes, {fail_count} fails")

    # if there have been errors, exit with an ERRORLEVEL of 1
    if fail_count > 0:
        sys.exit(1)


def collect_results(data, line_counter, line):
    """
    Collector for YARA test results
    """
    data["line_number"] = line_counter
    data["line"] = line
    results.append(data)
    return yara.CALLBACK_CONTINUE


# Global results list for callback
results = []


if __name__ == "__main__":
    main()
