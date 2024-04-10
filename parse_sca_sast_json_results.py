#!/usr/bin/env python3


from argparse import ArgumentParser
import json
import re
import sys


def get_args():
    parser = ArgumentParser(description='Parses JSON Results For CWE Results')
    parser.add_argument('-p', '--product', required=True, help='Horusec, Insider or OWASP')
    parser.add_argument('-f', '--results-filename', required=True)
    return parser.parse_args()


def parse_horusec_data(data, cwe_pattern):
    unique_cwe = []
    for vulnerabilities in data['analysisVulnerabilities']:
        details = vulnerabilities['vulnerabilities']['details']
        if 'CWE' in details.upper():
            match = re.search(cwe_pattern, details)
            if match:
                cwe_id = match.group(0)
                entry = cwe_id + ", " + vulnerabilities['vulnerabilities']['severity']
                if not entry in unique_cwe:
                    unique_cwe.append(entry)
    return unique_cwe


def parse_insider_data(data, cwe_pattern):
    unique_cwe = []
    for vulnerabilities in data['vulnerabilities']:
        if 'cwe' in vulnerabilities:
            match = re.search(cwe_pattern, vulnerabilities['cwe'])
            if match:
                cwe_id = match.group(0)
                entry = cwe_id + ", " + str(vulnerabilities['cvss'])
                if not entry in unique_cwe:
                    unique_cwe.append(entry)
    return unique_cwe


def parse_owasp_dependency_data(data):
    unique_cwe = []
    for vulnerabilities in data['dependencies']:
        if 'vulnerabilities' in vulnerabilities.keys():
            if 'vulnerableSoftware' in vulnerabilities['vulnerabilities'][0].keys():
                if len(vulnerabilities['vulnerabilities'][0]['vulnerableSoftware']) != 0:
                    name = vulnerabilities['vulnerabilities'][0]['name']
                    severity = vulnerabilities['vulnerabilities'][0]['severity']
                    software = vulnerabilities['vulnerabilities'][0]['vulnerableSoftware'][0]['software']['id']
                    cwe = vulnerabilities['vulnerabilities'][0]['cwes']
                    cvss_score = None
                    if 'cvssv3' in vulnerabilities['vulnerabilities'][0].keys():
                        cvss_score = vulnerabilities['vulnerabilities'][0]['cvssv3']['baseScore']
                    elif 'cvssv2' in vulnerabilities['vulnerabilities'][0].keys():
                        cvss_score = vulnerabilities['vulnerabilities'][0]['cvssv2']['score']
                    if not name in unique_cwe:
                        unique_cwe.append(name)
                        print(f"{name},{severity},{software},{cwe},{cvss_score}")
    return unique_cwe


def parse_results(product, results_filename):
    with open(results_filename, 'r') as f:
        data = json.load(f)

    cwe_pattern = "CWE-(\\d+){0,9}"

    if product == "HORUSEC":
        unique_cwe = parse_horusec_data(data, cwe_pattern)
    elif product == "INSIDER":
        unique_cwe = parse_insider_data(data, cwe_pattern)
    elif product == "OWASP":
        unique_cwe = parse_owasp_dependency_data(data)
    else:
        print("Invalid product. Please choose from Horusec, Insider or OWASP.")
        sys.exit(1)

    return unique_cwe


def main(args) -> None:
    """Start point of application."""
    all_cwe = parse_results(args.product.upper(), args.results_filename)
    print(*all_cwe, sep='\n')


if __name__ == '__main__':
    main(get_args())
