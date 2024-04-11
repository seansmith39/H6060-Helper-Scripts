#!/usr/bin/env python3

from argparse import ArgumentParser
import json
import re
import sys
import csv


def get_args():
    parser = ArgumentParser(description='Parses JSON Results For CWE Results')
    parser.add_argument('-p', '--product', required=True, help='Horusec, Insider or OWASP')
    return parser.parse_args()


def parse_horusec_data(cwe_pattern):
    with open('horusec_results.json', 'r') as f:
        data = json.load(f)
    unique_cwe = csv_rows = []
    for vulnerabilities in data['analysisVulnerabilities']:
        details = vulnerabilities['vulnerabilities']['details']
        if 'CWE' in details.upper():
            match = re.search(cwe_pattern, details)
            if match:
                cwe_id = match.group(0)
                severity = vulnerabilities['vulnerabilities']['severity']
                if cwe_id not in unique_cwe:
                    unique_cwe.append(cwe_id)
                    csv_rows.append([cwe_id, severity])

    fields = ['CWE', 'Severity']
    filename = "horusec_details.csv"
    write_csv(csv_rows, fields, filename)
    return True


def parse_insider_data(cwe_pattern):
    with open('insider_results.json', 'r') as f:
        data = json.load(f)
    unique_cwe = csv_rows = []
    for vulnerabilities in data['vulnerabilities']:
        if 'cwe' in vulnerabilities:
            match = re.search(cwe_pattern, vulnerabilities['cwe'])
            if match:
                cwe_id = match.group(0)
                cvss = str(vulnerabilities['cvss'])
                if unique_cwe not in unique_cwe:
                    unique_cwe.append(cwe_id)
                    csv_rows.append([cwe_id, cvss])

    fields = ['CWE', 'CVSS']
    filename = "insider_details.csv"
    write_csv(csv_rows, fields, filename)
    return True


def parse_owasp_dependency_data():
    with open('owasp_dependency.json', 'r') as f:
        data = json.load(f)
    unique_cwe = csv_rows = []
    for vulnerabilities in data['dependencies']:
        if 'vulnerabilities' in vulnerabilities.keys():
            if 'vulnerableSoftware' in vulnerabilities['vulnerabilities'][0].keys():
                if len(vulnerabilities['vulnerabilities'][0]['vulnerableSoftware']) != 0:
                    name = vulnerabilities['vulnerabilities'][0]['name']
                    severity = vulnerabilities['vulnerabilities'][0]['severity']
                    software = vulnerabilities['vulnerabilities'][0]['vulnerableSoftware'][0]['software']['id']
                    cwe = vulnerabilities['vulnerabilities'][0]['cwes']
                    cvss_score = 'N/A'
                    if 'cvssv3' in vulnerabilities['vulnerabilities'][0].keys():
                        cvss_score = vulnerabilities['vulnerabilities'][0]['cvssv3']['baseScore']
                    elif 'cvssv2' in vulnerabilities['vulnerabilities'][0].keys():
                        cvss_score = vulnerabilities['vulnerabilities'][0]['cvssv2']['score']
                    if name not in unique_cwe:
                        unique_cwe.append(name)
                        csv_rows.append([name, severity, software, cwe, cvss_score])

    fields = ['Name', 'Severity', 'Software', 'CWE', 'CVSS']
    filename = "owasp_dependency_details.csv"
    write_csv(csv_rows, fields, filename)
    return True


def write_csv(csv_rows, fields, filename):
    with open(filename, 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(fields)
        csvwriter.writerows(csv_rows)
    return True


def main(args):
    cwe_pattern = "CWE-(\\d+){0,9}"
    if args.product.upper() == "HORUSEC":
        parse_horusec_data(cwe_pattern)
    elif args.product.upper() == "INSIDER":
        parse_insider_data(cwe_pattern)
    elif args.product.upper() == "OWASP":
        parse_owasp_dependency_data()
    else:
        print("Invalid product. Please choose from Horusec, Insider or OWASP.")
        sys.exit(1)


if __name__ == '__main__':
    main(get_args())
