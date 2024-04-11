#!/usr/bin/env python3

from argparse import ArgumentParser
import csv
from time import sleep
from requests import get
import re


def get_args():
    parser = ArgumentParser(description='Get CWE from CVE')
    parser.add_argument('-i', '--ignore-scoring', required=True, help='Ignore CVSS scoring')
    return parser.parse_args()


def search_cve_from_nvd(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    sleep_time = 0.1
    headers = {"apiKey": "400db763-de8c-4c62-a716-f5eaa36497fa"}

    parameters = {"keywordSearch": cve_id}

    for tries in range(3):
        try:
            sleep(sleep_time)
            response = get(url, params=parameters, headers=headers)
            data = response.json()
        except Exception as e:
            if response.status_code == 403:
                print("Requests are being rate limited by NIST API")
                sleep(sleep_time)
        else:
            break
    return data


def get_cve_year(cve):
    cve_year_pattern = re.compile(r'(?<=-)\w+(?=-)')
    match = re.search(cve_year_pattern, cve)
    if match:
        return int(match.group(0))


def find_matching_cwe(ignore_scoring):
    csv_rows = []
    with open('cve_list.txt', 'r') as f:
        cve_list = f.readlines()
    for cve in cve_list:
        cve = cve.strip()
        cve_year = get_cve_year(cve)
        cve_info = search_cve_from_nvd(cve)
        try:
            total_cwe = len(cve_info['vulnerabilities'][0]['cve']['weaknesses'][0]['description'])
            cwe = cve_info['vulnerabilities'][0]['cve']['weaknesses'][0]['description'][0]['value']
            if total_cwe > 1:
                for i in range(1, total_cwe):
                    cwe += "," + cve_info['vulnerabilities'][0]['cve']['weaknesses'][0]['description'][i]['value']
            if ignore_scoring == 'True':
                base_score = base_severity = 'N/A'
            else:
                if cve_year > 2016:
                    base_score = cve_info['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    base_severity = cve_info['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                else:
                    base_score = cve_info['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    base_severity = cve_info['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
            csv_rows.append([cve, cwe, base_score, base_severity])
        except KeyError:
            print(f"Error: Problems parsing {cve}")
            csv_rows.append([cve, 'N/A', 'N/A', 'N/A'])
            continue
    return csv_rows


def write_csv(csv_rows):
    fields = ['CVE', 'CWE', 'CVSS', 'Severity']
    filename = "cve_details.csv"
    with open(filename, 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(fields)
        csvwriter.writerows(csv_rows)


def main(args):
    csv_rows = find_matching_cwe(args.ignore_scoring)
    write_csv(csv_rows)


if __name__ == '__main__':
    main(get_args())
