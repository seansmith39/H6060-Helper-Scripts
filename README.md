## H6060-Helper-Scripts

### Description

The following repository contains helper scripts for the H6060 Experiment 1.

### Scripts

#### parse_sca_sast_json_results.py

This script parses the JSON results of the SCA and SAST scans and writes the results to a CSV file.

Copy the resulting json output from the Git Action Workflow to the following input files:
- `horusec_results.json`
- `insider_results.json`
- `owasp_results.json`

To run the script, use the following command:
```
python3 parse_sca_sast_json_results.py -p [horusec|insider|owasp]
```

Results will be written to the following output files:
- `horusec_results.csv`
- `insider_results.csv`
- `owasp_results.csv`

#### get_cwe_details_from_cve.py

This script acquires the CWE details from the NVD API and writes the results to a CSV file.

Enter the list of CVE IDs to be queried in `cve_list.txt`.

To run the script, use the following command:
```
python3 get_cwe_details_from_cwe.py -i [ignore-scoring]
```

Results will be written to `cve_details.csv`.

#### get_cwe_top_owasp_sans.py

This script returns a list of CWEs that are in the OWASP Top 10 and/or SANS Top 25.

Enter the list of CWE IDs to be queried in `cwe_list.txt`.

To run the script, use the following command:
```
python3 get_cwe_top_owasp_sans.py
```

Results will be written to `cwe_details.csv`.
