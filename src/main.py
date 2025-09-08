from datetime import datetime
import os
from elastic import get_elastic_rules
from opencti import get_actor_details, get_actor_techniques, get_sigma_rules, get_sigma_techniques, update_rules_in_opencti, remove_disabled_coas
from tables import create_actor_table, create_technique_table, create_coverage_table, create_metric_table
from log import log_info
from dotenv import load_dotenv

# ==============
# Config
# ==============
load_dotenv()
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
ELASTIC_API_URL = os.getenv("ELASTIC_API_URL")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")



OPENCTI_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json"
}

ELASTIC_HEADERS = {
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    "Content-Type": "application/json"
}  


TOP_ACTORS = os.getenv("TOP_ACTORS").split(", ")    

TABLE_LENGTH = 10 # Number of rows to show in the table


# ==============
# Data processing
# ==============


# Create threat-reports/<YYYY-MM> relative to this script
def ensure_threat_report_folder():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(base_dir, '..', 'Threat-report', datetime.now().strftime("%Y-%m"))
    os.makedirs(report_dir, exist_ok=True)
    return os.path.abspath(report_dir)

def get_unique_actor_techniques(all_actors):
    unique_techniques = []
    for actor in all_actors:
        techniques = get_actor_techniques(OPENCTI_URL, OPENCTI_HEADERS, actor[0])
        for technique in techniques:
            if technique.get('x_mitre_id') not in [t.get('x_mitre_id') for t in unique_techniques]:
                unique_techniques.append(technique)
    return unique_techniques

def extract_elastic_techniques(elastic_rules):
    results = []
    for rule in elastic_rules:
        rule_name = rule.get('name', 'Unknown Rule')
        for threat_entry in rule.get('threat', []):
            for technique in threat_entry.get('technique', []):
                tid = technique.get('id')
                technique_name = technique.get('name', 'Unknown Technique')
                # If there are subtechniques, list each one
                subtechs = technique.get('subtechnique', [])
                if subtechs:
                    for subtech in subtechs:
                        stid = subtech.get('id')
                        subtech_name = subtech.get('name', 'Unknown Subtechnique')
                        results.append({
                            'rule': rule_name,
                            'tid': tid,
                            'technique': technique_name,
                            'stid': stid,
                            'subtechnique': subtech_name
                        })
                else:
                    # No subtechnique, just the main technique
                    results.append({
                        'rule': rule_name,
                        'tid': tid,
                        'technique': technique_name,
                        'stid': None,
                        'subtechnique': None
                    })
    return results

# ==============
# Main function
# ==============

def main():
    report_dir = ensure_threat_report_folder()
    elastic_rules, enabled_rules = get_elastic_rules(ELASTIC_API_URL, ELASTIC_HEADERS)
    log_info(f"Found {len(elastic_rules)} Elastic rules, {len(enabled_rules)} enabled rules.")
    log_info("Updating Elastic rules in OpenCTI.")
    update_rules_in_opencti(OPENCTI_URL, OPENCTI_HEADERS, enabled_rules)
    log_info("Updated Elastic rules in OpenCTI.")
  
    remove_disabled_coas(OPENCTI_URL, OPENCTI_HEADERS, enabled_rules)
    log_info("Removed disabled CoAs from OpenCTI.")
    log_info("Fetching techniques from elastic rules.")
    elastic_techniques = extract_elastic_techniques(enabled_rules)
    log_info("Fetching Sigma rules from OpenCTI.")
    sigma_rules = get_sigma_rules(OPENCTI_URL, OPENCTI_HEADERS)
    log_info(f"Found {len(sigma_rules)} Sigma rules.")
    log_info("Fetching techniques from Sigma rules.")
    sigma_techniques = get_sigma_techniques(OPENCTI_URL, OPENCTI_HEADERS, sigma_rules)


    log_info("Fetching actor details from OpenCTI.")
    all_actors = []
    missing_actors = []
    log_info(f"Processing TOP {TABLE_LENGTH} actors: {TOP_ACTORS}")
    for actor in TOP_ACTORS:
        actor_details = get_actor_details(OPENCTI_URL, OPENCTI_HEADERS, actor)
        if actor_details:
            all_actors.extend(actor_details)
        else:
            missing_actors.append(actor)
    log_info(f"Found {len(all_actors)} actors, missing details for {len(missing_actors)} actors: {', '.join(missing_actors)}.")

    log_info("Fetching techniques for all actors.")
    unique_techniques = get_unique_actor_techniques(all_actors)
    log_info(f"Found {len(unique_techniques)} unique techniques across all actors.")

# ==============
# Generate tables
# ==============
    log_info("Generating tables for the report.")
    overview_table = f" | {len(all_actors)}| {len(sigma_rules)} | {len(enabled_rules)}  | {len(unique_techniques)} |"

    actor_table = create_actor_table(OPENCTI_URL, OPENCTI_HEADERS, all_actors, TABLE_LENGTH)

    tactic_table = ""
    
    technique_table = create_technique_table(OPENCTI_URL, OPENCTI_HEADERS, all_actors, TABLE_LENGTH)

    coverage_table, coverage_table_uncovered, sigma_table = create_coverage_table(unique_techniques, elastic_techniques, sigma_techniques, TABLE_LENGTH)

    metric_table = create_metric_table(elastic_techniques, sigma_techniques, unique_techniques)
    log_info("Generated all tables for the report.")
# ==============
# Generate report
# ==============

    report_data = f"""# :chart: Strategic Threat Intelligence & Detection Coverage Report

**Platform**: OpenCTI + Sigma + ATT&CK + Elastic + Gitlab
**Date**: {datetime.now().strftime("%Y-%m-%d")}
**Author**: CTI Engineer

## :mag: Executive Summary
The Organisation has prioritised the following actors; **{', '.join(TOP_ACTORS)}** however there is no details in OpenCTI on **{', '.join(missing_actors)}**. The report provides an overview of available actors techniques, coverage by Elastic rules and suggested Sigma rules.
There is a total of **{len(all_actors)}** actors, **{len(sigma_rules)}** Sigma rules, **{len(enabled_rules)}** Elastic rules, and **{len(unique_techniques)}** unique techniques identified in the organisation's threat landscape.


# :scroll: Landscape Overview
| Intrusion Sets | Sigma Rules | Elastic Rules | Attack Patterns |
|----------------|-------------|----------------|----------------|
{overview_table}

## :fire: TOP {TABLE_LENGTH} ACTORS
| Name | Aliases | # of Techniques |
|------|---------|-----------------| 
{actor_table}

## :triangular_flag_on_post: Coverage by MITRE Tactic

| MITRE Tactic          | # Techniques Used | Elastic Rules | Sigma Rules | Coverage % | High-Risk Techniques Without Coverage |
|-----------------------|-------------------|----------------|-------------|------------|--------------------------------------|
{tactic_table}

## :top: Top {TABLE_LENGTH} Targetted Techniques by Actors
| Technique | Used by Actors | Count |
|-----------|----------------|-------|
{technique_table}

## :mag: Detection Coverage
This section provides an overview of the coverage of techniques by Elastic and Sigma rules.  

### :dart: Top {TABLE_LENGTH} Techniques with Elastic Rules and Sigma Rules
|Technique | Elastic rules | Sigma Rules | Covered |
|----------|---------------|-------------|---------|
{coverage_table}

### :warning: Top {TABLE_LENGTH} Techniques with lowest Elastic Rules and/or Sigma Rules  
|Technique | Elastic Rules | Sigma Rules | Covered |
|----------|----------------|------------|---------|
{coverage_table_uncovered}

### :rocket: {TABLE_LENGTH} techniques with Sigma Rules but no Elastic Rules
| Technique | Sigma Rules | Elastic Rules | 5 Sigma Rule suggestions |
|-----------|-------------|---------------|----------------------|
{sigma_table}

### :chart: Coverage Summary
| Metric | Value | % |
|--------|-------|---|
{metric_table}
"""

    #print(report_data)
    log_info("Saving report to file.")
    report_title = datetime.now().strftime("%Y-%m-%d-Threat-Report.md")
    report_path = os.path.join(report_dir, report_title)
    with open(report_path, "w") as f:
        f.write(report_data)
        log_info(f"Report saved to {report_path}")

if __name__ == "__main__":
    main()