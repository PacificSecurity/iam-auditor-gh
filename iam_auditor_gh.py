#!/usr/bin/env python3

import boto3
import json
import argparse
import sys
import os
import logging
import csv
from typing import List, Dict, Any, Optional, Set
from botocore.exceptions import ClientError

# --- Configuration & Constants ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

BANNER = """
================================================================================
==          IAM Auditor for GitHub Actions OIDC Federation                    ==
================================================================================
"""

HELP_DESCRIPTION = """
This tool helps you identify IAM roles that trust GitHub's OIDC provider and
checks them for common security misconfigurations.

It includes checks for:
- AdministratorAccess
- Privilege Escalation risks (based on HackTricks/CloudPEASS)
- Trust Policy misconfigurations (wildcards)
- External Organization validation (via --allowed-orgs)

EXAMPLES:
  # Scan the default profile
  python %(prog)s

  # Scan a specific profile and save the report to a file
  python %(prog)s --profile my-audit-profile -o report.txt

  # Scan multiple profiles and export all found role policies to a directory
  python %(prog)s --profiles prof1 prof2 --export audit_files/

  # Scan and output the results in JSON format
  python %(prog)s --json -o report.json
  
  # Scan and output the results in CSV format
  python %(prog)s --csv -o report.csv

  # [SECURITY LOCK] Scan ensuring only specific orgs are trusted
  # This alerts if any role trusts a repo outside of 'my-org' or 'another-org'
  python %(prog)s --allowed-orgs my-org another-org
"""

EPILOG = """
MINIMUM IAM PERMISSIONS REQUIRED:
- iam:ListRoles
- iam:ListAttachedRolePolicies
- iam:ListRolePolicies
- iam:GetPolicy
- iam:GetPolicyVersion
- iam:GetRolePolicy
"""

from sensitive_permissions import (
    VERY_SENSITIVE_COMBINATIONS,
    SENSITIVE_COMBINATIONS,
    get_hacktricks_link
)

# --- Analysis Functions ---

def analyze_policy_document(policy_doc: Dict[str, Any]) -> List[str]:
    """Analyzes a policy document for risky wildcard permissions and privilege escalation."""
    findings: List[str] = []
    if not policy_doc or 'Statement' not in policy_doc:
        return findings

    statements = policy_doc['Statement']
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') == 'Allow':
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            

            actions_set = set(actions)

            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for full admin access
            if '*' in actions_set and '*' in resources:
                 findings.append("CRITICAL: Action: '*' on Resource: '*' (AdministratorAccess)")
                 continue

            # Check for Very Sensitive Combinations (CloudPEASS)
            for combination in VERY_SENSITIVE_COMBINATIONS:
                if len(combination) == 1:
                    if combination[0] in actions_set:
                        if '*' in resources:
                            link = get_hacktricks_link(combination[0])
                            findings.append(f"HIGH RISK: Potential Privilege Escalation via '{combination[0]}' on Resource: '*'. Info: {link}")
                else:
                    if all(action in actions_set for action in combination):
                         if '*' in resources:
                            combo_str = ", ".join(combination)
                            link = get_hacktricks_link(combination)
                            findings.append(f"HIGH RISK: Potential Privilege Escalation via combination '{combo_str}' on Resource: '*'. Info: {link}")

            # Check for Sensitive Combinations (CloudPEASS) - flagged as Medium/Potential Risk
            for combination in SENSITIVE_COMBINATIONS:
                 if len(combination) == 1:
                    if combination[0] in actions_set:
                        if '*' in resources:
                             link = get_hacktricks_link(combination[0])
                             findings.append(f"MEDIUM RISK: Sensitive permission '{combination[0]}' on Resource: '*'. Info: {link}")
                 else:
                    if all(action in actions_set for action in combination):
                        if '*' in resources:
                            combo_str = ", ".join(combination)
                            link = get_hacktricks_link(combination)
                            findings.append(f"MEDIUM RISK: Sensitive permission combination '{combo_str}' on Resource: '*'. Info: {link}")


            for action in actions:
                # Check for wildcards in actions
                if '*' in action and action != '*':
                    for resource in resources:
                        if resource == '*':
                            findings.append(f"POTENTIAL RISK: Action: '{action}' on Resource: '*' (All resources)")
                        else:
                            findings.append(f"POTENTIAL RISK: Action: '{action}' on Resource: '{resource}'")
    return findings

def get_role_permissions(iam_client: Any, role_name: str) -> Dict[str, Any]:
    """
    Analyzes the permissions of a role and returns a structured dictionary.
    """
    permissions_data: Dict[str, Any] = {
        "attached_policies": [],
        "inline_policies": [],
        "has_administrator_access": False,
        "risky_actions_found": []
    }
    
    try:
        # --- Attached Policies ---
        attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies_response.get('AttachedPolicies', []):
            policy_info = {"name": policy['PolicyName'], "arn": policy['PolicyArn'], "findings": []}
            if "AdministratorAccess" in policy['PolicyName']:
                permissions_data["has_administrator_access"] = True
            
            try:
                policy_response = iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                version_id = policy_response['Policy']['DefaultVersionId']
                policy_info['default_version_id'] = version_id
                policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=version_id)
                policy_document = policy_version['PolicyVersion']['Document']
                policy_info["findings"] = analyze_policy_document(policy_document)
            except ClientError as e:
                logger.warning(f"Could not retrieve attached policy '{policy['PolicyName']}': {e}")
                policy_info["findings"].append("Could not retrieve policy document to analyze.")

            permissions_data["attached_policies"].append(policy_info)
        
        # --- Inline Policies ---
        inline_policies_response = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies_response.get('PolicyNames', []):
            policy_info = {"name": policy_name, "findings": []}
            try:
                policy_doc_response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                policy_document = policy_doc_response['PolicyDocument']
                policy_info["findings"] = analyze_policy_document(policy_document)
            except ClientError as e:
                logger.warning(f"Could not retrieve inline policy '{policy_name}': {e}")
                policy_info["findings"].append("Could not retrieve policy document to analyze.")
            
            permissions_data["inline_policies"].append(policy_info)

    except ClientError as e:
        logger.error(f"Could not retrieve permissions for role {role_name}: {e}")
        permissions_data["error"] = f"Could not retrieve permissions: {e.response['Error']['Code']}"

    return permissions_data

def analyze_role_trust(policy_doc: Dict[str, Any], allowed_orgs: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Analyzes the trust policy document and returns a structured dictionary.
    """
    trust_data: Dict[str, Any] = {
        "allowed_repositories": [],
        "is_misconfigured": False,
        "misconfiguration_type": None,
        "external_org_warnings": []
    }
    
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') == 'Allow':
            principal = stmt.get('Principal', {})
            if 'Federated' in principal and 'token.actions.githubusercontent.com' in principal['Federated']:
                condition = stmt.get('Condition', {})
                subjects = []
                for condition_type in ['StringLike', 'StringEquals']:
                    if condition_type in condition:
                        sub_condition = condition[condition_type].get('token.actions.githubusercontent.com:sub')
                        if sub_condition:
                            subjects.extend(sub_condition if isinstance(sub_condition, list) else [sub_condition])
                
                trust_data["allowed_repositories"].extend(subjects)
                
                for sub in subjects:
                    # Check for wildcards
                    if sub.lower() == "repo:*:*":
                        trust_data["is_misconfigured"] = True
                        trust_data["misconfiguration_type"] = "SEVERE: Wildcard allows ANY GitHub repository."
                    elif not trust_data["is_misconfigured"] and "*" in sub.split(':')[1]:
                        trust_data["is_misconfigured"] = True
                        trust_data["misconfiguration_type"] = "WARNING: Wildcard used in repository path."
                    
    # Deduplicate allowed repositories after all subjects have been collected
    trust_data["allowed_repositories"] = list(set(trust_data["allowed_repositories"]))

    # Check for external organizations if allowed_orgs is provided
    if allowed_orgs:
        for sub in trust_data["allowed_repositories"]:
            try:
                # Expected format: repo:ORG/REPO:ref
                parts = sub.split(':')
                if len(parts) >= 2:
                    repo_full = parts[1] # ORG/REPO
                    org = repo_full.split('/')[0]
                    if org not in allowed_orgs and org != '*':
                        trust_data["external_org_warnings"].append(f"Repository '{repo_full}' belongs to organization '{org}' which is NOT in the allowed list.")
            except IndexError:
                pass # Malformed subject, ignore for org check

    return trust_data

def export_role_policies(iam_client: Any, role_data: Dict[str, Any], export_dir: str) -> None:
    """Exports all policies associated with a role to JSON files."""
    role_name = role_data['role_name']
    account_id = role_data['account_id']
    
    # Export Trust Policy
    trust_policy_doc = role_data.get('assume_role_policy_document', {})
    filename = os.path.join(export_dir, f"{account_id}_{role_name}_trust_policy.json")
    try:
        with open(filename, 'w') as f:
            json.dump(trust_policy_doc, f, indent=2)
    except IOError as e:
        logger.error(f"Could not write file {filename}: {e}")

    # Export Attached Policies
    for policy_info in role_data['permissions'].get('attached_policies', []):
        try:
            policy_response = iam_client.get_policy(PolicyArn=policy_info['arn'])
            version_id = policy_response['Policy']['DefaultVersionId']
            policy_version = iam_client.get_policy_version(PolicyArn=policy_info['arn'], VersionId=version_id)
            policy_document = policy_version['PolicyVersion']['Document']
            filename = os.path.join(export_dir, f"{account_id}_{role_name}_attached_{policy_info['name']}.json")
            with open(filename, 'w') as f:
                json.dump(policy_document, f, indent=2)
        except (ClientError, IOError) as e:
            logger.error(f"Could not export attached policy '{policy_info['name']}': {e}")

    # Export Inline Policies
    for policy_info in role_data['permissions'].get('inline_policies', []):
        try:
            policy_doc_response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_info['name'])
            policy_document = policy_doc_response['PolicyDocument']
            filename = os.path.join(export_dir, f"{account_id}_{role_name}_inline_{policy_info['name']}.json")
            with open(filename, 'w') as f:
                json.dump(policy_document, f, indent=2)
        except (ClientError, IOError) as e:
            logger.error(f"Could not export inline policy '{policy_info['name']}': {e}")


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

def format_report_human(report_data: Dict[str, Any], min_severity: str = 'LOW') -> str:
    """Formats the collected data into a human-readable report with colors and summary table."""
    
    c = Colors
    
    # Severity Mapping
    severity_rank = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1
    }
    
    min_rank = severity_rank.get(min_severity, 1)

    banner = f"""
{c.CYAN}{'='*80}
==          IAM Auditor for GitHub Actions OIDC Federation                    ==
{'='*80}{c.RESET}
"""
    output_lines = [banner]

    summary_data = []

    for account_id, profile_name in report_data["accounts_scanned"].items():
        output_lines.append(f"\n{c.BOLD}{c.WHITE}--- SCANNING ACCOUNT: {account_id} (Profile: {profile_name}) ---{c.RESET}")
        roles = [role for role in report_data["findings"] if role["account_id"] == account_id]

        if not roles:
            output_lines.append(f"\n{c.GREEN}[+] Scan complete. No roles with GitHub Actions OIDC federation were found.{c.RESET}")
            output_lines.append(f"{c.BLUE}[i] NOTE: Automated tools are helpful, but always perform manual validation to ensure full security coverage.{c.RESET}")
            continue

        for role in roles:
            # Collect findings for this role to determine max severity
            role_findings = []
            max_severity_found = 'LOW'
            
            # Check Trust Policy
            trust = role['trust_policy']
            if trust["is_misconfigured"]:
                role_findings.append(("CRITICAL", trust['misconfiguration_type']))
                max_severity_found = 'CRITICAL'
            
            # Check Permissions
            permissions = role['permissions']
            if permissions["has_administrator_access"]:
                role_findings.append(("CRITICAL", "AdministratorAccess"))
                max_severity_found = 'CRITICAL'
            
            for p in permissions.get("attached_policies", []) + permissions.get("inline_policies", []):
                for f in p.get("findings", []):
                    sev = 'LOW'
                    if "CRITICAL" in f: sev = 'CRITICAL'
                    elif "HIGH RISK" in f: sev = 'HIGH'
                    elif "MEDIUM RISK" in f: sev = 'MEDIUM'
                    elif "POTENTIAL RISK" in f: sev = 'LOW' # Treat potential as low for filtering base
                    
                    if severity_rank[sev] > severity_rank[max_severity_found]:
                        max_severity_found = sev
                    
                    role_findings.append((sev, f))

            # Filter logic: Only show role if it has a finding >= min_severity
            # OR if min_severity is LOW, show everything including roles with no findings (just info)
            if severity_rank[max_severity_found] < min_rank and min_severity != 'LOW':
                continue
            
            # Add to summary table
            summary_data.append({
                'role_name': role['role_name'], 
                'severity': max_severity_found, 
                'finding_count': len(role_findings)
            })

            # --- Detailed Output Construction ---
            output_lines.extend([
                f"\n{c.CYAN}" + "="*80 + f"{c.RESET}",
                f"{c.BOLD}[*] ROLE FOUND: {role['role_name']}{c.RESET}",
                f"    ARN: {role['arn']}",
                f"{c.CYAN}" + "-"*80 + f"{c.RESET}",
                f"\n{c.BOLD}[+] PERMISSIONS ANALYSIS{c.RESET}"
            ])
            
            if permissions.get("error"):
                 output_lines.append(f"  {c.RED}[!] {permissions['error']}{c.RESET}")
            
            if permissions["attached_policies"]:
                output_lines.append("  -> Attached Policies:")
                for policy in permissions["attached_policies"]:
                    output_lines.append(f"     - {c.WHITE}{policy['name']}{c.RESET}")
                    if "AdministratorAccess" in policy['name']:
                        output_lines.append(f"       {c.RED}{c.BOLD}[!!!] CRITICAL ALERT: This role has ADMINISTRATOR permissions!{c.RESET}")
                        output_lines.append(f"             For more details on the risks, see: {c.BLUE}https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/{c.RESET}")
                    
                    if policy.get("findings"):
                        for finding in policy["findings"]:
                            # Filter individual findings in detail view as well?
                            # Let's show all findings for the role if the role is shown, but maybe highlight relevant ones.
                            # Or strictly filter lines. Let's strictly filter lines for cleaner output.
                            
                            f_sev = 'LOW'
                            if "CRITICAL" in finding: f_sev = 'CRITICAL'
                            elif "HIGH RISK" in finding: f_sev = 'HIGH'
                            elif "MEDIUM RISK" in finding: f_sev = 'MEDIUM'
                            
                            if severity_rank[f_sev] < min_rank:
                                continue

                            if "CRITICAL" in finding:
                                output_lines.append(f"       {c.RED}{c.BOLD}[!!!] {finding}{c.RESET}")
                            elif "HIGH RISK" in finding:
                                output_lines.append(f"       {c.RED}[!!] {finding}{c.RESET}")
                            elif "MEDIUM RISK" in finding:
                                output_lines.append(f"       {c.YELLOW}[!] {finding}{c.RESET}")
                            else:
                                output_lines.append(f"       {c.YELLOW}[!] {finding}{c.RESET}")
                        
                        if policy.get('default_version_id'):
                            cmd = f"aws iam get-policy-version --policy-arn {policy['arn']} --version-id {policy['default_version_id']} --profile {profile_name}"
                            output_lines.append(f"       {c.BLUE}[i] To verify, inspect the policy: {cmd}{c.RESET}")


            if permissions["inline_policies"]:
                output_lines.append("  -> Inline Policies:")
                for policy in permissions["inline_policies"]:
                    output_lines.append(f"     - {c.WHITE}{policy['name']}{c.RESET}")
                    if policy.get("findings"):
                        for finding in policy["findings"]:
                           f_sev = 'LOW'
                           if "CRITICAL" in finding: f_sev = 'CRITICAL'
                           elif "HIGH RISK" in finding: f_sev = 'HIGH'
                           elif "MEDIUM RISK" in finding: f_sev = 'MEDIUM'
                           
                           if severity_rank[f_sev] < min_rank:
                               continue

                           if "CRITICAL" in finding:
                                output_lines.append(f"       {c.RED}{c.BOLD}[!!!] {finding}{c.RESET}")
                           elif "HIGH RISK" in finding:
                                output_lines.append(f"       {c.RED}[!!] {finding}{c.RESET}")
                           elif "MEDIUM RISK" in finding:
                                output_lines.append(f"       {c.YELLOW}[!] {finding}{c.RESET}")
                           else:
                                output_lines.append(f"       {c.YELLOW}[!] {finding}{c.RESET}")
                        cmd = f"aws iam get-role-policy --role-name {role['role_name']} --policy-name {policy['name']} --profile {profile_name}"
                        output_lines.append(f"       {c.BLUE}[i] To verify, inspect the policy: {cmd}{c.RESET}")

            if not permissions["attached_policies"] and not permissions["inline_policies"]:
                output_lines.append(f"  {c.GREEN}-> No attached or inline policies found.{c.RESET}")

            output_lines.append(f"\n{c.BOLD}[+] TRUST POLICY ANALYSIS (Conditions to assume the role){c.RESET}")
            trust = role['trust_policy']
            if trust["allowed_repositories"]:
                output_lines.append("  -> Allowed GitHub Repositories:")
                for repo in trust["allowed_repositories"]:
                    output_lines.append(f"     - {c.WHITE}{repo}{c.RESET}")
                
                if trust["is_misconfigured"]:
                     if severity_rank['CRITICAL'] >= min_rank:
                        output_lines.append(f"       {c.RED}{c.BOLD}[###] CRITICAL ALERT: {trust['misconfiguration_type']}{c.RESET}") # Changed label
                
                for warning in trust.get("external_org_warnings", []):
                     # Warnings are typically medium/low, treating as medium for visibility
                     if severity_rank['MEDIUM'] >= min_rank:
                        output_lines.append(f"       {c.YELLOW}[WARNING] {warning}{c.RESET}")

                if trust["is_misconfigured"] or trust.get("external_org_warnings"):
                    cmd = f"aws iam get-role --role-name {role['role_name']} --profile {profile_name}"
                    output_lines.append(f"       {c.BLUE}[i] To verify, inspect the trust policy: {cmd}{c.RESET}")
                    output_lines.append(f"\n  For a deep dive on how this can be exploited, read: {c.BLUE}https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/{c.RESET}")
            else:
                output_lines.append(f"  {c.YELLOW}-> No specific repository ('sub') condition found. This could be risky.{c.RESET}")

    # --- Summary Table ---
    if summary_data: # Changed from summary_rows to summary_data
        output_lines.append(f"\n{c.BOLD}" + "="*80 + f"{c.RESET}")
        output_lines.append(f"{c.BOLD}SUMMARY OF FINDINGS (Min Severity: {min_severity}){c.RESET}")
        output_lines.append(f"{c.BOLD}" + "-"*80 + f"{c.RESET}")
        output_lines.append(f"{c.BOLD}{'ROLE NAME':<40} | {'SEVERITY':<10} | {'DETAILS':<20} {c.RESET}")
        output_lines.append(f"{c.BOLD}" + "-"*80 + f"{c.RESET}")
        
        for item in summary_data: # Changed from summary_rows to summary_data
            role_name = item['role_name']
            severity = item['severity']
            count = item['finding_count']
            
            color = c.GREEN
            if severity == 'CRITICAL': color = c.RED
            elif severity == 'HIGH': color = c.RED
            elif severity == 'MEDIUM': color = c.YELLOW
            
            plural = "finding" if count == 1 else "findings" # Corrected pluralization
            output_lines.append(f"{item['role_name']:<40} | {color}{severity:<10}{c.RESET} | {count} {plural:<19}")
            
        output_lines.append(f"{c.BOLD}" + "="*80 + f"{c.RESET}\n") # Added newline for consistency

    return "\n".join(output_lines)

def format_report_csv(report_data: Dict[str, Any]) -> str:
    """Formats the collected data into a CSV string."""
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "Account ID", "Profile", "Role Name", "Role ARN", 
        "Allowed Repos", "Trust Misconfiguration", "External Org Warnings",
        "Attached Policies", "Inline Policies", "Findings"
    ])
    
    for role in report_data["findings"]:
        trust = role['trust_policy']
        permissions = role['permissions']
        
        allowed_repos = ", ".join(trust.get("allowed_repositories", []))
        trust_misc = trust.get("misconfiguration_type", "")
        ext_orgs = ", ".join(trust.get("external_org_warnings", []))
        
        attached = ", ".join([p['name'] for p in permissions.get("attached_policies", [])])
        inline = ", ".join([p['name'] for p in permissions.get("inline_policies", [])])
        
        all_findings = []
        for p in permissions.get("attached_policies", []) + permissions.get("inline_policies", []):
            all_findings.extend(p.get("findings", []))
        
        findings_str = "; ".join(all_findings)
        
        writer.writerow([
            role["account_id"], role["profile_name"], role["role_name"], role["arn"],
            allowed_repos, trust_misc, ext_orgs,
            attached, inline, findings_str
        ])
        
    return output.getvalue()

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description=f"{BANNER.strip()}\n\n{HELP_DESCRIPTION}",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--profile', help='A single AWS CLI profile to use for the audit.')
    group.add_argument('--profiles', nargs='+', help='A list of AWS CLI profiles to scan.')
    
    parser.add_argument('-o', '--output', help='File to write the report to (e.g., report.txt).', metavar='FILENAME')
    parser.add_argument('--json', action='store_true', help='Output the report in JSON format.')
    parser.add_argument('--csv', action='store_true', help='Output the report in CSV format.')
    parser.add_argument('--export', help='Export policies of all found roles to the specified directory.', metavar='DIRECTORY')
    parser.add_argument('--allowed-orgs', nargs='+', help='List of GitHub organizations that are trusted. Alerts on others.', metavar='ORG')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging (DEBUG level).')
    parser.add_argument('--min-severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW', help='Minimum severity level to report.')

    args = parser.parse_args()

    # Configure Logging Level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    profiles_to_scan = args.profiles or ([args.profile] if args.profile else ['default'])
    
    report_data: Dict[str, Any] = {
        "accounts_scanned": {},
        "findings": []
    }
    iam_client_map = {}

    # If outputting to stdout (no file) and JSON/CSV is requested, silence logs to stderr
    # so they don't break the structured output
    if not args.output and (args.json or args.csv):
        # Keep logs on stderr, but ensure print statements don't interfere
        pass
    else:
        print(BANNER)

    if args.export:
        try:
            os.makedirs(args.export, exist_ok=True)
            logger.info(f"Policies for all found roles will be exported to: {args.export}")
        except OSError as e:
            logger.error(f"Could not create export directory '{args.export}': {e}")
            sys.exit(1)


    for profile_name in profiles_to_scan:
        logger.info(f"Attempting to scan profile: '{profile_name}'")
        try:
            session = boto3.Session(profile_name=profile_name)
            iam_client = session.client('iam')
            sts_client = session.client('sts')
            
            account_id = sts_client.get_caller_identity()['Account']
            report_data["accounts_scanned"][account_id] = profile_name
            iam_client_map[account_id] = iam_client

            logger.info(f"Successfully connected to account {account_id}. Starting role analysis...")

            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    policy_doc = role.get('AssumeRolePolicyDocument', {})
                    if 'token.actions.githubusercontent.com' in json.dumps(policy_doc):
                        logger.debug(f"Found OIDC role: {role['RoleName']}")
                        permissions = get_role_permissions(iam_client, role['RoleName'])
                        trust_policy = analyze_role_trust(policy_doc, args.allowed_orgs)
                        
                        report_data["findings"].append({
                            "account_id": account_id,
                            "profile_name": profile_name,
                            "role_name": role['RoleName'],
                            "arn": role['Arn'],
                            "permissions": permissions,
                            "trust_policy": trust_policy,
                            "assume_role_policy_document": policy_doc
                        })
        
        except ClientError as e:
            error_message = f"Failed to scan profile '{profile_name}': {e.response['Error']['Code']}"
            if 'InvalidClientTokenId' in str(e) or 'ExpiredToken' in str(e):
                error_message = f"Invalid or expired credentials for profile '{profile_name}'."
            logger.error(error_message)
        except Exception as e:
            logger.error(f"An unexpected error occurred with profile '{profile_name}': {e}")

    # --- Export Policies if requested ---
    if args.export:
        logger.info("Exporting Policies for All Found Roles...")
        exported_count = 0
        for role_data in report_data.get("findings", []):
            logger.debug(f"Exporting policies for role: {role_data['role_name']}...")
            export_role_policies(iam_client_map[role_data['account_id']], role_data, args.export)
            exported_count += 1
        if exported_count == 0:
            logger.info("No roles found that required exporting.")


    # --- Output Generation ---
    output_content = ""
    if args.json:
        # Clean up data for JSON output
        for finding in report_data["findings"]:
            finding.pop("assume_role_policy_document", None)
        output_content = json.dumps(report_data, indent=2)
    elif args.csv:
        output_content = format_report_csv(report_data)
    else:
        output_content = format_report_human(report_data, args.min_severity)

    if args.output:
        # Disable colors when writing to file to avoid ANSI codes in text file
        Colors.RESET = ""
        Colors.BOLD = ""
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.CYAN = ""
        Colors.WHITE = ""
        
        try:
            with open(args.output, 'w') as f:
                f.write(output_content)
            logger.info(f"Report successfully saved to '{args.output}'")
        except IOError as e:
            logger.error(f"Could not write to file '{args.output}': {e}")
    else:
        # Print to stdout
        print(output_content)


if __name__ == "__main__":
    main()
