#!/usr/bin/env python3

import boto3
import json
import argparse
import sys
import os
from botocore.exceptions import ClientError

# --- Banner and Help Text ---

BANNER = """
================================================================================
==          IAM Auditor for GitHub Actions OIDC Federation                    ==
================================================================================
"""

HELP_DESCRIPTION = """
This tool helps you identify IAM roles that trust GitHub's OIDC provider and
checks them for common security misconfigurations.

EXAMPLES:
  # Scan the default profile
  python %(prog)s

  # Scan a specific profile and save the report to a file
  python %(prog)s --profile my-audit-profile -o report.txt

  # Scan multiple profiles and export all found role policies to a directory
  python %(prog)s --profiles prof1 prof2 --export audit_files/

  # Scan and output the results in JSON format
  python %(prog)s --json -o report.json
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

# --- Analysis Functions ---

def analyze_policy_document(policy_doc):
    """Analyzes a policy document for risky wildcard permissions."""
    findings = []
    if not policy_doc or 'Statement' not in policy_doc:
        return findings

    statements = policy_doc['Statement']
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') == 'Allow':
            actions = stmt.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]

            resources = stmt.get('Resource', [])
            if not isinstance(resources, list):
                resources = [resources]

            for action in actions:
                if '*' in action:
                    for resource in resources:
                        if resource == '*':
                            findings.append(f"Action: '{action}' on Resource: '*' (All resources)")
                        else:
                            findings.append(f"Action: '{action}' on Resource: '{resource}'")
    return findings

def get_role_permissions(iam_client, role_name):
    """
    Analyzes the permissions of a role and returns a structured dictionary.
    """
    permissions_data = {
        "attached_policies": [],
        "inline_policies": [],
        "has_administrator_access": False
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
            except ClientError:
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
            except ClientError:
                policy_info["findings"].append("Could not retrieve policy document to analyze.")
            
            permissions_data["inline_policies"].append(policy_info)

    except ClientError as e:
        permissions_data["error"] = f"Could not retrieve permissions: {e.response['Error']['Code']}"

    return permissions_data

def analyze_role_trust(policy_doc):
    """
    Analyzes the trust policy document and returns a structured dictionary.
    """
    trust_data = {
        "allowed_repositories": [],
        "is_misconfigured": False,
        "misconfiguration_type": None
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
                    if sub.lower() == "repo:*:*":
                        trust_data["is_misconfigured"] = True
                        trust_data["misconfiguration_type"] = "SEVERE: Wildcard allows ANY GitHub repository."
                    elif not trust_data["is_misconfigured"] and "*" in sub.split(':')[1]:
                        trust_data["is_misconfigured"] = True
                        trust_data["misconfiguration_type"] = "WARNING: Wildcard used in repository path."
    return trust_data

def export_role_policies(iam_client, role_data, export_dir):
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
        print(f"[!] Could not write file {filename}: {e}", file=sys.stderr)

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
            print(f"[!] Could not export attached policy '{policy_info['name']}': {e}", file=sys.stderr)

    # Export Inline Policies
    for policy_info in role_data['permissions'].get('inline_policies', []):
        try:
            policy_doc_response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_info['name'])
            policy_document = policy_doc_response['PolicyDocument']
            filename = os.path.join(export_dir, f"{account_id}_{role_name}_inline_{policy_info['name']}.json")
            with open(filename, 'w') as f:
                json.dump(policy_document, f, indent=2)
        except (ClientError, IOError) as e:
            print(f"[!] Could not export inline policy '{policy_info['name']}': {e}", file=sys.stderr)


def format_report_human(report_data):
    """Formats the collected data into a human-readable report."""
    output_lines = [BANNER]
    for account_id, profile_name in report_data["accounts_scanned"].items():
        output_lines.append(f"\n--- SCANNING ACCOUNT: {account_id} (Profile: {profile_name}) ---")
        roles = [role for role in report_data["findings"] if role["account_id"] == account_id]

        if not roles:
            output_lines.append("\n[+] Scan complete. No roles with GitHub Actions OIDC federation were found.")
            output_lines.append("[i] NOTE: Automated tools are helpful, but always perform manual validation to ensure full security coverage.")
            continue

        for role in roles:
            output_lines.extend([
                "\n" + "="*80,
                f"[*] ROLE FOUND: {role['role_name']}",
                f"    ARN: {role['arn']}",
                "-"*80,
                "\n[+] PERMISSIONS ANALYSIS"
            ])
            
            permissions = role['permissions']
            if permissions.get("error"):
                 output_lines.append(f"  [!] {permissions['error']}")
            
            if permissions["attached_policies"]:
                output_lines.append("  -> Attached Policies:")
                for policy in permissions["attached_policies"]:
                    output_lines.append(f"     - {policy['name']}")
                    if "AdministratorAccess" in policy['name']:
                        output_lines.append("       [!!!] CRITICAL ALERT: This role has ADMINISTRATOR permissions!")
                        output_lines.append("             For more details on the risks, see: https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/")
                    
                    if policy.get("findings"):
                        for finding in policy["findings"]:
                            output_lines.append(f"       [!!] POTENTIAL RISK: {finding}")
                        if policy.get('default_version_id'):
                            cmd = f"aws iam get-policy-version --policy-arn {policy['arn']} --version-id {policy['default_version_id']} --profile {profile_name}"
                            output_lines.append(f"       [i] To verify, inspect the policy: {cmd}")


            if permissions["inline_policies"]:
                output_lines.append("  -> Inline Policies:")
                for policy in permissions["inline_policies"]:
                    output_lines.append(f"     - {policy['name']}")
                    if policy.get("findings"):
                        for finding in policy["findings"]:
                           output_lines.append(f"       [!!] POTENTIAL RISK: {finding}")
                        cmd = f"aws iam get-role-policy --role-name {role['role_name']} --policy-name {policy['name']} --profile {profile_name}"
                        output_lines.append(f"       [i] To verify, inspect the policy: {cmd}")

            if not permissions["attached_policies"] and not permissions["inline_policies"]:
                output_lines.append("  -> No attached or inline policies found.")

            output_lines.append("\n[+] TRUST POLICY ANALYSIS (Conditions to assume the role)")
            trust = role['trust_policy']
            if trust["allowed_repositories"]:
                output_lines.append("  -> Allowed GitHub Repositories:")
                for repo in trust["allowed_repositories"]:
                    output_lines.append(f"     - {repo}")
                if trust["is_misconfigured"]:
                    output_lines.append(f"       [###] {trust['misconfiguration_type']}")
                    cmd = f"aws iam get-role --role-name {role['role_name']} --profile {profile_name}"
                    output_lines.append(f"       [i] To verify, inspect the trust policy: {cmd}")
                    output_lines.append("\n  For a deep dive on how this can be exploited, read: https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/")
            else:
                output_lines.append("  -> No specific repository ('sub') condition found. This could be risky.")

    return "\n".join(output_lines)

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
    parser.add_argument('--export', help='Export policies of all found roles to the specified directory.', metavar='DIRECTORY')
    
    args = parser.parse_args()

    profiles_to_scan = args.profiles or ([args.profile] if args.profile else ['default'])
    
    report_data = {
        "accounts_scanned": {},
        "findings": []
    }
    iam_client_map = {}

    original_stdout = sys.stdout
    if not args.json:
        print(BANNER)

    if args.export:
        try:
            os.makedirs(args.export, exist_ok=True)
            print(f"[*] Policies for all found roles will be exported to: {args.export}")
        except OSError as e:
            print(f"[ERROR] Could not create export directory '{args.export}': {e}", file=sys.stderr)
            sys.exit(1)


    for profile_name in profiles_to_scan:
        if not args.json:
            print(f"\n--- Attempting to scan profile: '{profile_name}' ---")
        try:
            session = boto3.Session(profile_name=profile_name)
            iam_client = session.client('iam')
            sts_client = session.client('sts')
            
            account_id = sts_client.get_caller_identity()['Account']
            report_data["accounts_scanned"][account_id] = profile_name
            iam_client_map[account_id] = iam_client

            if not args.json:
                print(f"[*] Successfully connected to account {account_id}. Starting role analysis...")

            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    policy_doc = role.get('AssumeRolePolicyDocument', {})
                    if 'token.actions.githubusercontent.com' in json.dumps(policy_doc):
                        permissions = get_role_permissions(iam_client, role['RoleName'])
                        trust_policy = analyze_role_trust(policy_doc)
                        
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
            error_message = f"[ERROR] Failed to scan profile '{profile_name}': {e.response['Error']['Code']}"
            if 'InvalidClientTokenId' in str(e) or 'ExpiredToken' in str(e):
                error_message = f"[ERROR] Invalid or expired credentials for profile '{profile_name}'."
            print(error_message, file=original_stdout if args.output else sys.stderr)
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred with profile '{profile_name}': {e}", file=original_stdout if args.output else sys.stderr)

    # --- Export Policies if requested ---
    if args.export:
        print("\n--- Exporting Policies for All Found Roles ---")
        exported_count = 0
        for role_data in report_data.get("findings", []):
            print(f"[*] Exporting policies for role: {role_data['role_name']}...")
            export_role_policies(iam_client_map[role_data['account_id']], role_data, args.export)
            exported_count += 1
        if exported_count == 0:
            print("[+] No roles found that required exporting.")


    # --- Output Generation ---
    output_content = ""
    if args.json:
        # Clean up data for JSON output
        for finding in report_data["findings"]:
            finding.pop("assume_role_policy_document", None)
        output_content = json.dumps(report_data, indent=2)
    else:
        output_content = format_report_human(report_data)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output_content)
            print(f"\nReport successfully saved to '{args.output}'", file=original_stdout)
        except IOError as e:
            print(f"[ERROR] Could not write to file '{args.output}': {e}", file=original_stdout)
    else:
        # Avoid printing the banner twice
        if not args.output and not args.json:
             print("\n" + "\n".join(output_content.splitlines()[4:])) # Skips banner
        elif not args.output and args.json:
             print(output_content)


if __name__ == "__main__":
    main()
