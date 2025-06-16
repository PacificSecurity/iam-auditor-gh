# IAM Auditor for GitHub Actions Federation

A command-line tool in Python, created for the first Pacific Security Webinar, to help participants audit and identify misconfigurations in IAM roles that use OIDC federation with GitHub Actions.


## The Problem

Using OIDC federation between GitHub Actions and AWS is a modern and secure practice for granting permissions to CI/CD workflows without needing long-lived static credentials. However, an improper configuration in the Trust Policy of these roles can create critical security breaches, allowing unauthorized repositories to assume permissions in your AWS account, leading to potential privilege escalation and a full environment compromise.

To deeply understand the risks and attack vectors, read our article: [**Abusing GitHub Actions to Compromise AWS Accounts**](https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/).

## What does this tool do?

This script automates the audit across one or multiple AWS accounts, searching for IAM roles that trust GitHub's OIDC provider (`token.actions.githubusercontent.com`) and analyzing them for common security flaws.

**Key Features:**

* **Multi-Account Scanning:** Analyzes several AWS accounts in a single run using AWS CLI profiles.
* **Critical Permission Detection:** Specifically alerts when a role has the `AdministratorAccess` policy.
* **In-Depth Policy Analysis:** Scans the content of attached and inline policies for risky wildcards (`*`) in actions or resources.
* **Trust Policy Analysis:** Identifies dangerous configurations in the trust policy, such as the use of wildcards (`*`) in the repository path.
* **Actionable Forensics:** Exports all found policies to a local directory for offline analysis and forensics.
* **Flexible Output:** Generates reports in a human-readable format or in JSON for integration with other tools.

---

## Installation and Prerequisites

1.  **Python 3:** You need Python 3.6 or higher installed.
2.  **AWS CLI:** The tool uses the profiles configured in your AWS CLI. Make sure it is installed and configured (`aws configure`).
3.  **Boto3 Library:** Install the AWS SDK for Python.
    ```bash
    pip install boto3
    ```
4.  **Clone the Repository:**
    ```bash
    git clone https://github.com/PacificSecurity/iam-auditor-gh
    cd iam-auditor-gh
    ```

---

## How to Use

The tool can be run directly from the command line.

**Usage Examples:**

* **Scan the `default` AWS CLI profile:**
    ```bash
    python iam_auditor_gh.py
    ```
* **Scan a specific profile and save the report to a file:**
    ```bash
    python iam_auditor_gh.py --profile my-security-profile -o report.txt
    ```
* **Scan multiple accounts and export all policies to a directory:**
    ```bash
    python iam_auditor_gh.py --profiles dev staging --export audit_files/
    ```
* **Generate a report in JSON format:**
    ```bash
    python iam_auditor_gh.py --profiles dev staging --json -o report.json
    ```
* **View all options:**
    ```bash
    python iam_auditor_gh.py --help
    ```

---

## Understanding the Output

The report is divided into sections for each role found:

* **`[*] ROLE FOUND`**: Basic information about the role, including its name and ARN.
* **`[+] PERMISSIONS ANALYSIS`**: Details the permissions attached to the role.
    * **`[!!!] CRITICAL ALERT`**: Indicates the role has `AdministratorAccess`. This is the highest risk level.
    * **`[!!] POTENTIAL RISK`**: Highlights the use of wildcards (`*`) within a policy's `Action` or `Resource`, which may grant excessive permissions.
* **`[+] TRUST POLICY ANALYSIS`**: Shows which GitHub repositories are allowed to assume this role.
    * **`[###] SEVERE MISCONFIGURATION`**: Alerts when the trust policy is overly permissive (e.g., `repo:*:*`), allowing any repository on GitHub to assume the role.
* **`[i] To verify...`**: Provides the exact AWS CLI command to inspect a specific finding manually.

### Example Output

```
$ python iam_auditor_gh.py --export policy_exports/
================================================================================
==          IAM Auditor for GitHub Actions OIDC Federation                    ==
================================================================================

[*] Policies for all found roles will be exported to: policy_exports/

--- Attempting to scan profile: 'default' ---
[*] Successfully connected to account XXXXXXXXXXXX. Starting role analysis...

--- Exporting Policies for All Found Roles ---
[*] Exporting policies for role: IAMCheckRole...
[*] Exporting policies for role: PacificWebinarParticipantRole...
[*] Exporting policies for role: TextAccess...


--- SCANNING ACCOUNT: XXXXXXXXXXXX (Profile: default) ---

================================================================================
[*] ROLE FOUND: IAMCheckRole
    ARN: arn:aws:iam::XXXXXXXXXXXX:role/IAMCheckRole
--------------------------------------------------------------------------------

[+] PERMISSIONS ANALYSIS
  -> Attached Policies:
     - IAMFullReadOnly
       [!!] POTENTIAL RISK: Action: 'iam:Get*' on Resource: '*' (All resources)
       [!!] POTENTIAL RISK: Action: 'iam:List*' on Resource: '*' (All resources)
       [i] To verify, inspect the policy: aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/IAMFullReadOnly --version-id v1 --profile default

[+] TRUST POLICY ANALYSIS (Conditions to assume the role)
  -> Allowed GitHub Repositories:
     - repo:GrayHat-Consultoria/IAM-CHECK:*

================================================================================
[*] ROLE FOUND: PacificWebinarParticipantRole
    ARN: arn:aws:iam::XXXXXXXXXXXX:role/PacificWebinarParticipantRole
--------------------------------------------------------------------------------

[+] PERMISSIONS ANALYSIS
  -> Attached Policies:
     - PacificWebinarParticipantPolicy

[+] TRUST POLICY ANALYSIS (Conditions to assume the role)
  -> Allowed GitHub Repositories:
     - repo:*/pacsecwebinar:*
       [###] SEVERE MISCONFIGURATION: Wildcard used in repository path.
       [i] To verify, inspect the trust policy: aws iam get-role --role-name PacificWebinarParticipantRole --profile default

  For a deep dive on how this can be exploited, read: [https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/](https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/)

================================================================================
[*] ROLE FOUND: TextAccess
    ARN: arn:aws:iam::XXXXXXXXXXXX:role/TextAccess
--------------------------------------------------------------------------------

[+] PERMISSIONS ANALYSIS
  -> Attached Policies:
     - AdministratorAccess
       [!!!] CRITICAL ALERT: This role has ADMINISTRATOR permissions!
             For more details on the risks, see: [https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/](https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/)
       [!!] POTENTIAL RISK: Action: '*' on Resource: '*' (All resources)
       [i] To verify, inspect the policy: aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --version-id v1 --profile default

[+] TRUST POLICY ANALYSIS (Conditions to assume the role)
  -> Allowed GitHub Repositories:
     - repo:GrayHat-Consultoria/text-generator:*

```

---

## Minimum IAM Permissions

For the script to work correctly, the identity (user or role) used for scanning needs at least the following IAM permissions:

* `iam:ListRoles`
* `iam:ListAttachedRolePolicies`
* `iam:ListRolePolicies`
* `iam:GetPolicy`
* `iam:GetPolicyVersion`
* `iam:GetRolePolicy`

The AWS managed policy `IAMReadOnlyAccess` is sufficient to cover most of these requirements, but you may need to add `iam:GetRolePolicy`.

---


## License

This project is licensed under the MIT License.
