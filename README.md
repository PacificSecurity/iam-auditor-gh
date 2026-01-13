# IAM Auditor for GitHub Actions Federation

A command-line tool in Python, created for the first Pacific Security Webinar, to help participants audit and identify misconfigurations in IAM roles that use OIDC federation with GitHub Actions.


## The Problem

Using OIDC federation between GitHub Actions and AWS is a modern and secure practice for granting permissions to CI/CD workflows without needing long-lived static credentials. However, an improper configuration in the Trust Policy of these roles can create critical security breaches, allowing unauthorized repositories to assume permissions in your AWS account, leading to potential privilege escalation and a full environment compromise.

To deeply understand the risks and attack vectors, read our article: [**Abusing GitHub Actions to Compromise AWS Accounts**](https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/).

## What does this tool do?

This script automates the audit across one or multiple AWS accounts, searching for IAM roles that trust GitHub's OIDC provider (`token.actions.githubusercontent.com`) and analyzing them for common security flaws.

**Key Features:**

*   **Multi-Account Scanning:** Analyzes several AWS accounts in a single run using AWS CLI profiles.
*   **Privilege Escalation Detection (CloudPEASS):** Identifies risky permission combinations based on the **CloudPEASS** project.
*   **Educational Links:** Provides direct links to **HackTricks** for every detected risk (e.g., `iam:PassRole` -> `aws-iam-privesc`).
*   **Rich CLI Output:** Uses colors (Red/Yellow/Green) and a **Summary Table** to highlight risks effectively.
*   **Filtering:** Focus on what matters with `--min-severity` (e.g., show only HIGH/CRITICAL).
*   **Trust Policy Analysis:** Identifies dangerous configurations like wildcards (`*`) in repository paths.
*   **Security Lock:** Validates if trusted repositories belong to allowed organizations via `--allowed-orgs`.
*   **Flexible Output:** JSON, CSV, and human-readable formats.

---

## Installation and Prerequisites

1.  **Python 3:** You need Python 3.6 or higher installed.
2.  **AWS CLI:** The tool uses the profiles configured in your AWS CLI. Make sure it is installed and configured (`aws configure`).
3.  **Boto3 Library:** Install the AWS SDK for Python.
    ```bash
    pip install -r requirements.txt
    ```
4.  **Clone the Repository:**
    ```bash
    git clone https://github.com/PacificSecurity/iam-auditor-gh
    cd iam-auditor-gh
    ```

---

## Usage

### Basic Scan
Scan the default AWS profile:
```bash
python iam_auditor_gh.py
```

### Advanced Options

**Filter by Severity:**
Show only HIGH and CRITICAL risks:
```bash
python iam_auditor_gh.py --min-severity HIGH
```

**Security Lock (Allowed Orgs):**
Alert if any role trusts a repository outside your organization:
```bash
python iam_auditor_gh.py --allowed-orgs my-org another-org
```

**Export to CSV:**
```bash
python iam_auditor_gh.py --csv -o report.csv
```

**Scan Multiple Profiles:**
```bash
python iam_auditor_gh.py --profiles prod-account dev-account
```

**Verbose Mode:**
```bash
python iam_auditor_gh.py -v
```

*   **View all options:**
    ```bash
    python iam_auditor_gh.py --help
    ```

---

## Understanding the Output

The report is divided into sections for each role found:

*   **`[*] ROLE FOUND`**: Basic information about the role, including its name and ARN.
*   **`[+] PERMISSIONS ANALYSIS`**: Details the permissions attached to the role.
    *   **`[!!!] CRITICAL ALERT`**: Indicates the role has `AdministratorAccess`. This is the highest risk level.
    *   **`[!!] HIGH RISK`**: Indicates the role has permissions that allow **Privilege Escalation** (e.g., `iam:CreatePolicyVersion`, `iam:PassRole`). The tool provides a direct link to **HackTricks** explaining how an attacker could exploit this.
    *   **`[!] POTENTIAL RISK`**: Highlights the use of wildcards (`*`) within a policy's `Action` or `Resource`.
*   **`[+] TRUST POLICY ANALYSIS`**: Shows which GitHub repositories are allowed to assume this role.
    *   **`[###] SEVERE MISCONFIGURATION`**: Alerts when the trust policy is overly permissive (e.g., `repo:*:*`).
*   **`[i] To verify...`**: Provides the exact AWS CLI command to inspect a specific finding manually.



### Example Output

$ python iam_auditor_gh.py --profile audit-profile

```

================================================================================
==          IAM Auditor for GitHub Actions OIDC Federation                    ==
================================================================================

2025-12-03 14:07:38 - INFO - Successfully connected to account 123456789012. Starting role analysis...

================================================================================
[*] ROLE FOUND: admin-git
    ARN: arn:aws:iam::123456789012:role/admin-git
--------------------------------------------------------------------------------

[+] PERMISSIONS ANALYSIS
  -> Attached Policies:
     - AdministratorAccess
       [!!!] CRITICAL ALERT: This role has ADMINISTRATOR permissions!
             For more details on the risks, see: https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/
       [!!!] CRITICAL: Action: '*' on Resource: '*' (AdministratorAccess)
       [i] To verify, inspect the policy: aws iam get-policy-version ...

[+] TRUST POLICY ANALYSIS (Conditions to assume the role)
  -> Allowed GitHub Repositories:
     - repo:MyOrg/Master:*

================================================================================
[*] ROLE FOUND: bucket-all-git
    ARN: arn:aws:iam::123456789012:role/bucket-all-git
--------------------------------------------------------------------------------

[+] PERMISSIONS ANALYSIS
  -> Attached Policies:
     - bucket-all

[+] TRUST POLICY ANALYSIS (Conditions to assume the role)
  -> Allowed GitHub Repositories:
     - repo:MyOrg*/Cloud-test:*
       [###] CRITICAL ALERT: Wildcard used in repository path.
       [i] To verify, inspect the trust policy: aws iam get-role ...

  For a deep dive on how this can be exploited, read: https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/

================================================================================
[*] ROLE FOUND: ec2-git
    ARN: arn:aws:iam::123456789012:role/ec2-git
--------------------------------------------------------------------------------

[+] PERMISSIONS ANALYSIS
  -> Attached Policies:
     - ec2-github
       [!] MEDIUM RISK: Sensitive permission 'ecs:RunTask' on Resource: '*'. Info: https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ecs-privesc/index.html#ecs-runtask
       [!!] HIGH RISK: Potential Privilege Escalation via 'iam:PassRole' on Resource: '*'. Info: https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-iam-privesc/index.html#iam-passrole
       [i] To verify, inspect the policy: aws iam get-policy-version ...

[+] TRUST POLICY ANALYSIS (Conditions to assume the role)
  -> Allowed GitHub Repositories:
     - repo:MyOrg/super-broccoli:*

================================================================================
SUMMARY OF FINDINGS (Min Severity: LOW)
--------------------------------------------------------------------------------
ROLE NAME                                | SEVERITY   | DETAILS          
--------------------------------------------------------------------------------
admin-git                                | CRITICAL   | 2 findings         
bucket-all-git                           | CRITICAL   | 1 finding          
bucket-git                               | LOW        | 0 findings         
ec2-git                                  | HIGH       | 2 findings         
git-iam                                  | CRITICAL   | 3 findings         
================================================================================
```

### Analyzing the Results
In this example scan, we found **5 roles** that can be assumed by GitHub Actions workflows. The audit reveals significant security risks:
*   **`admin-git`**: Has full `AdministratorAccess`, meaning any workflow in `MyOrg/Master` can take over the entire AWS account.
*   **`bucket-all-git`**: Contains a **Critical Trust Policy Misconfiguration** (wildcard `*` in the organization name), allowing potentially any GitHub organization starting with "MyOrg" to assume this role.
*   **`ec2-git`**: Has high-risk privilege escalation vectors (`iam:PassRole`) and sensitive permissions (`ecs:RunTask`), which could be chained to gain higher privileges.

---

## Minimum IAM Permissions

For the script to work correctly, the identity (user or role) used for scanning needs at least the following IAM permissions:

*   `iam:ListRoles`
*   `iam:ListAttachedRolePolicies`
*   `iam:ListRolePolicies`
*   `iam:GetPolicy`
*   `iam:GetPolicyVersion`
*   `iam:GetRolePolicy`

The AWS managed policy `IAMReadOnlyAccess` is sufficient to cover most of these requirements, but you may need to add `iam:GetRolePolicy`.

---


---

## Credits & References

*   **CloudPEASS**: The comprehensive list of sensitive permissions is derived from [CloudPEASS](https://github.com/carlospolop/CloudPEASS/blob/main/src/sensitive_permissions/aws.py) by Carlos Polop.
*   **HackTricks**: Exploitation techniques and documentation are linked from [HackTricks Cloud](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/index.html).
*   **Research**: Based on my research into GitHub Actions OIDC security risks (e.g., [Pacific Security](https://article.pacificsec.com/blog/2025-02-03-abusing-github-actions-to-compromise-aws-accounts/)).

---

## License

This project is licensed under the MIT License.
