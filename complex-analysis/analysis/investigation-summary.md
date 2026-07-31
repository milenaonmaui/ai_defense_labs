# Investigation Summary: Azure Session Hijacking Incident

## Executive Summary
On March 1, 2025, we detected unauthorized access to Azure resources via browser cookie theft. The attacker leveraged Chrome's remote debugging feature to steal session cookies, then used those cookies to access Azure AD as the victim user.

## Timeline
- 14:32:15 - Chrome launched with --remote-debugging-port=9222
- 14:33:00 - PowerShell script accessed Chrome debugging endpoint
- 14:35:22 - Cookies extracted and exfiltrated
- 14:45:00 - Azure sign-in from attacker IP using stolen cookies
- 14:52:00 - Attacker enumerated Azure AD users and groups

## ATT&CK Techniques
- T1539 - Steal Web Session Cookie (High confidence)
- T1087.004 - Account Discovery: Cloud Account (High confidence)  
- T1078.004 - Valid Accounts: Cloud Accounts (High confidence)

## Indicators of Compromise
- Process: chrome.exe --remote-debugging-port=9222
- IP: 203.0.113.42 (attacker Azure access)
- User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...

## Impact
- One user account compromised
- Azure AD enumeration performed
- No evidence of data exfiltration (yet)

## Recommendations
1. Force password reset for affected user
2. Revoke all Azure AD sessions for the user
3. Implement Conditional Access policies for location/device
4. Deploy detection for Chrome remote debugging usage
