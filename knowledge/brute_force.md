# Brute-Force Login Response

## Indicators
Repeated authentication failures from the same source IP, especially against one or more privileged accounts, may indicate password spraying or brute-force activity.

## Immediate actions
1. Preserve the relevant authentication logs and timestamps.
2. Identify the targeted accounts and source addresses.
3. Temporarily rate-limit or block clearly malicious sources when operationally safe.
4. Force a credential reset for affected accounts when compromise is suspected.
5. Confirm multi-factor authentication is enabled for privileged and exposed accounts.

## Investigation
Correlate successful logins that occur after repeated failures. Review geolocation, device, session, and identity-provider telemetry before concluding that an account was compromised.
