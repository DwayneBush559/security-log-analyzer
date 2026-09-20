# SQL Injection Response

## Indicators
Requests containing UNION SELECT, tautologies such as OR 1=1, database error leakage, or unusual query-string payloads can indicate SQL injection attempts.

## Immediate actions
1. Preserve web, API gateway, WAF, and database logs.
2. Identify the vulnerable endpoint and affected parameters.
3. Remove direct string concatenation from database queries and use parameterized queries.
4. Restrict database permissions to the minimum required by the application.
5. Review whether sensitive records were read, modified, or deleted.

## Containment
A WAF rule may reduce exposure, but it should not replace correcting the vulnerable query construction in the application.
