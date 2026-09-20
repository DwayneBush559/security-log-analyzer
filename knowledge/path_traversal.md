# Path Traversal Response

## Indicators
Sequences such as ../, encoded traversal characters, or attempts to access operating-system files can indicate path traversal.

## Immediate actions
1. Preserve application and reverse-proxy logs.
2. Determine which file-serving endpoint accepted the untrusted path.
3. Canonicalize and validate paths against an explicit allowed directory.
4. Reject paths that resolve outside the intended storage root.
5. Review file permissions and determine whether sensitive files were exposed.

## Prevention
Use allowlisted identifiers rather than accepting raw filesystem paths from clients whenever possible.
