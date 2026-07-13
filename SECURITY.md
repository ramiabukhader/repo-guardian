# Security policy

## Supported versions

Security fixes are provided for the latest tagged release. Before `v1.0.0`,
minor releases may include compatibility changes described in their release
notes.

## Reporting a vulnerability

Use this repository's **Security** tab and choose **Report a vulnerability**.
Include the affected version, operating system, reproduction steps, impact,
and a minimal proof of concept. Do not include real credentials, tokens, or
private repository content.

Please avoid filing a public issue for an unpatched vulnerability. You can
expect an initial response within seven days. Valid reports will be assessed,
fixed on a private branch when appropriate, and credited with the reporter's
permission.

## Security boundary

repo-guardian is an offline metadata auditor. It reads paths, file modes,
sizes, and the local Git index. It does not open file contents and does not
perform network requests. Risk detection is intentionally based on filenames,
locations, sizes, and tracked state; it is not a secret scanner, malware
scanner, or substitute for code review.

The tool skips symlinks and known dependency/VCS directories. Human-readable
paths are quoted and JSON paths are escaped, but reports include the absolute
scan root. Review reports before sharing them outside your organization.
