# Security Policy

## Responsible use

VulnScan Pro performs **active** security testing (it sends probes, including
injection payloads, to the target). Only scan systems you own or have explicit,
written authorisation to test. Unauthorised scanning may be illegal in your
jurisdiction.

`SAFE_MODE` is enabled by default and blocks scans of private / loopback /
link-local / reserved addresses to prevent the tool being pointed at internal
infrastructure or cloud metadata endpoints.

## Reporting a vulnerability

If you find a security issue in VulnScan Pro itself, please open a private
report via GitHub Security Advisories on this repository, or contact the
maintainer directly. Please do not open a public issue for undisclosed
vulnerabilities.

## Scope

- In scope: the scanner backend, API, and web UI in this repository.
- Out of scope: the deliberately vulnerable demo app under `vulnerable-webapp/`,
  which exists solely for local testing and is insecure by design.
