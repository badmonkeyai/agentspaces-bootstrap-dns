# Security Policy

AgentSpaces Bootstrap :: dnsjava answers the DNS questions a newcomer's
bootstrap locators ask when it looks for a group to join. With DNSSEC on, it
also vouches for those answers: `authenticated() == true` is what lets a `dns`
locator accept a GroupId from DNS. It inherits the security model of the
AgentSpaces core (signed, self-certifying peers and agents; the threat model in
the AgentSpaces specification, SPEC §11).

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's security advisories:

> https://github.com/badmonkeyai/agentspaces-bootstrap-dns/security/advisories/new

A vulnerability in the locators, the `DnsResolver` SPI, or how a GroupId from
DNS is trusted belongs in the bootstrap repository's advisories:
https://github.com/badmonkeyai/agentspaces-bootstrap/security/advisories/new

A vulnerability in dnsjava itself belongs with the dnsjava project:
https://github.com/dnsjava/dnsjava/security

Do not open public issues for suspected vulnerabilities, and do not include
exploit details in public discussions until a fix is released.

We will acknowledge your report within five business days, keep you informed of
progress, credit you in the advisory unless you prefer otherwise, and
coordinate the disclosure timeline with you. There is currently no bug bounty
program.

Questions can be sent to `oss [at] badmonkey.ai`

## Scope

In scope: anything in this repository that lets an attacker make the resolver
vouch for an answer it should not. For example:
- a validating resolver (`dnssec(true)`) that returns a bogus or insecure
  answer instead of failing;
- a resolver configured for DNS over HTTPS that falls back to plain DNS, or
  sends a query anywhere other than the configured URL;
- trust anchors that differ from the root's published DS records, or a
  `trustAnchors(...)` input that is accepted when malformed;
- a response that crashes the resolver or holds it past its timeout.

Without DNSSEC (the default), `authenticated()` is `false` and answers are
returned as the server gave them; spoofing an unauthenticated answer is a
property of plain DNS, and the locators already treat such answers as
unauthenticated.

## Supported versions

During 0.x, only the latest minor release receives security fixes.
