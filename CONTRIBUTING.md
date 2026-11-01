# Contributing to AgentSpaces Bootstrap :: dnsjava

Thank you for your interest in contributing. AgentSpaces Bootstrap :: dnsjava is
an Apache 2.0 project from Bad Monkey, Inc., and everything in this repository
stays Apache 2.0.

This repository holds one class: the [dnsjava](https://github.com/dnsjava/dnsjava)
implementation of the `DnsResolver` SPI, with DNS over HTTPS and DNSSEC
validation. The SPI and the locators that call it live in
[agentspaces-bootstrap](https://github.com/badmonkeyai/agentspaces-bootstrap);
the coordination fabric itself lives in the
[AgentSpaces core repository](https://github.com/badmonkeyai/agentspaces).

## Before you start

- **Questions and ideas** are welcome as [GitHub issues](https://github.com/badmonkeyai/agentspaces-bootstrap-dns/issues).
- **Security issues** must not be filed as public issues. See
  [SECURITY.md](SECURITY.md) for private reporting.
- **Code of conduct:** by participating you agree to the
  [code of conduct](CODE_OF_CONDUCT.md).

## The rules a change must keep

- **`authenticated()` must stay honest.** It is a flag on the resolver, so with
  `dnssec(true)` every answer the resolver returns must have validated. A
  bogus or insecure answer is an `IOException`, never a returned result. A
  change that returns an unvalidated answer from a validating resolver breaks
  the guarantee the `dns` locators rely on to accept a GroupId from DNS.
- **The SPI's answer rules.** NXDOMAIN and no data are an empty list; a
  timeout, SERVFAIL, REFUSED, or an unreachable server is an `IOException`
  naming the record type, the name, and the cause. The README's "What the
  answers mean" section is the contract.
- **The trust anchors are data.** `root-anchors.txt` holds the root's DS
  records as IANA publishes them. Change it only to follow a root key roll,
  and cite the IANA source in the pull request.
- **dnsjava stays declared, not bundled.** Its BSD-2-Clause licence is named
  in `NOTICE`. Update `NOTICE` when the dependency or its licence changes.
- **No framework.** The enforcer bans Spring and Micronaut. A host selects this
  resolver by defining a bean, so the library needs neither.

## Building and testing

```bash
mvn -B -ntp verify                                                  # the resolver and its unit tests
AGENTSPACES_NETWORK_TESTS=1 mvn -B -ntp verify                      # plus real lookups over the network
mvn -B -ntp -Pcentral-publish -DskipTests -Dgpg.skip=true package   # the release dry run, as CI runs it
```

Java 21 and Maven. The unit tests run against a stub dnsjava resolver and need
no network. The network test is skipped unless `AGENTSPACES_NETWORK_TESTS=1` is
set; run it before a pull request that touches DoH or DNSSEC.

## Pull requests

Open an issue first for anything beyond a fix. Keep the change small, add the
test that fails without it, and sign off your commits (DCO). CI runs the build
and a dependency scan on every push and pull request.
