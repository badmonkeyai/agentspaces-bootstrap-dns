# AgentSpaces Bootstrap :: dnsjava

The [dnsjava](https://github.com/dnsjava/dnsjava) implementation of the
`DnsResolver` SPI from `agentspaces-bootstrap`. It answers the same four
questions the locators ask (addresses, SRV, PTR, TXT) and adds what the JDK's
JNDI resolver cannot do:

- **DNS over HTTPS** (RFC 8484) to a resolver URL, through dnsjava's `DohResolver`.
- **DNSSEC validation** against the IANA root trust anchors (KSK-2017 and
  KSK-2024, bundled), through dnsjava's `ValidatingResolver`. A validating
  resolver answers `authenticated() == true`, which is what lets the `dns`
  locators supply a GroupId (SRAD DB-L-14).
- A configured server list (UDP with TCP fallback) or the platform's servers
  as dnsjava's `ResolverConfig` finds them.

It is a project of its own, beside `agentspaces-bootstrap`, so that dnsjava's
BSD-2-Clause licence stands alone and the bootstrap project stays JDK-only.

## Coordinates

```xml
<dependency>
  <groupId>ai.badmonkey.agentspaces</groupId>
  <artifactId>agentspaces-bootstrap-dns</artifactId>
  <version>0.4.0</version>
</dependency>
```

It brings `ai.badmonkey.agentspaces:agentspaces-bootstrap:0.4.0` and
`dnsjava:dnsjava:3.6.3` (which depends on `slf4j-api`). Java 21.

## Selecting it

The `agentspaces.bootstrap.*` keys are bound by `agentspaces-bootstrap`'s own
Spring Boot autoconfigure and Micronaut factory; those host modules look for a
`DnsResolver` bean and fall back to the JDK's `JndiDnsResolver` when there is
none. This project supplies only the resolver, so selecting it is defining the
bean:

```java
@Bean
DnsResolver dns() {
    return DnsJavaResolver.builder()
            .doh("https://dns.corp.example/dns-query")
            .dnssec(true)
            .build();
}
```

With that bean in place, the locators configured under `agentspaces.bootstrap`
go through it:

```yaml
agentspaces:
  bootstrap:
    domain: auto                       # or [corp.example]
    locators: [dns-sd, srv, txt, url]
    srv: _aspace._tcp.seeds.corp.example
    timeout: 3s
```

The builder:

| Method | Meaning | Default |
|---|---|---|
| `servers(List<String>)` | servers to ask, each `host`, `host:port`, or `[v6]:port` | the platform's (`ResolverConfig`) |
| `doh(String url)` | resolve over DNS over HTTPS at this URL instead of the servers | none |
| `dnssec(boolean)` | validate every answer from the root trust anchors, and require that it validates | `false` |
| `trustAnchors(String)` | DS or DNSKEY records in master-file format in place of the bundled root anchors | bundled IANA anchors |
| `timeout(Duration)` | the query timeout | 3 s |

A plain resolver (no DoH, no DNSSEC) over the platform's servers is
`DnsJavaResolver.builder().build()`.

## What the answers mean

- NXDOMAIN, or NOERROR with no record of the asked type, is an empty list.
- A timeout, SERVFAIL, REFUSED, an unreachable server, or a name dnsjava will
  not parse is an `IOException` whose message names the record type, the name,
  and the cause. A SERVFAIL produced by the validator carries its reason
  (`failed.ds.nonsec`, ...).
- `addresses` returns the A records then the AAAA records, each in the answer's
  order; SRV targets and PTR names have no trailing dot; each TXT record is its
  list of character-strings.

### DNSSEC and `authenticated()`

The SPI's `authenticated()` is a flag on the resolver, not on each answer, so
it can only be honest if every answer the resolver returns has validated. With
`dnssec(true)` the resolver therefore requires validation: a **bogus** answer
(the validator rewrites it to SERVFAIL) is an `IOException` with the
validator's reason, and an **insecure** answer (no chain of trust from the
root, which is what an unsigned zone looks like; the AD flag is absent) is an
`IOException` too, instead of being returned as if authenticated. Validated
positive answers and validated denials (NXDOMAIN or no data with AD set) are
returned as usual.

The consequence: a validating resolver cannot look up names in unsigned zones.
An operator whose zones are unsigned runs it with `dnssec(false)` (the
default), where `authenticated()` is `false` and every answer is returned as
the server gave it; the locators then treat a DNS-supplied GroupId the way the
SRAD prescribes for unauthenticated DNS.

The bundled anchors are the root's DS records as published at
`https://data.iana.org/root-anchors/root-anchors.xml`; `trustAnchors(String)`
replaces them for a private root or after a key roll.

## Building

```
mvn -q clean install
```

The unit tests run against a stub dnsjava resolver and need no network. The
network test (`DnsJavaResolverNetworkTest`: `google.com` A,
`_xmpp-client._tcp.jabber.org` SRV, and a DoH plus DNSSEC lookup of
`www.iana.org`) is skipped unless `AGENTSPACES_NETWORK_TESTS=1` is set.

## Licence

Apache License 2.0, Copyright 2026 Bad Monkey, Inc. The dnsjava dependency is
BSD-2-Clause (see `NOTICE`); it is declared, not bundled.
