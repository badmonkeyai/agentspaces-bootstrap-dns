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
  <version>0.6.0</version>
</dependency>
```

It brings `ai.badmonkey.agentspaces:agentspaces-bootstrap:0.6.0` and
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

## Bootstrap patterns

A peer that joins a group asks its bootstrap chain where to dial, and some of the chain's locators
read DNS: `dns-sd`, `dns-txt`, `dns-srv`, and `k8s`. This resolver decides how much those answers
are worth. The patterns below go from the lightest to the strictest. Each one adds a check and
keeps the checks before it.

| Pattern | Resolver | What DNS may tell the peer |
|---|---|---|
| Plain discovery | `builder().build()`, or `servers(...)` | where to dial: seeds, SRV targets, a beacon document's URL |
| Private lookups | `doh(url)` | the same, over an encrypted channel to a resolver you choose |
| Authenticated discovery | `dnssec(true)` | the same, and every answer is proven to come from the zone owner unchanged |
| DNS as the root of the group identity | `dnssec(true)`, with `accept-group-id-from` naming a DNS locator | which group a peer in your domain joins: the zone's `id=` record |

### Plain discovery

The platform's servers, or a server list you name, answer the locators' questions. This is what
the JDK resolver already does, with dnsjava's parser, TCP fallback, and a timeout you set. A
poisoned answer can send a peer to the wrong host. Every connection still goes through the same
handshake, signature checks, and admission policy as a stranger's, and a peer that joins by id
rejects a host whose founding does not hash to that id, so for a group with a signed founding the
cost of a poisoned answer is a wasted dial. A group started from a founding text has no founding to
check, and anyone who knows the text derives the same id, so give such a group authenticated DNS
or keep it on a network whose DNS you run.

### Private lookups with DNS over HTTPS

`doh("https://dns.corp.example/dns-query")` sends every query inside HTTPS to the resolver you
name. A laptop on hotel or conference Wi-Fi then hides from the local network which groups it
looks for, and it no longer depends on a local resolver that may block or rewrite the answers. DNS over HTTPS protects the
path to your resolver. It does not prove the records themselves, so combine it with DNSSEC when
the answers carry identity.

### Authenticated discovery with DNSSEC

`dnssec(true)` validates every answer from the IANA root anchors down to your zone and refuses any
answer that does not validate. A forged SRV record, a substituted `url=` pointer, or a spoofed
seed address fails as an `IOException` before a locator sees it, so a peer only dials hosts your
zone actually lists. The zone has to be signed and its DS record published at the parent. A
validating resolver cannot read an unsigned zone (see [DNSSEC and `authenticated()`](#dnssec-and-authenticated)).

The records a beacon operator registers are the ones `agentspaces-beacon` prints:

```
_agentspaces._tcp.corp.example.                 IN PTR  research-fleet._agentspaces._tcp.corp.example.
research-fleet._agentspaces._tcp.corp.example.  IN SRV  10 50 7500 beacon.corp.example.
research-fleet._agentspaces._tcp.corp.example.  IN TXT  "v=1" "group=research-fleet" "id=aspace://z7f3a..." "scheme=tls" "url=https://agentspaces.corp.example/.well-known/agentspaces/beacon.json"
agentspaces.corp.example.                       IN TXT  "v=1" "url=https://agentspaces.corp.example/.well-known/agentspaces/beacon.json"
```

### DNS as the root of the group identity

A locator can claim a group id: `dns-sd` reads it from the instance's `id=` TXT string. The chain
honours a claim only when the peer asked without an id of its own, and only from the locators named
in `accept-group-id-from`, which default to `url` and `document`. A host refuses to start when that
list names a DNS locator and the resolver does not authenticate, unless `insecure-group-id: true`
says otherwise. With this resolver in DNSSEC mode the refusal lifts, because `authenticated()` is
`true`:

```yaml
agentspaces:
  bootstrap:
    domain: auto                            # the host's search domain, such as corp.example
    order: [ seeds, dns-sd, url ]
    accept-group-id-from: [ dns-sd, url ]   # allowed only with an authenticated resolver
```

Your signed zone then decides which group your domain's peers join. Publish the id of a group with
a **signed founding**. Its id is the hash of the founding, so a peer that takes the id from DNS
also checks the founding a member or the beacon document shows it, and joins only a group whose
founding hashes to that id. A group started from a founding text has no signed founding, so it
cannot be joined by an id alone.

### Keeping certificate-based security end to end

DNSSEC proves where to go and which group to expect. The fleet's own cryptography proves who
answers. Each link of the chain checks the one before it:

| Step | What proves it | What it stops |
|---|---|---|
| The DNS records are your zone's | DNSSEC, from the IANA root anchors to your zone's keys (this library) | spoofed or poisoned answers, a substituted seed list, a forged group id |
| The lookup is private | DNS over HTTPS to your resolver (this library) | a local network reading or rewriting queries |
| The group is the one the id names | the id is the hash of the signed founding | a host that pretends to be the group |
| The beacon document is your beacon's | the document's signature, pinned with `beacon-peer` | a substituted document at the published URL |
| Each connection is to the peer it claims to be | the TLS channel certificate the peer's identity key endorses (SPEC §5.6) | impersonation of a member on the wire |
| The peer holds a credential your organization issued and has not revoked | the enterprise-CA mode: `transport.tls.trust-store`, `key-store`, and `crls` | an identity your organization never enrolled, and a machine it revoked |

The default `mtls` security profile already runs the TLS transport with identity-endorsed channel
certificates. An organization that runs its own certificate authority adds the CA mode and requires
attestation, so that every frame arrives on a connection whose certificate chain validates to that
CA:

```yaml
agentspaces:
  security:
    profile: mtls
  transport:
    tls:
      key-store: /etc/agentspaces/peer.p12            # this peer's CA-issued credential
      key-store-password: ${PEER_KEY_PASSWORD}
      trust-store: /etc/agentspaces/ca.p12            # selects the enterprise-CA mode
      trust-store-password: ${CA_STORE_PASSWORD}
      crls: [ /etc/agentspaces/fleet.crl ]            # re-read every crl-refresh (5 minutes)
      require-attestation: true                       # plaintext transports are refused
  bootstrap:
    domain: auto
    order: [ seeds, dns-sd, url ]
    accept-group-id-from: [ dns-sd, url ]
    beacon-peer: z6Mk...beacon                        # the PeerId that must sign the beacon document
```

```java
@Bean
DnsResolver dns() {
    return DnsJavaResolver.builder()
            .doh("https://dns.corp.example/dns-query")
            .dnssec(true)
            .build();
}
```

With that configuration a new machine in `corp.example` needs its enrolled credential and nothing
else. DNSSEC tells it which group to join and where the seeds are. The founding confirms the group,
and the CA confirms every member it talks to. A revoked machine loses its connections at the next
handshake after the CRL that names it arrives.

## Building

```
mvn -q clean install
```

The unit tests run against a stub dnsjava resolver and need no network. The
network test (`DnsJavaResolverNetworkTest`: `google.com` A,
`_xmpp-client._tcp.jabber.org` SRV, and a DoH plus DNSSEC lookup of
`www.iana.org`) is skipped unless `AGENTSPACES_NETWORK_TESTS=1` is set.

## Releasing

The `central-publish` profile attaches the sources and javadoc jars, signs
every artifact with GPG (the passphrase from `MAVEN_GPG_PASSPHRASE`, or a GPG
agent), and uploads through the Sonatype Central Portal using the `central`
server id in `settings.xml`. The dry run builds the jars without signing or
uploading anything:

```sh
mvn -Pcentral-publish -DskipTests -Dgpg.skip=true clean package
```

The release signs the artifacts and uploads them:

```sh
mvn -Pcentral-publish clean deploy
```

`autoPublish` is off, so the upload waits on the Portal as a validated bundle
until you publish it there. Publish `agentspaces-bootstrap` 0.6.0 first, since
this library implements its `DnsResolver` SPI.

CI runs the same profile unsigned on every push, so a javadoc or packaging
problem fails a pull request before it can fail a release.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Report a vulnerability privately, as
[SECURITY.md](SECURITY.md) describes.

## Licence

Apache License 2.0, Copyright 2026 Bad Monkey, Inc. The dnsjava dependency is
BSD-2-Clause (see `NOTICE`); it is declared, not bundled.
