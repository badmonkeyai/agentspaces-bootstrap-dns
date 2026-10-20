/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.badmonkey.agentspaces.bootstrap.dns;

import ai.badmonkey.agentspaces.bootstrap.DnsResolver;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.ValidatingResolver;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The {@link DnsResolver} over dnsjava: A and AAAA, SRV, PTR, and TXT over the
 * platform's servers or a configured list (UDP with TCP fallback), over DNS
 * over HTTPS ({@link DohResolver}), and with DNSSEC validation
 * ({@link ValidatingResolver} against the IANA root trust anchors, bundled).
 * No search list is applied: names are taken as absolute, which is what the
 * locators pass.
 *
 * <p>Negative answers (NXDOMAIN, or NOERROR with no record of the asked type)
 * are empty lists. A resolver failure (timeout, SERVFAIL, REFUSED, an
 * unreachable server, a validation failure) is an {@link IOException} whose
 * message names the type, the name, and the cause.
 *
 * <p><b>DNSSEC and {@link #authenticated()}.</b> The SPI's flag is per
 * resolver, not per answer, so it can only be honest if every answer this
 * resolver returns is validated. With {@code dnssec(true)} the resolver
 * therefore <em>requires</em> validation: an answer that the validating
 * resolver marks bogus comes back SERVFAIL and is an {@link IOException}
 * carrying the validator's reason; an answer the validator leaves
 * <em>insecure</em> (no chain of trust from the root, which is what an unsigned
 * zone looks like) does not carry the AD flag and is rejected with an
 * {@link IOException} too, rather than returned as if it were authenticated.
 * Validated positive and validated negative answers (AD set) are returned.
 * The consequence is that a validating resolver cannot look up names in
 * unsigned zones; an operator with unsigned zones runs it with
 * {@code dnssec(false)}, where {@link #authenticated()} is {@code false} and
 * every answer is returned as the server gave it.
 */
public final class DnsJavaResolver implements DnsResolver {

    /** The bundled IANA root trust anchors, next to this class. */
    static final String ROOT_ANCHORS = "root-anchors.txt";

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(3);

    private final Resolver resolver;
    private final boolean dnssec;

    /**
     * A resolver over a dnsjava resolver the caller built.
     *
     * @param resolver the dnsjava resolver
     * @param dnssec   whether {@code resolver} validates, so that every answer must carry AD
     */
    DnsJavaResolver(Resolver resolver, boolean dnssec) {
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.dnssec = dnssec;
    }

    /** A builder with the platform's servers, no DoH, no DNSSEC, a 3 s timeout. */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public List<InetAddress> addresses(String name) throws IOException {
        List<InetAddress> out = new ArrayList<>();
        for (Record record : answers(name, Type.A)) {
            out.add(((ARecord) record).getAddress());
        }
        for (Record record : answers(name, Type.AAAA)) {
            out.add(((AAAARecord) record).getAddress());
        }
        return out;
    }

    @Override
    public List<SrvRecord> srv(String name) throws IOException {
        List<SrvRecord> out = new ArrayList<>();
        for (Record record : answers(name, Type.SRV)) {
            SRVRecord srv = (SRVRecord) record;
            out.add(new SrvRecord(srv.getPriority(), srv.getWeight(), srv.getPort(), srv.getTarget().toString(true)));
        }
        return out;
    }

    @Override
    public List<String> ptr(String name) throws IOException {
        List<String> out = new ArrayList<>();
        for (Record record : answers(name, Type.PTR)) {
            out.add(((PTRRecord) record).getTarget().toString(true));
        }
        return out;
    }

    @Override
    public List<List<String>> txt(String name) throws IOException {
        List<List<String>> out = new ArrayList<>();
        for (Record record : answers(name, Type.TXT)) {
            @SuppressWarnings("unchecked")
            List<String> strings = ((TXTRecord) record).getStrings();
            out.add(List.copyOf(strings));
        }
        return out;
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code true} when the resolver was built with {@code dnssec(true)}; in
     * that mode every answer this resolver returns has validated (see the
     * class comment), so the per-resolver flag holds per answer.
     */
    @Override
    public boolean authenticated() {
        return dnssec;
    }

    @Override
    public String toString() {
        return "DnsJavaResolver[" + resolver + (dnssec ? ", dnssec" : "") + "]";
    }

    /**
     * The answer-section records of one type at a name.
     *
     * @param name the owner name, with or without the trailing dot
     * @param type the record type
     * @return the records of that type, in answer order; empty for NXDOMAIN or no data
     * @throws IOException when the resolver could not be asked, or refused, or the answer did not validate
     */
    private List<Record> answers(String name, int type) throws IOException {
        String label = "DNS " + Type.string(type) + " " + name;
        Name owner;
        try {
            owner = Name.fromString(absolute(name));
        } catch (TextParseException e) {
            throw new IOException(label + ": not a valid name (" + e.getMessage() + ")", e);
        }
        Message response;
        try {
            response = resolver.send(Message.newQuery(Record.newRecord(owner, type, DClass.IN)));
        } catch (IOException e) {
            throw new IOException(label + ": " + describe(e), e);
        }
        int rcode = response.getRcode();
        if (rcode == Rcode.SERVFAIL) {
            throw new IOException(label + ": SERVFAIL" + validationReason(response));
        }
        if (dnssec && !response.getHeader().getFlag(Flags.AD)) {
            throw new IOException(label + ": the answer did not validate under DNSSEC (no chain of trust from the"
                    + " root; an unsigned zone); this resolver requires validated answers");
        }
        if (rcode == Rcode.NXDOMAIN) {
            return List.of();
        }
        if (rcode != Rcode.NOERROR) {
            throw new IOException(label + ": " + Rcode.string(rcode));
        }
        List<Record> out = new ArrayList<>();
        for (Record record : response.getSection(Section.ANSWER)) {
            if (record.getType() == type) {
                out.add(record);
            }
        }
        return out;
    }

    /** The validator's reason, which {@link ValidatingResolver} adds as a TXT record of its own class. */
    private static String validationReason(Message response) {
        for (Record record : response.getSection(Section.ADDITIONAL)) {
            if (record instanceof TXTRecord txt && record.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
                @SuppressWarnings("unchecked")
                List<String> strings = txt.getStrings();
                return " (DNSSEC: " + String.join(" ", strings) + ")";
            }
        }
        return "";
    }

    private static String describe(IOException e) {
        if (e instanceof SocketTimeoutException) {
            return "timed out";
        }
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    private static String absolute(String name) {
        String trimmed = name.trim();
        return trimmed.endsWith(".") ? trimmed : trimmed + ".";
    }

    /** Builds a {@link DnsJavaResolver}. */
    public static final class Builder {

        private List<String> servers = List.of();
        private String doh;
        private boolean dnssec;
        private String trustAnchors;
        private Duration timeout = DEFAULT_TIMEOUT;

        private Builder() {
        }

        /**
         * The servers to ask over UDP and TCP, each {@code host}, {@code host:port},
         * or {@code [v6]:port}; empty (the default) means the platform's servers as
         * dnsjava's {@code ResolverConfig} finds them. Ignored when {@link #doh} is set.
         *
         * @param servers the servers
         * @return this
         */
        public Builder servers(List<String> servers) {
            this.servers = List.copyOf(Objects.requireNonNull(servers, "servers"));
            return this;
        }

        /**
         * Resolve over DNS over HTTPS (RFC 8484) at a resolver URL such as
         * {@code https://dns.corp.example/dns-query}, instead of the servers.
         *
         * @param url the DoH endpoint, or null for none
         * @return this
         */
        public Builder doh(String url) {
            this.doh = url;
            return this;
        }

        /**
         * Validate every answer under DNSSEC from the root trust anchors and
         * require that it validates; see the class comment for what that means
         * for unsigned zones and for {@link DnsJavaResolver#authenticated()}.
         *
         * @param validate whether to validate
         * @return this
         */
        public Builder dnssec(boolean validate) {
            this.dnssec = validate;
            return this;
        }

        /**
         * Trust anchors in master-file format (DS or DNSKEY records) in place of
         * the bundled IANA root anchors, for a private root or a newer key.
         *
         * @param masterFormat the records, or null for the bundled anchors
         * @return this
         */
        public Builder trustAnchors(String masterFormat) {
            this.trustAnchors = masterFormat;
            return this;
        }

        /**
         * The query timeout, 3 s by default.
         *
         * @param timeout the timeout
         * @return this
         */
        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        /**
         * Builds the resolver.
         *
         * @return the resolver
         * @throws IllegalArgumentException for a server the builder cannot parse or the
         *                                  trust anchors it cannot read
         */
        public DnsJavaResolver build() {
            Resolver base = base();
            base.setTimeout(timeout);
            if (!dnssec) {
                return new DnsJavaResolver(base, false);
            }
            ValidatingResolver validating = new ValidatingResolver(base);
            try (InputStream anchors = anchors()) {
                validating.loadTrustAnchors(anchors);
            } catch (IOException e) {
                throw new IllegalArgumentException("DNSSEC trust anchors: " + e.getMessage(), e);
            }
            return new DnsJavaResolver(validating, true);
        }

        private Resolver base() {
            if (doh != null) {
                return new DohResolver(doh);
            }
            if (servers.isEmpty()) {
                return new ExtendedResolver();
            }
            List<Resolver> list = new ArrayList<>();
            for (String server : servers) {
                list.add(new SimpleResolver(address(server)));
            }
            return new ExtendedResolver(list);
        }

        private InputStream anchors() throws IOException {
            if (trustAnchors != null) {
                return new ByteArrayInputStream(trustAnchors.getBytes(StandardCharsets.US_ASCII));
            }
            InputStream bundled = DnsJavaResolver.class.getResourceAsStream(ROOT_ANCHORS);
            if (bundled == null) {
                throw new IOException("bundled " + ROOT_ANCHORS + " is missing");
            }
            return bundled;
        }

        /** Parses {@code host}, {@code host:port}, or {@code [v6]:port}; an IPv6 literal without brackets is a host. */
        static InetSocketAddress address(String server) {
            String s = server.trim();
            String host = s;
            int port = SimpleResolver.DEFAULT_PORT;
            if (s.startsWith("[")) {
                int close = s.indexOf(']');
                if (close < 0) {
                    throw new IllegalArgumentException("DNS server '" + server + "': unterminated [");
                }
                host = s.substring(1, close);
                String rest = s.substring(close + 1);
                if (!rest.isEmpty()) {
                    port = port(server, rest.substring(1), rest.startsWith(":"));
                }
            } else if (s.indexOf(':') >= 0 && s.indexOf(':') == s.lastIndexOf(':')) {
                host = s.substring(0, s.indexOf(':'));
                port = port(server, s.substring(s.indexOf(':') + 1), true);
            }
            if (host.isEmpty()) {
                throw new IllegalArgumentException("DNS server '" + server + "': no host");
            }
            InetSocketAddress address = new InetSocketAddress(host, port);
            if (address.isUnresolved()) {
                throw new IllegalArgumentException("DNS server '" + server + "': unknown host " + host);
            }
            return address;
        }

        private static int port(String server, String text, boolean wellFormed) {
            try {
                int port = wellFormed ? Integer.parseInt(text) : -1;
                if (port < 1 || port > 65_535) {
                    throw new NumberFormatException();
                }
                return port;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("DNS server '" + server + "': bad port");
            }
        }
    }
}
