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
import org.junit.jupiter.api.Test;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.ValidatingResolver;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The mapping from dnsjava messages to the SPI, over a stub dnsjava resolver; no network. */
class DnsJavaResolverTest {

    /**
     * A dnsjava resolver that answers from a function. It overrides
     * {@code sendAsync(Message, Executor)}, which is where the interface's
     * default {@code send} chain ends and what ValidatingResolver calls.
     */
    static final class StubResolver implements Resolver {

        final List<Message> queries = new ArrayList<>();
        private final Function<Message, Message> answers;

        StubResolver(Function<Message, Message> answers) {
            this.answers = answers;
        }

        @Override
        public CompletionStage<Message> sendAsync(Message query, Executor executor) {
            queries.add(query);
            try {
                return CompletableFuture.completedFuture(answers.apply(query));
            } catch (RuntimeException e) {
                if (e.getCause() instanceof IOException io) {
                    return CompletableFuture.failedFuture(io);
                }
                throw e;
            }
        }

        @Override
        public void setPort(int port) {
        }

        @Override
        public void setTCP(boolean flag) {
        }

        @Override
        public void setIgnoreTruncation(boolean flag) {
        }

        @Override
        public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
        }

        @Override
        public void setTSIGKey(TSIG key) {
        }

        @Override
        public void setTimeout(Duration timeout) {
        }
    }

    private static Name name(String s) {
        return Name.fromConstantString(s);
    }

    /** A NOERROR reply to {@code query} with {@code records} in the answer section. */
    private static Message reply(Message query, Record... records) {
        return reply(query, Rcode.NOERROR, records);
    }

    private static Message reply(Message query, int rcode, Record... records) {
        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(rcode);
        response.addRecord(query.getQuestion(), Section.QUESTION);
        for (Record record : records) {
            response.addRecord(record, Section.ANSWER);
        }
        return response;
    }

    private static Message failing(IOException cause) {
        throw new IllegalStateException(cause);
    }

    private static int type(Message query) {
        return query.getQuestion().getType();
    }

    private static DnsJavaResolver over(Function<Message, Message> answers) {
        return new DnsJavaResolver(new StubResolver(answers), false);
    }

    @Test
    void addressesReturnBothFamiliesInAnswerOrderAndSkipTheCname() throws Exception {
        Name owner = name("seed.corp.example.");
        Name alias = name("seeds.corp.example.");
        DnsJavaResolver dns = over(q -> switch (type(q)) {
            case Type.A -> reply(q,
                    new CNAMERecord(alias, DClass.IN, 60, owner),
                    new ARecord(owner, DClass.IN, 60, ip("10.0.0.2")),
                    new ARecord(owner, DClass.IN, 60, ip("10.0.0.1")));
            case Type.AAAA -> reply(q,
                    new CNAMERecord(alias, DClass.IN, 60, owner),
                    new AAAARecord(owner, DClass.IN, 60, ip("fd00::2")));
            default -> throw new AssertionError("unexpected " + Type.string(type(q)));
        });
        assertThat(dns.addresses("seeds.corp.example")).extracting(InetAddress::getHostAddress)
                .containsExactly("10.0.0.2", "10.0.0.1", "fd00:0:0:0:0:0:0:2");
    }

    @Test
    void srvMapsEveryFieldAndDropsTheTrailingDot() throws Exception {
        Name owner = name("_aspace._tcp.seeds.example.");
        DnsJavaResolver dns = over(q -> reply(q,
                new SRVRecord(owner, DClass.IN, 300, 10, 60, 7500, name("seed-a.corp.example.")),
                new SRVRecord(owner, DClass.IN, 300, 20, 0, 7501, name("seed-b.corp.example."))));
        assertThat(dns.srv("_aspace._tcp.seeds.example")).containsExactly(
                new DnsResolver.SrvRecord(10, 60, 7500, "seed-a.corp.example"),
                new DnsResolver.SrvRecord(20, 0, 7501, "seed-b.corp.example"));
    }

    @Test
    void ptrReturnsTargetsWithoutTheTrailingDot() throws Exception {
        Name owner = name("_agentspaces._tcp.corp.example.");
        DnsJavaResolver dns = over(q -> reply(q,
                new PTRRecord(owner, DClass.IN, 300, name("research-fleet._agentspaces._tcp.corp.example.")),
                new PTRRecord(owner, DClass.IN, 300, name("ops._agentspaces._tcp.corp.example."))));
        assertThat(dns.ptr("_agentspaces._tcp.corp.example")).containsExactly(
                "research-fleet._agentspaces._tcp.corp.example", "ops._agentspaces._tcp.corp.example");
    }

    @Test
    void txtKeepsEachRecordsCharacterStrings() throws Exception {
        Name owner = name("_agentspaces.corp.example.");
        DnsJavaResolver dns = over(q -> reply(q,
                new TXTRecord(owner, DClass.IN, 300, List.of("v=1", "url=https://beacon.corp.example/.well-known/agentspaces/beacon.json")),
                new TXTRecord(owner, DClass.IN, 300, "group=research-fleet")));
        assertThat(dns.txt("_agentspaces.corp.example")).containsExactly(
                List.of("v=1", "url=https://beacon.corp.example/.well-known/agentspaces/beacon.json"),
                List.of("group=research-fleet"));
    }

    @Test
    void nxdomainAndNoDataAreEmpty() throws Exception {
        DnsJavaResolver nxdomain = over(q -> reply(q, Rcode.NXDOMAIN));
        assertThat(nxdomain.addresses("nowhere.example")).isEmpty();
        assertThat(nxdomain.srv("_aspace._tcp.nowhere.example")).isEmpty();
        assertThat(nxdomain.ptr("_agentspaces._tcp.nowhere.example")).isEmpty();
        assertThat(nxdomain.txt("nowhere.example")).isEmpty();
        DnsJavaResolver nodata = over(q -> reply(q));
        assertThat(nodata.addresses("seed.corp.example")).isEmpty();
        assertThat(nodata.srv("seed.corp.example")).isEmpty();
        assertThat(nodata.ptr("seed.corp.example")).isEmpty();
        assertThat(nodata.txt("seed.corp.example")).isEmpty();
    }

    @Test
    void servfailAndRefusedAreIOExceptionsNamingTheQuery() {
        DnsJavaResolver servfail = over(q -> reply(q, Rcode.SERVFAIL));
        assertThatThrownBy(() -> servfail.srv("_aspace._tcp.seeds.example"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("SRV _aspace._tcp.seeds.example")
                .hasMessageContaining("SERVFAIL");
        DnsJavaResolver refused = over(q -> reply(q, Rcode.REFUSED));
        assertThatThrownBy(() -> refused.addresses("seed.corp.example"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("A seed.corp.example")
                .hasMessageContaining("REFUSED");
    }

    @Test
    void servfailCarriesTheValidatorsReason() {
        DnsJavaResolver dns = over(q -> {
            Message response = reply(q, Rcode.SERVFAIL);
            response.addRecord(new TXTRecord(Name.root, ValidatingResolver.VALIDATION_REASON_QCLASS, 0,
                    "failed.ds.nonsec"), Section.ADDITIONAL);
            return response;
        });
        assertThatThrownBy(() -> dns.txt("_agentspaces.corp.example"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("DNSSEC: failed.ds.nonsec");
    }

    @Test
    void aTimeoutIsAnIOExceptionSayingSo() {
        DnsJavaResolver dns = over(q -> failing(new SocketTimeoutException("Timed out")));
        assertThatThrownBy(() -> dns.addresses("seed.corp.example"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("A seed.corp.example")
                .hasMessageContaining("timed out")
                .hasCauseInstanceOf(SocketTimeoutException.class);
    }

    @Test
    void namesAreSentAbsoluteAndBadNamesAreIOExceptions() throws Exception {
        StubResolver stub = new StubResolver(q -> reply(q));
        DnsJavaResolver dns = new DnsJavaResolver(stub, false);
        dns.addresses(" seed.corp.example ");
        dns.srv("_aspace._tcp.seeds.example.");
        assertThat(stub.queries).extracting(q -> q.getQuestion().getName().toString())
                .containsExactly("seed.corp.example.", "seed.corp.example.", "_aspace._tcp.seeds.example.");
        assertThat(stub.queries).extracting(q -> q.getQuestion().getType())
                .containsExactly(Type.A, Type.AAAA, Type.SRV);
        assertThatThrownBy(() -> dns.addresses("a..b"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("not a valid name");
    }

    @Test
    void dnssecRequiresTheAdFlagOnEveryAnswer() throws Exception {
        Name owner = name("seed.corp.example.");
        Function<Message, Message> signed = q -> {
            Message response = type(q) == Type.A
                    ? reply(q, new ARecord(owner, DClass.IN, 60, ip("10.0.0.1")))
                    : reply(q, Rcode.NXDOMAIN);
            response.getHeader().setFlag(Flags.AD);
            return response;
        };
        Function<Message, Message> insecure = q -> reply(q, new ARecord(owner, DClass.IN, 60, ip("10.0.0.1")));

        DnsJavaResolver validating = new DnsJavaResolver(new StubResolver(signed), true);
        assertThat(validating.authenticated()).isTrue();
        assertThat(validating.addresses("seed.corp.example")).extracting(InetAddress::getHostAddress)
                .containsExactly("10.0.0.1");
        assertThat(validating.srv("seed.corp.example")).as("a validated denial is empty").isEmpty();

        DnsJavaResolver unsignedZone = new DnsJavaResolver(new StubResolver(insecure), true);
        assertThatThrownBy(() -> unsignedZone.addresses("seed.corp.example"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("did not validate under DNSSEC");

        DnsJavaResolver plain = new DnsJavaResolver(new StubResolver(insecure), false);
        assertThat(plain.authenticated()).isFalse();
        assertThat(plain.addresses("seed.corp.example")).hasSize(1);
    }

    @Test
    void builderWiresServersDohAndTheBundledRootAnchors() {
        DnsJavaResolver plain = DnsJavaResolver.builder().servers(List.of("127.0.0.1:5353", "[::1]:5353"))
                .timeout(Duration.ofMillis(200)).build();
        assertThat(plain.authenticated()).isFalse();
        assertThat(plain.toString()).contains("127.0.0.1").doesNotContain("dnssec");

        DnsJavaResolver doh = DnsJavaResolver.builder().doh("https://dns.corp.example/dns-query").build();
        assertThat(doh.toString()).contains("https://dns.corp.example/dns-query");

        DnsJavaResolver validating = DnsJavaResolver.builder().servers(List.of("127.0.0.1")).dnssec(true).build();
        assertThat(validating.authenticated()).isTrue();
        assertThat(validating.toString()).contains("dnssec");

        DnsJavaResolver privateRoot = DnsJavaResolver.builder().servers(List.of("127.0.0.1")).dnssec(true)
                .trustAnchors(". 3600 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")
                .build();
        assertThat(privateRoot.authenticated()).isTrue();

        assertThatThrownBy(() -> DnsJavaResolver.builder().servers(List.of("127.0.0.1:dns")).build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("bad port");
        assertThatThrownBy(() -> DnsJavaResolver.builder().servers(List.of("[::1")).build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("unterminated");
        assertThatThrownBy(() -> DnsJavaResolver.builder().servers(List.of("127.0.0.1")).dnssec(true)
                .trustAnchors("this is not a record\n").build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("trust anchors");
    }

    @Test
    void serverAddressesParseHostPortAndBracketedV6() {
        assertThat(DnsJavaResolver.Builder.address("127.0.0.1")).isEqualTo(new InetSocketAddress("127.0.0.1", 53));
        assertThat(DnsJavaResolver.Builder.address("127.0.0.1:5353")).isEqualTo(new InetSocketAddress("127.0.0.1", 5353));
        assertThat(DnsJavaResolver.Builder.address("::1")).isEqualTo(new InetSocketAddress("::1", 53));
        assertThat(DnsJavaResolver.Builder.address("[::1]")).isEqualTo(new InetSocketAddress("::1", 53));
        assertThat(DnsJavaResolver.Builder.address("[::1]:5353")).isEqualTo(new InetSocketAddress("::1", 5353));
    }

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (IOException e) {
            throw new IllegalArgumentException(literal, e);
        }
    }
}
