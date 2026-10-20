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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** Real lookups; skipped unless {@code AGENTSPACES_NETWORK_TESTS=1}. */
class DnsJavaResolverNetworkTest {

    @BeforeEach
    void onlyOnline() {
        Assumptions.assumeTrue("1".equals(System.getenv("AGENTSPACES_NETWORK_TESTS")),
                "set AGENTSPACES_NETWORK_TESTS=1 to run lookups against the network");
    }

    @Test
    void platformServersAnswerAddressesAndSrv() throws Exception {
        DnsJavaResolver dns = DnsJavaResolver.builder().timeout(Duration.ofSeconds(5)).build();
        assertThat(dns.addresses("google.com")).isNotEmpty();
        assertThat(dns.srv("_xmpp-client._tcp.jabber.org"))
                .isNotEmpty()
                .allSatisfy(srv -> {
                    assertThat(srv.port()).isPositive();
                    assertThat(srv.target()).isNotEmpty().doesNotEndWith(".");
                });
        assertThat(dns.addresses("does-not-exist.invalid")).isEmpty();
        assertThat(dns.authenticated()).isFalse();
    }

    @Test
    void dnsOverHttpsWithValidationAnswersASignedZone() throws Exception {
        DnsJavaResolver dns = DnsJavaResolver.builder().doh("https://dns.google/dns-query").dnssec(true)
                .timeout(Duration.ofSeconds(10)).build();
        assertThat(dns.authenticated()).isTrue();
        assertThat(dns.addresses("www.iana.org")).isNotEmpty();
        assertThat(dns.txt("iana.org")).isNotEmpty();
        assertThat(dns.srv("_aspace._tcp.iana.org")).as("a validated denial").isEmpty();
    }
}
