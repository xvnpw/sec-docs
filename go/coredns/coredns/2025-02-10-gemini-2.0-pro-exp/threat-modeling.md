# Threat Model Analysis for coredns/coredns

## Threat: [Cache Poisoning via Malformed Responses](./threats/cache_poisoning_via_malformed_responses.md)

*   **Description:** An attacker sends crafted DNS responses to CoreDNS, attempting to inject malicious records into the cache. This often involves exploiting vulnerabilities in upstream resolvers (if forwarding is used) or sending responses with manipulated TTLs and resource records. The attacker might send a large number of responses with slightly different query names, hoping one will be cached.  The attacker leverages the lack of proper validation of responses by CoreDNS.
*   **Impact:** Redirection of legitimate traffic to malicious servers controlled by the attacker. This can lead to phishing, malware distribution, man-in-the-middle attacks, and data theft.  Users are transparently directed to the wrong services.
*   **Affected Component:** `cache` plugin (specifically, its caching logic and validation of responses). Also, the `forward` plugin (if forwarding to vulnerable resolvers) and any plugin that interacts with the cache.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **DNSSEC Validation:** *Crucially*, enable DNSSEC validation in the `dnssec` plugin. This ensures that responses are cryptographically signed and that the signatures are valid, preventing the acceptance of forged records. CoreDNS *must* validate signatures.
    *   **Secure Upstream Resolvers:** Configure the `forward` plugin to use *only* trusted, reputable DNS resolvers that are known to support DNSSEC and have robust security measures in place. Avoid using public resolvers that are not well-maintained.  This is a CoreDNS configuration choice.
    *   **QNAME Minimization:** Enable the `minimalresponses` plugin. This reduces the amount of information sent to upstream resolvers (a CoreDNS feature), making cache poisoning attacks more difficult.
    *   **Cache TTL Limits:** Configure reasonable minimum and maximum TTL values in the `cache` plugin to prevent attackers from setting excessively long or short TTLs to manipulate the cache. This is a direct CoreDNS configuration.
    *   **Monitor for Anomalies:** Monitor DNS logs and metrics for unusual patterns, such as a sudden increase in NXDOMAIN responses or responses with unexpected TTLs, which could indicate cache poisoning attempts. This relies on CoreDNS's logging capabilities.

## Threat: [Denial of Service via Query Flooding](./threats/denial_of_service_via_query_flooding.md)

*   **Description:** An attacker sends a large volume of DNS queries to the CoreDNS server, overwhelming its resources (CPU, memory, network bandwidth) and preventing it from responding to legitimate requests. This can be done using various techniques, including amplification attacks (though mitigation of amplification is partially external). The attacker directly targets the CoreDNS service.
*   **Impact:** Outage of DNS resolution services, making the application and its dependent services unavailable to users.  CoreDNS becomes unresponsive.
*   **Affected Component:** CoreDNS server itself (overall resource handling), potentially exacerbated by plugins that consume significant resources (e.g., `cache`, `kubernetes`). The `ratelimit` plugin is directly relevant for mitigation.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement the `ratelimit` plugin to limit the number of queries per client IP address, source network, or query type. Configure appropriate thresholds based on expected traffic patterns. This is a *direct* CoreDNS mitigation.
    *   **Resource Limits:** Configure operating system-level resource limits (e.g., using `ulimit` on Linux) to prevent the CoreDNS process from consuming excessive CPU, memory, or file descriptors. While this is OS-level, it directly protects the CoreDNS process.
    *   **Monitor Server Health:** Implement comprehensive monitoring of CoreDNS server resources (CPU, memory, network I/O) and set up alerts for any unusual spikes or resource exhaustion. This relies on CoreDNS's ability to expose metrics.

## Threat: [Exploitation of Plugin Vulnerability (e.g., `kubernetes` plugin)](./threats/exploitation_of_plugin_vulnerability__e_g____kubernetes__plugin_.md)

*   **Description:** An attacker exploits a vulnerability in a specific CoreDNS plugin (e.g., a buffer overflow or code injection vulnerability in the `kubernetes` plugin, or any other installed plugin) to gain unauthorized access or execute arbitrary code. The attacker might send specially crafted requests that trigger the vulnerability *within the plugin's code*.
*   **Impact:** Varies depending on the vulnerability, but could range from denial of service to complete compromise of the CoreDNS server and potentially the underlying host system. Could lead to data breaches, service disruption, or lateral movement within the network. The impact is directly tied to the compromised CoreDNS plugin.
*   **Affected Component:** The specific vulnerable plugin (e.g., `kubernetes`, `file`, `etcd`, etc.). The vulnerability exists *within* the plugin code.
*   **Risk Severity:** Critical or High (depending on the specific vulnerability).
*   **Mitigation Strategies:**
    *   **Keep Plugins Updated:** Regularly update *all* installed CoreDNS plugins to the latest versions. This is the most crucial mitigation, directly addressing plugin vulnerabilities. Subscribe to security advisories for CoreDNS and its plugins.
    *   **Minimize Plugin Usage:** Only enable the plugins that are absolutely necessary for your application's functionality. Disable any unused plugins. This reduces the attack surface within CoreDNS.
    *   **Vulnerability Scanning:** Use a vulnerability scanner that specifically targets CoreDNS and its plugins to identify known vulnerabilities.
    *   **Input Validation:** If you are developing custom plugins, ensure that all input is properly validated and sanitized to prevent injection attacks. This is a best practice for plugin development.
    *   **Code Review:** If possible, conduct code reviews of any custom plugins or critical third-party plugins to identify potential security flaws.
    *   **Least Privilege:** Run the CoreDNS process with the least privileges necessary. Avoid running it as root. This limits the impact of a successful exploit.

## Threat: [Zone Transfer to Unauthorized Parties](./threats/zone_transfer_to_unauthorized_parties.md)

*   **Description:** An attacker sends an `AXFR` or `IXFR` request to the CoreDNS server, attempting to retrieve the entire contents of a DNS zone. The attacker may not be authorized to receive this information. This is done by sending a standard DNS query with the type set to `AXFR` or `IXFR`. The attacker exploits a misconfiguration or lack of authorization checks in CoreDNS.
*   **Impact:** Exposure of internal network topology, hostnames, IP addresses, and other sensitive information contained within the zone. This can facilitate further attacks, such as targeted phishing or reconnaissance for vulnerabilities.
*   **Affected Component:** `transfer` plugin (specifically, the `to` directive and overall authorization logic). Also potentially the `file` or `kubernetes` plugins (or any plugin that serves zone data) if they don't properly interact with the `transfer` plugin's restrictions.
*   **Risk Severity:** High (if sensitive zones are exposed).
*   **Mitigation Strategies:**
    *   **Strictly Limit `to`:** In the `transfer` plugin configuration, use the `to` directive to explicitly list the IP addresses or CIDR blocks of authorized secondary DNS servers. *Never* use wildcards or allow transfers to any host. This is a direct CoreDNS configuration.
    *   **Use TSIG (Transaction Signature):** Implement TSIG to cryptographically authenticate zone transfer requests, ensuring that only authorized servers can receive the zone data. This requires configuring shared secrets between the primary and secondary servers, managed within CoreDNS's configuration.
    *   **Monitor Transfer Logs:** Enable logging for the `transfer` plugin and regularly review the logs for any unauthorized transfer attempts. This relies on CoreDNS's logging.

