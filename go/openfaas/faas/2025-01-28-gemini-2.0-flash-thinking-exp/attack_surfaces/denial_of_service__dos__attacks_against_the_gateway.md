## Deep Analysis: Denial of Service (DoS) Attacks against the OpenFaaS Gateway

### 1. Define Objective of Deep Analysis

The primary objective of this deep analysis is to thoroughly investigate the Denial of Service (DoS) attack surface targeting the OpenFaaS Gateway. This analysis aims to:

*   **Understand the Attack Vector:**  Gain a comprehensive understanding of how DoS attacks can be launched against the OpenFaaS Gateway, identifying potential attack subtypes and entry points.
*   **Assess Impact and Risk:**  Evaluate the potential impact of successful DoS attacks on the OpenFaaS platform, its users, and dependent applications, quantifying the associated risks.
*   **Evaluate Mitigation Strategies:**  Critically analyze the effectiveness of the proposed mitigation strategies in preventing or mitigating DoS attacks against the Gateway, identifying strengths, weaknesses, and implementation considerations.
*   **Identify Gaps and Recommendations:**  Uncover potential gaps in the current mitigation strategies and propose additional security measures or enhancements to strengthen the Gateway's resilience against DoS attacks.
*   **Provide Actionable Insights:** Deliver clear and actionable recommendations to the development team for improving the security posture of the OpenFaaS Gateway against DoS threats.

### 2. Scope

This deep analysis is specifically focused on **Denial of Service (DoS) attacks targeting the OpenFaaS Gateway**. The scope includes:

*   **Attack Surface:**  The OpenFaaS Gateway component and its exposed interfaces (API endpoints for function invocation, management, metrics, etc.).
*   **Attack Vectors:**  Various types of DoS attacks applicable to the Gateway, including but not limited to:
    *   HTTP Flood attacks (SYN flood, ACK flood, HTTP GET/POST flood)
    *   Resource exhaustion attacks (CPU, memory, network bandwidth)
    *   Application-layer attacks (Slowloris, Slow Read)
    *   Amplification attacks (if applicable to Gateway services)
*   **Impact Assessment:**  Consequences of successful DoS attacks on:
    *   Platform availability and uptime
    *   Function execution and responsiveness
    *   User experience (developers, operators, application users)
    *   Business operations relying on OpenFaaS
*   **Mitigation Strategies:**  Detailed evaluation of the proposed mitigation strategies:
    *   Rate Limiting on Gateway API
    *   Resource Limits for Gateway Component
    *   DDoS Protection Infrastructure
    *   Scalable Gateway Deployment
*   **Exclusions:**
    *   DoS attacks targeting functions directly (function code vulnerabilities, resource consumption within functions) - unless directly related to Gateway overload.
    *   DoS attacks targeting other OpenFaaS components (e.g., Prometheus, NATS, Function containers) - unless they indirectly impact the Gateway's availability.
    *   Distributed Denial of Service (DDoS) attacks in the context of botnet-driven attacks (while DDoS protection infrastructure is considered, the focus is on the Gateway's inherent vulnerabilities to DoS).

### 3. Methodology

The deep analysis will be conducted using the following methodology:

1.  **Information Gathering and Review:**
    *   Thoroughly review the provided attack surface description.
    *   Consult official OpenFaaS documentation, architecture diagrams, and security best practices related to the Gateway.
    *   Research common DoS attack techniques and their application to API Gateways and Kubernetes-based applications.

2.  **Threat Modeling and Attack Vector Analysis:**
    *   Develop detailed threat models specifically for DoS attacks against the OpenFaaS Gateway.
    *   Identify potential attack vectors, considering different types of DoS attacks and how they can be exploited against the Gateway's API endpoints and underlying infrastructure.
    *   Analyze the Gateway's architecture and dependencies to pinpoint potential weaknesses susceptible to DoS attacks.

3.  **Impact and Risk Assessment:**
    *   Analyze the potential impact of successful DoS attacks on various aspects of the OpenFaaS platform and its users, as outlined in the scope.
    *   Quantify the risk severity based on the likelihood of successful attacks and the magnitude of the potential impact.
    *   Consider different attack scenarios and their corresponding impact levels.

4.  **Mitigation Strategy Evaluation:**
    *   For each proposed mitigation strategy, conduct a detailed evaluation:
        *   **Mechanism of Action:** Explain how the mitigation strategy works technically to counter DoS attacks.
        *   **Effectiveness:** Assess its effectiveness against different types of DoS attacks and attack volumes.
        *   **Implementation Considerations:**  Analyze the practical aspects of implementing the mitigation within OpenFaaS, including configuration, deployment, and operational overhead.
        *   **Limitations and Weaknesses:** Identify any limitations or weaknesses of the mitigation strategy, including potential bypass techniques or scenarios where it might be less effective.

5.  **Gap Analysis and Recommendations:**
    *   Based on the mitigation evaluation, identify any gaps in the current security posture against DoS attacks.
    *   Propose additional mitigation strategies, security controls, or architectural improvements to address identified gaps and enhance resilience.
    *   Prioritize recommendations based on their effectiveness, feasibility, and impact.

6.  **Documentation and Reporting:**
    *   Document all findings, analysis, and recommendations in a clear and structured markdown report.
    *   Present the analysis in a format suitable for the development team and stakeholders, highlighting key risks and actionable steps.

### 4. Deep Analysis of Attack Surface: Denial of Service (DoS) Attacks against the Gateway

#### 4.1. Detailed Description of the Attack Surface

The OpenFaaS Gateway acts as the central control plane and entry point for all interactions with the OpenFaaS platform. It is responsible for:

*   **Function Invocation:**  Receiving and routing function invocation requests from external clients.
*   **Function Management:**  Handling API requests for deploying, updating, deleting, and listing functions.
*   **Platform Management:**  Providing endpoints for platform-level operations, such as scaling, metrics, and health checks.
*   **Authentication and Authorization:**  Enforcing security policies and controlling access to functions and platform resources (depending on configuration).

This central role makes the Gateway a critical component and a prime target for Denial of Service attacks. If an attacker can successfully overwhelm the Gateway, they can effectively shut down the entire OpenFaaS platform, preventing function execution and management operations.

**Attack Vectors and Subtypes:**

*   **HTTP Flood Attacks:**
    *   **HTTP GET/POST Flood:** Attackers send a massive volume of seemingly legitimate HTTP GET or POST requests to the Gateway's function invocation endpoints (`/function/{function_name}`) or management endpoints. This overwhelms the Gateway's capacity to process requests, leading to resource exhaustion (CPU, memory, network connections) and slow response times or complete unresponsiveness.
    *   **SYN Flood:** Attackers initiate a large number of TCP connection requests (SYN packets) without completing the handshake (ACK). This can exhaust the Gateway's connection resources and prevent legitimate connections from being established.
    *   **ACK Flood:** Attackers send a flood of ACK packets, attempting to overwhelm the Gateway's ability to process and manage these packets.

*   **Resource Exhaustion Attacks:**
    *   **CPU Exhaustion:**  Attackers may craft requests that trigger computationally intensive operations within the Gateway, consuming excessive CPU resources and slowing down or halting request processing. This could involve complex function invocations (if allowed without proper limits) or exploiting vulnerabilities in request parsing or processing logic.
    *   **Memory Exhaustion:**  Similar to CPU exhaustion, attackers might send requests that cause the Gateway to allocate excessive memory, leading to memory exhaustion and potential crashes. This could be through large request payloads, memory leaks, or inefficient resource management.
    *   **Network Bandwidth Exhaustion:**  High-volume request floods can saturate the network bandwidth available to the Gateway, preventing legitimate traffic from reaching it and causing network congestion.

*   **Application-Layer Attacks:**
    *   **Slowloris:** Attackers send slow, incomplete HTTP requests, keeping connections to the Gateway open for extended periods. By opening a large number of these slow connections, they can exhaust the Gateway's connection limits and prevent new legitimate connections.
    *   **Slow Read (R-U-Dead-Yet):** Attackers initiate legitimate requests but read the response data very slowly. This keeps server resources tied up for extended periods, potentially exhausting connection limits and resources.

#### 4.2. How FaaS Contributes to the Attack Surface

OpenFaaS's architecture, while offering benefits in scalability and agility, inherently contributes to the DoS attack surface of the Gateway in several ways:

*   **Single Point of Entry:** The Gateway is the *single* entry point for all function invocations and management operations. This centralization, while simplifying access, also creates a single point of failure and a concentrated target for attackers. Compromising or overwhelming the Gateway impacts the entire platform.
*   **API Exposure:** The Gateway exposes a public API for function invocation and management. These API endpoints are accessible over the network and are potential targets for DoS attacks. The more publicly accessible and feature-rich the API, the larger the attack surface.
*   **Dynamic Function Execution:** The Gateway is responsible for dynamically routing requests to function containers. While this provides flexibility, it also adds complexity and potential overhead in request processing, which can be exploited in DoS attacks.
*   **Kubernetes Dependency:** OpenFaaS typically runs on Kubernetes. While Kubernetes provides resilience and scalability, misconfigurations or vulnerabilities in the underlying Kubernetes infrastructure can indirectly impact the Gateway's susceptibility to DoS attacks. For example, insufficient resource limits for the Gateway pod or network misconfigurations within the Kubernetes cluster.

#### 4.3. Example Scenario: HTTP Flood Attack

**Scenario:** An attacker wants to disrupt the "image-processing" function deployed on OpenFaaS. They identify the function invocation endpoint for this function: `https://<gateway-url>/function/image-processing`.

**Attack Execution:** The attacker uses a botnet or distributed attack tools to launch a large-scale HTTP GET flood attack against this endpoint. They send thousands of requests per second, each appearing to be a legitimate function invocation request (though potentially with minimal or invalid payloads to reduce attacker resource consumption).

**Impact on Gateway:**

1.  **Resource Overload:** The Gateway receives a massive influx of requests, overwhelming its network interfaces, CPU, and memory.
2.  **Request Queue Saturation:** The Gateway's request queues become saturated, leading to delays in processing legitimate requests.
3.  **Service Degradation:**  The Gateway's response times increase dramatically, and it may start dropping requests or failing to respond altogether.
4.  **Platform Unavailability:**  The Gateway becomes effectively unavailable, preventing legitimate function invocations and management operations. Users are unable to access or utilize any functions deployed on OpenFaaS.
5.  **Cascading Effects:**  If the Gateway's unavailability impacts other dependent services or applications, it can lead to broader system disruptions.

#### 4.4. Impact: High

The impact of a successful DoS attack against the OpenFaaS Gateway is **High** due to the following reasons:

*   **Platform Unavailability:** The most immediate and critical impact is the complete or partial unavailability of the OpenFaaS platform. This means functions cannot be invoked, deployed, updated, or managed.
*   **Disruption of Function Execution:** All functions deployed on OpenFaaS become inaccessible, disrupting any applications or services that rely on these functions. This can lead to business process failures, service outages, and data processing delays.
*   **Inability to Manage OpenFaaS Environment:** Administrators are unable to manage the OpenFaaS environment through the Gateway API. This includes scaling functions, deploying new functions, monitoring platform health, and performing essential maintenance tasks.
*   **Business Disruption:** For organizations heavily reliant on OpenFaaS for critical applications or services, a prolonged DoS attack can lead to significant business disruption, financial losses, and reputational damage.
*   **Loss of Productivity:** Development teams and operations teams are unable to work with the OpenFaaS platform, leading to productivity losses and delays in project timelines.
*   **Potential Data Loss (Indirect):** While DoS attacks primarily target availability, prolonged unavailability can indirectly lead to data loss in scenarios where functions are involved in real-time data processing or temporary data storage if proper error handling and persistence mechanisms are not in place.

#### 4.5. Risk Severity: High

The Risk Severity is also assessed as **High** due to the combination of:

*   **High Impact:** As detailed above, the potential impact of a successful DoS attack is severe, leading to platform-wide disruption and business consequences.
*   **Moderate to High Likelihood:** DoS attacks are a common and relatively easy-to-execute attack vector. The OpenFaaS Gateway, being a publicly accessible API endpoint, is inherently exposed to this type of threat. The likelihood of a DoS attack being attempted is considered moderate to high, especially for publicly facing OpenFaaS deployments.
*   **Relatively Low Attacker Skill Required:** Launching basic DoS attacks, such as HTTP floods, does not require highly sophisticated attackers or advanced tools. Script kiddies or less skilled attackers can potentially launch disruptive attacks.

#### 4.6. Mitigation Strategies: Evaluation and Deep Dive

**1. Rate Limiting on Gateway API:**

*   **Mechanism of Action:** Rate limiting restricts the number of requests allowed from a specific source (e.g., IP address, API key) or across the entire platform within a defined time window. This is typically implemented using algorithms like token bucket or leaky bucket.
*   **Effectiveness:**
    *   **High Effectiveness against:** HTTP flood attacks, brute-force attempts, and excessive request bursts from a single source.
    *   **Moderate Effectiveness against:** Distributed DoS attacks (DDoS) from a large number of distinct IP addresses, although it can still limit the overall impact.
    *   **Lower Effectiveness against:** Application-layer attacks like Slowloris or Slow Read, which are designed to bypass simple rate limiting based on request frequency.
*   **Implementation Considerations in OpenFaaS:**
    *   **Gateway Level Implementation:** Rate limiting should be implemented directly within the OpenFaaS Gateway component. This can be achieved using middleware or libraries specifically designed for rate limiting in Go (the language OpenFaaS Gateway is written in).
    *   **Configuration Flexibility:** Rate limiting rules should be configurable, allowing administrators to define limits based on different criteria (e.g., requests per minute per IP, requests per second platform-wide).
    *   **Granularity:** Consider implementing rate limiting at different levels of granularity:
        *   **Global Rate Limiting:** Limits the total number of requests the Gateway can handle across all sources.
        *   **Per-IP Rate Limiting:** Limits requests from individual IP addresses.
        *   **Per-Function Rate Limiting:** Limits requests to specific functions (useful for protecting resource-intensive functions).
        *   **Authenticated vs. Unauthenticated Rate Limiting:** Different limits for authenticated and unauthenticated users.
    *   **Bypass Mechanisms:** Implement mechanisms to bypass rate limiting for legitimate internal traffic (e.g., from other OpenFaaS components or monitoring systems).
    *   **Logging and Monitoring:**  Log rate limiting events (e.g., requests being rate-limited) for monitoring and analysis.
*   **Limitations and Weaknesses:**
    *   **Bypass by Distributed Attacks:** Rate limiting based on IP addresses can be bypassed by DDoS attacks originating from a large number of distinct IP addresses.
    *   **Legitimate Traffic Impact:**  Aggressive rate limiting can inadvertently impact legitimate users during traffic spikes or legitimate bursts of activity. Careful configuration and monitoring are crucial to avoid false positives.
    *   **Complexity in Configuration:**  Setting optimal rate limits requires careful analysis of expected traffic patterns and potential attack volumes. Incorrectly configured rate limits can be ineffective or overly restrictive.
    *   **Not Effective Against Application-Layer Attacks:** Rate limiting alone is not sufficient to mitigate sophisticated application-layer DoS attacks like Slowloris or Slow Read.

**2. Resource Limits for Gateway Component:**

*   **Mechanism of Action:** Kubernetes resource limits (CPU and memory requests and limits) are configured for the Gateway pod deployment. These limits restrict the maximum resources the Gateway container can consume.
*   **Effectiveness:**
    *   **High Effectiveness against:** Resource exhaustion attacks targeting CPU and memory. Prevents the Gateway from consuming excessive resources and potentially crashing the underlying node.
    *   **Indirect Effectiveness against:** HTTP flood attacks by limiting the resources available to process malicious requests, potentially causing attackers to exhaust their resources faster.
    *   **Lower Effectiveness against:** Network bandwidth exhaustion attacks or application-layer attacks that don't directly consume excessive CPU or memory.
*   **Implementation Considerations in OpenFaaS:**
    *   **Kubernetes Deployment Configuration:** Resource limits are configured in the Kubernetes deployment manifest for the OpenFaaS Gateway.
    *   **Right-Sizing:**  Properly sizing resource limits is crucial. Limits should be high enough to handle expected traffic peaks and legitimate workloads but low enough to prevent resource exhaustion during attacks.
    *   **Monitoring Resource Usage:**  Continuously monitor the Gateway's resource usage (CPU, memory) using Kubernetes monitoring tools (e.g., Prometheus, Kubernetes Dashboard) to identify potential bottlenecks and adjust resource limits as needed.
    *   **Horizontal Pod Autoscaling (HPA):** Combine resource limits with HPA to automatically scale the number of Gateway pods based on CPU or memory utilization. This allows the Gateway to dynamically adapt to increased load, including DoS attacks.
*   **Limitations and Weaknesses:**
    *   **Does not Prevent Attacks:** Resource limits do not prevent DoS attacks from reaching the Gateway. They only limit the impact of resource exhaustion on the Gateway itself.
    *   **Potential Performance Bottleneck:**  Overly restrictive resource limits can become a performance bottleneck, limiting the Gateway's ability to handle legitimate traffic even under normal conditions.
    *   **Requires Careful Tuning:**  Setting optimal resource limits requires careful performance testing and monitoring to find the right balance between resource protection and performance.

**3. DDoS Protection Infrastructure:**

*   **Mechanism of Action:** Utilizing dedicated DDoS mitigation services or infrastructure-level defenses (e.g., cloud provider DDoS protection, CDN with DDoS protection). These services typically operate at the network edge, filtering out malicious traffic before it reaches the OpenFaaS Gateway. They employ various techniques like traffic scrubbing, anomaly detection, and rate limiting at the infrastructure level.
*   **Effectiveness:**
    *   **High Effectiveness against:** Large-scale volumetric DDoS attacks (HTTP floods, SYN floods, UDP floods) originating from distributed botnets.
    *   **Moderate Effectiveness against:** Application-layer attacks, depending on the sophistication of the DDoS protection service. Advanced services may offer application-layer filtering and behavioral analysis.
    *   **Lower Effectiveness against:** Highly targeted, low-volume application-layer attacks or attacks originating from within the trusted network.
*   **Implementation Considerations in OpenFaaS:**
    *   **Cloud Provider Integration:** Leverage DDoS protection services offered by cloud providers (AWS Shield, Azure DDoS Protection, Google Cloud Armor) if OpenFaaS is deployed in the cloud.
    *   **CDN Integration:**  Use a Content Delivery Network (CDN) with built-in DDoS protection in front of the OpenFaaS Gateway. CDNs can absorb large volumes of traffic and filter out malicious requests.
    *   **Dedicated DDoS Mitigation Appliances:** For on-premises deployments or more advanced protection, consider deploying dedicated DDoS mitigation appliances or services.
    *   **Configuration and Monitoring:**  Properly configure the DDoS protection service to identify and mitigate malicious traffic while allowing legitimate traffic to pass through. Monitor DDoS mitigation logs and alerts.
*   **Limitations and Weaknesses:**
    *   **Cost:** DDoS protection services can be expensive, especially for advanced features and high traffic volumes.
    *   **Configuration Complexity:**  Configuring and managing DDoS protection services can be complex and require specialized expertise.
    *   **False Positives:**  Aggressive DDoS mitigation can sometimes lead to false positives, blocking legitimate users or traffic.
    *   **Latency:**  Introducing DDoS protection infrastructure can add some latency to legitimate requests, although reputable services minimize this impact.
    *   **Not a Silver Bullet:** DDoS protection is not a complete solution. It should be used in conjunction with other mitigation strategies like rate limiting and resource limits.

**4. Scalable Gateway Deployment:**

*   **Mechanism of Action:** Designing the Gateway infrastructure to be horizontally scalable. This involves deploying multiple Gateway instances behind a load balancer and using auto-scaling to dynamically adjust the number of instances based on traffic load.
*   **Effectiveness:**
    *   **High Effectiveness against:** HTTP flood attacks and other volumetric attacks by distributing the load across multiple Gateway instances. Increases the overall capacity to handle requests.
    *   **Moderate Effectiveness against:** Application-layer attacks, as scaling alone may not address vulnerabilities in the application logic. However, it can improve resilience by distributing the impact.
    *   **Lower Effectiveness against:** Resource exhaustion attacks if the underlying infrastructure itself becomes saturated.
*   **Implementation Considerations in OpenFaaS:**
    *   **Kubernetes Deployment and Service:** Deploy the OpenFaaS Gateway as a Kubernetes Deployment with multiple replicas and expose it through a Kubernetes Service of type LoadBalancer or NodePort.
    *   **Load Balancing:**  Kubernetes Services provide built-in load balancing across Gateway pods. Ensure proper load balancing configuration (e.g., round-robin, least connections).
    *   **Horizontal Pod Autoscaling (HPA):**  Enable HPA for the Gateway Deployment to automatically scale the number of pods based on CPU utilization, memory utilization, or custom metrics.
    *   **Stateless Gateway Design:** Ensure the Gateway component is designed to be stateless so that scaling out multiple instances is seamless and does not introduce data consistency issues.
    *   **Monitoring and Alerting:**  Monitor the performance and health of Gateway instances and set up alerts for scaling events and potential issues.
*   **Limitations and Weaknesses:**
    *   **Increased Infrastructure Complexity:** Scalable deployments add complexity to the infrastructure and management.
    *   **Resource Consumption:** Scaling out Gateway instances increases overall resource consumption (CPU, memory, network).
    *   **Not a Prevention Mechanism:** Scalability does not prevent DoS attacks from reaching the Gateway. It only improves the platform's ability to handle increased load and maintain availability under attack.
    *   **Cost:** Running multiple Gateway instances can increase infrastructure costs.

### 5. Gap Analysis and Recommendations

**Identified Gaps:**

*   **Lack of Application-Layer Attack Mitigation:** While rate limiting and DDoS protection can address volumetric attacks, the current mitigation strategies are less focused on application-layer attacks like Slowloris or Slow Read.
*   **Limited Granularity in Rate Limiting:**  The proposed rate limiting is mentioned at a general "Gateway API" level. More granular rate limiting options (per-function, authenticated vs. unauthenticated) would provide better control and flexibility.
*   **Proactive Threat Detection:** The current mitigations are primarily reactive (rate limiting, resource limits, DDoS protection). Proactive threat detection mechanisms, such as anomaly detection or behavioral analysis, could enhance early detection and response to DoS attacks.
*   **Security Hardening of Gateway Component:**  Beyond the proposed mitigations, further security hardening of the Gateway component itself (code reviews, vulnerability scanning, secure coding practices) is crucial to minimize potential vulnerabilities that could be exploited in DoS attacks.
*   **Testing and Validation:**  Regularly testing and validating the effectiveness of DoS mitigation strategies through penetration testing and simulated DoS attacks is essential to ensure they are working as expected and identify any weaknesses.

**Recommendations:**

1.  **Implement Application-Layer Attack Mitigation:**
    *   **Connection Limits:** Implement connection limits on the Gateway to prevent attackers from exhausting connection resources with Slowloris or Slow Read attacks.
    *   **Request Timeout Configuration:** Configure appropriate timeouts for HTTP requests to prevent long-held connections from consuming resources indefinitely.
    *   **Web Application Firewall (WAF):** Consider deploying a WAF in front of the Gateway to provide application-layer filtering and protection against various attack types, including Slowloris and Slow Read.

2.  **Enhance Rate Limiting Granularity:**
    *   Implement rate limiting policies with finer granularity, including:
        *   Per-function rate limiting to protect resource-intensive functions.
        *   Different rate limits for authenticated and unauthenticated users.
        *   Rate limiting based on API endpoint or request type.
    *   Provide configurable rate limiting rules that administrators can easily adjust based on their specific needs and traffic patterns.

3.  **Explore Proactive Threat Detection:**
    *   Integrate anomaly detection mechanisms into the Gateway or monitoring systems to identify unusual traffic patterns that might indicate a DoS attack in progress.
    *   Consider using behavioral analysis techniques to detect and block malicious requests based on their characteristics rather than just request frequency.

4.  **Strengthen Gateway Security Hardening:**
    *   Conduct regular code reviews and security audits of the Gateway codebase to identify and fix potential vulnerabilities.
    *   Implement automated vulnerability scanning as part of the CI/CD pipeline for the Gateway component.
    *   Follow secure coding practices to minimize the risk of introducing new vulnerabilities.
    *   Keep dependencies of the Gateway component up-to-date with the latest security patches.

5.  **Regular Security Testing and Validation:**
    *   Conduct regular penetration testing and vulnerability assessments specifically targeting DoS attack scenarios against the OpenFaaS Gateway.
    *   Perform simulated DoS attacks in a staging environment to validate the effectiveness of implemented mitigation strategies and identify any weaknesses.
    *   Use monitoring and logging data from real-world traffic to continuously evaluate and refine DoS mitigation measures.

6.  **Document and Communicate Security Best Practices:**
    *   Document all implemented DoS mitigation strategies and configuration settings clearly.
    *   Communicate security best practices for deploying and operating OpenFaaS securely, including recommendations for DoS protection, to users and operators.

By implementing these recommendations, the development team can significantly strengthen the OpenFaaS Gateway's resilience against Denial of Service attacks, ensuring platform availability and protecting users from potential disruptions.