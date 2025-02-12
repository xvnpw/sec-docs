# Attack Surface Analysis for serverless/serverless

## Attack Surface: [Event Injection](./attack_surfaces/event_injection.md)

*   **1. Event Injection**

    *   **Description:** Attackers inject malicious data into the event payload that triggers a serverless function.  The attack vector is the event data itself.
    *   **Serverless Contribution:** Serverless functions are *inherently* event-driven.  The Serverless Framework facilitates connecting functions to a wide variety of event sources (S3, API Gateway, SNS, SQS, DynamoDB, etc.), vastly increasing the potential input vectors and complexity compared to traditional applications. This architectural shift is the core contributor.
    *   **Example:** An attacker uploads a malformed JSON file to an S3 bucket configured to trigger a function. The JSON contains a command injection payload that is executed when the function attempts to parse it.
    *   **Impact:** Code execution, data exfiltration, privilege escalation, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Implement rigorous input validation and sanitization *within the function code* for *all* fields in the event payload, regardless of the source. Use allow-lists, not deny-lists.
        *   **Output Encoding:** Use appropriate output encoding where necessary.
        *   **Least Privilege (IAM):** Minimize the function's IAM permissions.
        *   **Schema Validation:** Enforce expected event structures using schema validation.

## Attack Surface: [Over-Privileged Functions (IAM Roles)](./attack_surfaces/over-privileged_functions__iam_roles_.md)

*   **2. Over-Privileged Functions (IAM Roles)**

    *   **Description:** Functions are granted excessive permissions via their IAM roles, allowing attackers who compromise a function to access a wider range of AWS resources than intended.
    *   **Serverless Contribution:** The Serverless Framework simplifies IAM role creation, making it easy to inadvertently grant overly permissive roles (e.g., using wildcards `*`). The fine-grained nature of serverless functions (many small functions) increases the *number* of roles to manage, increasing the likelihood of misconfiguration.  The framework's ease of use can lead to a "set it and forget it" mentality with IAM.
    *   **Example:** A function intended only to write to a specific DynamoDB table is granted `dynamodb:*` permissions, allowing an attacker to read, modify, or delete data from *any* DynamoDB table in the account.
    *   **Impact:** Data breaches, data modification, resource hijacking, privilege escalation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Principle of Least Privilege:** Define granular IAM roles with *only* the absolutely necessary permissions. Avoid wildcards.
        *   **IAM Condition Keys:** Use condition keys to restrict access based on specific criteria.
        *   **Regular Audits:** Regularly audit IAM roles and policies. Use IAM Access Analyzer.
        *   **Separate Accounts:** Use separate AWS accounts for different environments.
        *   **Infrastructure as Code Review:** Thoroughly review `serverless.yml` and related IaC for IAM configurations.

## Attack Surface: [Insecure Secrets Management](./attack_surfaces/insecure_secrets_management.md)

*   **3. Insecure Secrets Management**

    *   **Description:** Sensitive information (API keys, database credentials) is stored insecurely (e.g., in code, environment variables without encryption, or `serverless.yml`).
    *   **Serverless Contribution:** Serverless functions *frequently* need to access secrets to interact with other services. While the Serverless Framework *provides* mechanisms for referencing secrets (via environment variables), it doesn't *enforce* secure practices. Developers often misunderstand the difference between referencing a secret and storing it directly in an environment variable. The ephemeral nature of functions can also lead to a false sense of security.
    *   **Example:** A function's environment variables (defined in `serverless.yml`) contain a plaintext database password, which is exposed if the function's configuration is compromised.
    *   **Impact:** Data breaches, unauthorized access to services, privilege escalation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Secrets Management Service:** *Always* use a dedicated secrets management service (AWS Secrets Manager, Parameter Store).
        *   **Environment Variable References:** Use environment variables to *reference* secrets, *not* to store them.
        *   **Least Privilege (IAM):** Restrict the function's IAM role to access only necessary secrets.
        *   **Secrets Rotation:** Implement regular secrets rotation.
        *   **Never Hardcode Secrets:** Never store secrets in code or `serverless.yml`.

## Attack Surface: [Denial of Service (DoS) / Resource Exhaustion](./attack_surfaces/denial_of_service__dos___resource_exhaustion.md)

*   **4. Denial of Service (DoS) / Resource Exhaustion**

    *   **Description:** Attackers trigger a large number of function invocations, leading to resource exhaustion (concurrency limits, compute time, costs) or service unavailability.
    *   **Serverless Contribution:** The *pay-per-use* and *auto-scaling* nature of serverless makes it inherently more vulnerable to resource exhaustion attacks.  The Serverless Framework, by making it easy to deploy and scale functions, inadvertently amplifies this risk if not properly configured.  The "infinite scale" illusion can be dangerous.
    *   **Example:** An attacker sends a flood of requests to an API Gateway endpoint that triggers a serverless function, exceeding the account's concurrency limits and causing legitimate requests to be throttled or fail.
    *   **Impact:** Service unavailability, financial losses, performance degradation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Concurrency Limits:** Set *appropriate* concurrency limits for *all* functions.
        *   **Rate Limiting:** Implement rate limiting at the API Gateway level (if applicable).
        *   **Monitoring and Alerting:** Monitor function metrics (invocations, duration, errors) for anomalies.
        *   **AWS WAF:** Use AWS WAF to block malicious traffic.
        *   **Reserved Concurrency:** Use reserved concurrency for *critical* functions.
        *   **Circuit Breakers:** Implement circuit breakers to prevent cascading failures.

