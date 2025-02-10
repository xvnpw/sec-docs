# Threat Model Analysis for distribution/distribution

## Threat: [Malicious Image Push with Spoofed Tag](./threats/malicious_image_push_with_spoofed_tag.md)

*   **Threat:** Malicious Image Push with Spoofed Tag

    *   **Description:** An attacker with push access to a repository (or who has compromised credentials) uploads a malicious image and tags it with a name that mimics a legitimate, commonly used tag (e.g., `latest`, a version number close to a legitimate one, or a typo-squatted tag). The attacker crafts the image to include malware, backdoors, or vulnerable components. The registry *accepts* this push if authentication/authorization checks pass.
    *   **Impact:** Users pulling the spoofed tag unknowingly deploy the malicious image, leading to potential code execution, data breaches, or system compromise in their environments.
    *   **Affected Component:**
        *   `registry/handlers/app.go` (API endpoint handling image pushes – specifically, the tag handling logic).
        *   `registry/storage/driver.go` (interaction with the storage backend – the registry writes the malicious image).
        *   Tagging system in general.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Tagging Policies:** Implement and enforce strict naming conventions for tags *within the registry's configuration*. Limit who can create or modify tags (authorization).
        *   **Image Signing (Notary/Cosign):**  *Crucially*, require image signing and enforce verification on the *client-side*. This is the primary defense, as it prevents the *use* of untrusted images, even if pushed. The registry itself doesn't enforce signing, but client-side verification is essential.
        *   **Repository Mirroring (Client-Side):** While not directly a registry feature, client-side mirroring controls which images can be pulled, mitigating exposure.
        *   **User Education:** Train users to carefully inspect image names and tags *and* verify image signatures.

## Threat: [Denial of Service via Large Image Upload](./threats/denial_of_service_via_large_image_upload.md)

*   **Threat:** Denial of Service via Large Image Upload

    *   **Description:** An attacker repeatedly uploads extremely large images or a large number of images. While the storage backend *ultimately* bears the brunt, the registry's handling of these uploads is the direct point of attack.
    *   **Impact:** The registry becomes unavailable for legitimate users, preventing them from pushing or pulling images. The registry itself may become unresponsive due to resource exhaustion.
    *   **Affected Component:**
        *   `registry/handlers/blobs.go` (handling of blob uploads – this is where limits should be enforced).
        *   `registry/storage/driver.go` (interaction with the storage backend – the registry initiates the writes).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Storage Quotas (Registry Configuration):** Implement storage quotas per user and per repository *within the registry's configuration*. This is a *critical* mitigation, enforced by the registry.
        *   **Rate Limiting (Registry Configuration):** Limit the rate of image uploads per user and per IP address, configured within the registry.
        *   **Image Size Limits (Registry Configuration):** Enforce maximum image size limits *within the registry's configuration*. This is a direct registry control.
        *   **Monitoring:** Monitor registry performance and resource utilization (CPU, memory, network) to detect and respond to DoS attempts.

## Threat: [Denial of Service via Excessive API Requests](./threats/denial_of_service_via_excessive_api_requests.md)

*   **Threat:** Denial of Service via Excessive API Requests

    *   **Description:** An attacker floods the registry API with a large number of requests (e.g., listing repositories, pulling manifests, initiating uploads), overwhelming the registry server *directly*.
    *   **Impact:** The registry becomes unresponsive or very slow, preventing legitimate users from interacting with it.
    *   **Affected Component:**
        *   `registry/handlers/app.go` (all API endpoints – these are the direct targets).
        *   `registry/api/v2/router.go` (routing of API requests – the router is overwhelmed).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting (Registry Configuration):** Implement robust rate limiting per user and per IP address, specifically targeting API endpoints. This is configured *within the registry*.
        *   **Load Balancing:** Deploy the registry behind a load balancer (external, but essential).
        *   **Resource Limits (Registry/Container Configuration):** Configure resource limits (CPU, memory) for the registry process (often within the container runtime) to prevent it from consuming all available resources.
        * **Connection Limits (Registry Configuration):** Configure the maximum number of the concurrent connections.

## Threat: [Vulnerability in Registry Dependency](./threats/vulnerability_in_registry_dependency.md)

* **Threat:** Vulnerability in Registry Dependency

    * **Description:** A vulnerability is discovered in a third-party library used by `distribution/distribution`. This could be in a library used for storage, networking, or other functionality.
    * **Impact:** The impact depends on the specific vulnerability, but could range from denial of service to remote code execution.
    * **Affected Component:** Any component that uses the vulnerable dependency.
    * **Risk Severity:** Varies (High to Critical, depending on the vulnerability)
    * **Mitigation Strategies:**
        * **Dependency Management:** Use a dependency management tool (e.g., `go mod`) to track and update dependencies.
        * **Vulnerability Scanning:** Regularly scan dependencies for known vulnerabilities using tools like `snyk`, `dependabot`, or `govulncheck`.
        * **Prompt Patching:** Apply security updates to dependencies as soon as they are available.
        * **Vendor Security Advisories:** Monitor vendor security advisories for the libraries used by `distribution/distribution`.

## Threat: [Unpatched Registry Software](./threats/unpatched_registry_software.md)

* **Threat:** Unpatched Registry Software

    * **Description:** The deployed version of `distribution/distribution` contains known vulnerabilities that have not been patched.
    * **Impact:** Attackers can exploit these vulnerabilities to gain unauthorized access, compromise the registry, or cause denial of service.
    * **Affected Component:** Potentially any component, depending on the vulnerability.
    * **Risk Severity:** Varies (High to Critical, depending on the vulnerability)
    * **Mitigation Strategies:**
        * **Regular Updates:** Keep the `distribution/distribution` software up to date with the latest releases. Subscribe to release announcements.
        * **Automated Updates (with Caution):** Consider automating updates, but *thoroughly* test updates in a staging environment before deploying to production.
        * **Vulnerability Scanning:** Regularly scan the registry itself for known vulnerabilities.

