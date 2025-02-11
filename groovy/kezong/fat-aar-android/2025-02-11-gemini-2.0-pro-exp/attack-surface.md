# Attack Surface Analysis for kezong/fat-aar-android

## Attack Surface: [Hidden Vulnerable Dependencies](./attack_surfaces/hidden_vulnerable_dependencies.md)

*   **Description:** The application unknowingly includes outdated or vulnerable libraries bundled within the "fat" AAR.
*   **How `fat-aar-android` Contributes:** This is the *core* issue. `fat-aar-android` bundles multiple AARs and their transitive dependencies, obscuring the origin and version of individual components.  This makes it *significantly* harder to identify and track specific vulnerable libraries compared to explicitly declared dependencies.  The problem isn't just having dependencies, it's the *hidden* nature of them within the bundled AAR.
*   **Example:** A bundled AAR includes an old version of `OkHttp` with a known CVE for a denial-of-service vulnerability. The application developer is unaware because they only see the "fat" AAR.
*   **Impact:** Exploitation can lead to denial of service, data breaches, remote code execution, or other consequences depending on the specific vulnerability.
*   **Risk Severity:** **Critical** to **High**
*   **Mitigation Strategies:**
    *   **Prefer Explicit Dependencies:** The primary mitigation. Avoid `fat-aar-android` whenever possible.
    *   **Pre-Bundling Dependency Analysis:** *Before* using `fat-aar-android`, thoroughly analyze *all* AARs and their transitive dependencies.
    *   **Regular Dependency Updates:** Update *all* dependencies, including those to be bundled.
    *   **Manual AAR Inspection:** Unzip the "fat" AAR and manually verify contents.
    *   **SBOM Generation:** Create and maintain a Software Bill of Materials.

## Attack Surface: [Supply Chain Compromise of Bundled AAR](./attack_surfaces/supply_chain_compromise_of_bundled_aar.md)

*   **Description:** A malicious actor compromises an upstream AAR *before* it's bundled, injecting malicious code.
*   **How `fat-aar-android` Contributes:** `fat-aar-android` directly facilitates this by bundling the compromised AAR. The "fat" AAR obscures the source of the malicious code, making detection *much* harder than if the compromised AAR were a direct, explicitly declared dependency. The act of bundling is the direct contribution.
*   **Example:** An attacker compromises a UI library's AAR, adding data exfiltration code. The developer, using `fat-aar-android`, unknowingly includes this.
*   **Impact:** Data theft, remote code execution, application compromise, reputational damage.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Verify AAR Sources:** Obtain AARs only from trusted sources.
    *   **Checksum Verification:** *Before bundling*, verify the checksum of each AAR.
    *   **Code Signing (of individual AARs):** Verify the digital signature of each AAR *before* bundling (if available).
    *   **Use a Private Artifact Repository:** Manage internal AARs with strict access controls and vulnerability scanning.

