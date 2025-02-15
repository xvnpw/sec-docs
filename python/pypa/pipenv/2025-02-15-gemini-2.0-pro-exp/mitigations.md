# Mitigation Strategies Analysis for pypa/pipenv

## Mitigation Strategy: [Explicitly Specify Package Sources](./mitigation_strategies/explicitly_specify_package_sources.md)

**Description:**
1.  **Open `Pipfile`:** Locate the `Pipfile` in the root directory of your project.
2.  **Define Sources:** For *each* package listed under `[packages]` and `[dev-packages]`, add an `index` key specifying the source.  Ensure a `[[source]]` block exists for each source you use (typically PyPI and/or a private index).
3.  **Verify SSL:** In the `[[source]]` block, ensure `verify_ssl = true` is set for HTTPS sources.
4.  **Example:**
    ```toml
    [[source]]
    url = "https://pypi.org/simple"
    verify_ssl = true
    name = "pypi"

    [packages]
    requests = {version = "==2.31.0", index = "pypi"}
    my-internal-package = {version = "==1.2.3", index = "my-private-index"}

    [[source]]
    url = "https://my-artifactory.com/api/pypi/my-private-repo/simple"
    verify_ssl = true
    name = "my-private-index"
    ```
5.  **Lock and Test:** After modifying the `Pipfile`, run `pipenv lock` to update the `Pipfile.lock`.  Then, run `pipenv install` and thoroughly test your application. This is a crucial step, as `pipenv` handles the source resolution.

**Threats Mitigated:**
*   **Dependency Confusion/Substitution (High Severity):** Prevents attackers from tricking `pipenv` into installing a malicious package from a public index with the same name as an internal package or a package intended to come from PyPI. This is directly mitigated by `pipenv`'s handling of the `index` key.
*   **Typosquatting Attacks (High Severity):** Reduces the risk, as `pipenv` will only look at the specified index.

**Impact:**
*   **Dependency Confusion/Substitution:** Risk significantly reduced (almost eliminated if a private index is used for internal packages and `pipenv` correctly enforces the source).
*   **Typosquatting Attacks:** Risk reduced, as `pipenv` limits the search space.

**Currently Implemented:** Partially.  PyPI source is explicitly defined for most packages, but some older dependencies are missing the `index` key.  Private index is defined but not consistently used.

**Missing Implementation:**  `Pipfile` needs review to ensure *all* packages have the `index` key.  The project needs to standardize on using the private index for all internal packages, and ensure `pipenv` is configured to use it correctly.

## Mitigation Strategy: [Version Pinning and Hash Checking (Leveraging `Pipfile.lock`)](./mitigation_strategies/version_pinning_and_hash_checking__leveraging__pipfile_lock__.md)

**Description:**
1.  **Pin Versions:** In your `Pipfile`, use the `==` operator to specify exact versions for *all* dependencies.
2.  **Generate Lock File:** Run `pipenv lock` to generate or update the `Pipfile.lock`. This is the core `pipenv` command for this mitigation.
3.  **Install from Lock File:**  Use `pipenv install --ignore-pipfile`. This is a *critical* `pipenv`-specific command that enforces the use of the lock file.
4.  **Hash Verification:** `pipenv` *automatically* verifies the hashes of downloaded packages against the values in `Pipfile.lock`. This is a built-in feature of `pipenv`.
5.  **Regularly Update Lock File:** Periodically, update dependencies and regenerate the `Pipfile.lock` using `pipenv lock`.

**Threats Mitigated:**
*   **Dependency Hijacking (High Severity):** `pipenv`'s hash checking, enforced by the `Pipfile.lock`, prevents installation of compromised packages.
*   **Unintentional Upgrades (Medium Severity):** `pipenv install --ignore-pipfile` prevents upgrades, relying solely on the lock file.
*   **Supply Chain Attacks (High Severity):** Mitigated by `pipenv`'s hash verification and version pinning.

**Impact:**
*   **Dependency Hijacking:** Risk significantly reduced (almost eliminated, relying on `pipenv`'s correct hash verification and the integrity of the `Pipfile.lock`).
*   **Unintentional Upgrades:** Risk eliminated due to `pipenv`'s lock file enforcement.
*   **Supply Chain Attacks:** Risk significantly reduced.

**Currently Implemented:** Mostly.  Versions are pinned, and `Pipfile.lock` is used. However, the CI/CD pipeline sometimes uses `pipenv install` without `--ignore-pipfile`.

**Missing Implementation:**  The CI/CD pipeline needs to be updated to *always* use `pipenv install --ignore-pipfile`.  A process for regularly updating the `Pipfile.lock` (using `pipenv lock`) needs to be formalized.

## Mitigation Strategy: [Keep `pipenv` Updated](./mitigation_strategies/keep__pipenv__updated.md)

**Description:**
1.  **Check for Updates:** Regularly check for new `pipenv` releases.
2.  **Update `pipenv`:** Update using the appropriate method (e.g., `pip install --upgrade pipenv`).
3.  **Test After Update:** After updating `pipenv`, run `pipenv install` and test your application. This is important because `pipenv` itself could have bugs affecting dependency resolution or security features.

**Threats Mitigated:**
*   **Vulnerabilities in `pipenv` (Variable Severity, potentially High):** Addresses security vulnerabilities in `pipenv` itself, which could affect its ability to securely manage dependencies.

**Impact:**
*   **Vulnerabilities in `pipenv`:** Risk reduced, depending on the severity of the patched vulnerabilities in `pipenv`.

**Currently Implemented:** Ad-hoc. Developers are responsible for updating `pipenv`.

**Missing Implementation:** A policy and mechanism for ensuring all developers use an up-to-date `pipenv` version are needed.

## Mitigation Strategy: [Verify Pipfile.lock integrity (using pipenv install --ignore-pipfile)](./mitigation_strategies/verify_pipfile_lock_integrity__using_pipenv_install_--ignore-pipfile_.md)

**Description:**
1.  **Generate Checksum (Development):** After running `pipenv lock` in your development environment, generate a checksum (e.g., SHA256) of the `Pipfile.lock` file.
2.  **Generate Checksum (CI/CD):**  In your CI/CD pipeline, *before* running `pipenv install`, generate a checksum of the `Pipfile.lock`.
3.  **Compare Checksums:** Compare the checksums.
4.  **Fail Build on Mismatch:** If they don't match, fail the build.
5. **Use pipenv:** Use `pipenv install --ignore-pipfile` to install dependencies.
6. Example (bash):
    ```bash
    # Development:
    sha256sum Pipfile.lock > Pipfile.lock.sha256

    # CI/CD:
    sha256sum -c Pipfile.lock.sha256
    if [ $? -ne 0 ]; then
      echo "ERROR: Pipfile.lock checksum mismatch!"
      exit 1
    fi
    pipenv install --ignore-pipfile
    ```

**Threats Mitigated:**
*   **Tampered `Pipfile.lock` (High Severity):** Detects if the `Pipfile.lock` has been modified. This relies on `pipenv install --ignore-pipfile` to *only* use the lock file.

**Impact:**
*   **Tampered `Pipfile.lock`:** Risk significantly reduced. The use of `pipenv install --ignore-pipfile` is crucial here.

**Currently Implemented:** Not implemented.

**Missing Implementation:** This needs to be implemented in the CI/CD pipeline, and the use of `pipenv install --ignore-pipfile` must be enforced.

