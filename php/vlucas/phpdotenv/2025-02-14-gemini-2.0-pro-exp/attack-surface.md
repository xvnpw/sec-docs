# Attack Surface Analysis for vlucas/phpdotenv

## Attack Surface: [Direct `.env` File Exposure](./attack_surfaces/direct___env__file_exposure.md)

*   **Description:**  Attackers directly access the `.env` file via a web browser or other means, obtaining all contained secrets.  This is the most common and severe vulnerability associated with `phpdotenv` usage.
*   **`phpdotenv` Contribution:**  `phpdotenv` *defines* the use of the `.env` file as the central repository for sensitive configuration, making this file the primary target for attackers. The library's purpose is to load this file, so its exposure is a direct consequence of using the library.
*   **Example:**  An attacker navigates to `https://example.com/.env` and downloads the file containing database credentials, API keys, and other secrets.
*   **Impact:**  Complete compromise of all secrets stored in the `.env` file, leading to potential database breaches, unauthorized API access, and other severe consequences.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Web Server Configuration:**  Configure the webserver (Apache, Nginx) to *deny all access* to files starting with a dot (`.`).  This should be a global setting.
        *   **Apache:** Use `<FilesMatch "^\.">` in `.htaccess` or the main configuration.
        *   **Nginx:** Use `location ~ /\. { deny all; }`.
    *   **File Placement:**  Store the `.env` file *outside* the web server's document root (the publicly accessible directory).  This is the most effective mitigation.
    *   **Web Application Firewall (WAF):**  Configure a WAF to block requests for `.env` files.
    *   **Regular Audits:**  Periodically review web server configurations and file placements.

## Attack Surface: [Version Control Inclusion](./attack_surfaces/version_control_inclusion.md)

*   **Description:**  The `.env` file is accidentally committed to a version control repository (e.g., Git), exposing secrets to anyone with access to the repository.
*   **`phpdotenv` Contribution:**  `phpdotenv`'s reliance on a separate `.env` file *creates* the risk of this file being accidentally committed if developers are not diligent. The library's core functionality is tied to this file.
*   **Example:**  A developer forgets to add `.env` to `.gitignore` and commits the file containing production database credentials to a public GitHub repository.
*   **Impact:**  Exposure of all secrets to anyone who can access the repository, potentially including the public.  Secrets remain in the repository's history even after removal.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **`.gitignore` (or Equivalent):**  *Always* add `.env` to the `.gitignore` file (or the equivalent for other version control systems) *before* the initial commit.
    *   **Developer Training:**  Educate developers on the importance of never committing secrets.
    *   **Pre-Commit Hooks:**  Use pre-commit hooks (e.g., `git-secrets`, `pre-commit`) to scan for potential secret commits.
    *   **Repository Scanning:**  Use tools like truffleHog or GitGuardian to scan repositories.
    *   **Secret Rotation (If Compromised):**  If a secret has been committed, *immediately* rotate all affected credentials and remove the file from the repository history (complex process).

## Attack Surface: [Insecure Backup Storage](./attack_surfaces/insecure_backup_storage.md)

*   **Description:** Backups of the application or server include the `.env` file, and these backups are not adequately protected, leading to potential secret exposure.
*   **`phpdotenv` Contribution:** The existence and central role of the `.env` file, as defined by `phpdotenv`, makes backups containing this file a high-value target. The library's design necessitates this file, thus directly contributing to this risk.
*   **Example:** An attacker gains access to an unencrypted S3 bucket containing server backups, which include the `.env` file with production credentials.
*   **Impact:** Exposure of all secrets contained in the `.env` file.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Exclude `.env` from Backups:** If possible, exclude the `.env` file from backups. Manage secrets separately.
    *   **Secure Backup Storage:** If the `.env` file *must* be backed up:
        *   **Encryption:** Encrypt backups both in transit and at rest.
        *   **Access Control:** Implement strict access controls.
        *   **Regular Audits:** Regularly review backup security.

## Attack Surface: [Overly Permissive File Permissions](./attack_surfaces/overly_permissive_file_permissions.md)

*   **Description:** The `.env` file has file permissions that allow unauthorized users or processes on the same system to read its contents.
*   **`phpdotenv` Contribution:** `phpdotenv` *requires* reading the `.env` file. Incorrect file permissions directly compromise the secrets that `phpdotenv` is designed to load. The library's functionality is directly impacted by these permissions.
*   **Example:** The `.env` file is set to `chmod 777` (read, write, and execute for everyone), allowing any user on the server to read the database credentials.
*   **Impact:** Exposure of all secrets in the `.env` file to other users or processes on the same server.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Restrictive Permissions:** Set strict file permissions on the `.env` file. On Linux/macOS, use `chmod 600 .env` (read and write only for the owner).
    *   **Dedicated User:** Run the web server process under a dedicated user account with limited privileges.
    *   **Regular Audits:** Periodically check file permissions.

