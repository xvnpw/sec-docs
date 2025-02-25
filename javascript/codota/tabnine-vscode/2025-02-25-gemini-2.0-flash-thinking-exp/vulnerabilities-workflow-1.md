## Combined Vulnerability List

This document consolidates identified vulnerabilities from multiple reports into a unified list, removing duplicates and providing detailed descriptions, impacts, mitigations, and test cases for each.

### 1. Dependency Confusion/Supply Chain Attack via Unpinned GitHub Actions

**Description:**
1. Several GitHub Actions workflows within the project are configured to use third-party actions by referencing floating branch names, specifically `@master`, instead of pinning to fixed commit SHAs or tags. Examples include actions from repositories like `dsaltares/fetch-gh-release-asset`, `codota/replace-action`, `martinbeentjes/npm-get-version-action`, and others.
2. A threat actor gains control of one of these external GitHub Action repositories or manages to inject malicious commits into the `master` branch of these repositories. This compromise could occur through various means, such as compromising maintainer accounts or exploiting vulnerabilities in the action repository's infrastructure.
3. Once the action's `master` branch is compromised, the attacker modifies the action code to inject malicious code. This code could perform various malicious activities, such as exfiltrating data, injecting malware, or modifying build artifacts.
4. When the Tabnine project's workflow (e.g., `tag-ovsx.yml`, `alpha_release.yml`, `tag.yml`, `continues_integration.yml`, `package-enterprise.yml`, `bump_version.yml`) runs, it fetches and uses the compromised action from the `master` branch. Because the action is not pinned to a specific version, the workflow automatically pulls the latest code from the potentially compromised `master` branch.
5. The malicious code injected by the attacker is then executed as part of the Tabnine project's build process within the CI/CD pipeline. This execution occurs with the permissions granted to the GitHub Actions workflow, which can be substantial.
6. Depending on the nature of the injected malicious code, this could lead to various severe outcomes, including injecting malware directly into the Tabnine VS Code extension during the build process, altering release artifacts, or leaking sensitive internal secrets managed within the CI/CD environment.
7. If the extension is compromised, users who install or update to the compromised version from the marketplace will execute the malicious code on their local machines, potentially leading to widespread compromise of developer environments.

**Impact:**
Critical. Successful exploitation of this vulnerability could lead to a severe supply chain attack with widespread repercussions. Millions of developers using the Tabnine extension could be compromised. The attacker could gain persistent access to developer machines, steal source code, credentials, intellectual property, inject ransomware, or perform other malicious activities, leading to significant financial and reputational damage for Tabnine and its users. The integrity of the entire software delivery pipeline is at risk.

**Vulnerability Rank:** critical

**Currently implemented mitigations:**
Some core actions, such as `actions/checkout@v2` and `actions/setup-node@v3`, are versioned, indicating an awareness of versioning for actions. However, numerous custom or third-party actions are referenced using floating branch names like `@master` instead of fixed commit SHAs or specific tags.  The `dependabot.yml` file helps keep dependencies updated, but it does not mitigate the risk of using actions from the `master` branch.

**Missing mitigations:**
- **Pinning GitHub Actions to specific tags or commit SHAs:** The most critical missing mitigation is the consistent pinning of all GitHub Actions, especially third-party actions, to specific, immutable tags or commit SHAs instead of using floating branches like `master`. This ensures that workflows rely on known, trusted versions of actions and are immune to unintended or malicious changes on the `master` branch.
- **Regularly auditing used GitHub Actions and their dependencies:**  Implementing a process for regularly auditing the GitHub Actions used in workflows and their own dependencies would help identify and mitigate potential supply chain risks proactively.
- **Using tools like GitHub's Dependency Review:**  Leveraging tools like GitHub's Dependency Review feature to automatically check for known vulnerabilities in action dependencies can add an extra layer of security.
- **Consider using in-house actions or forking and vendoring critical actions:** For highly sensitive parts of the CI/CD pipeline, consider developing and maintaining in-house actions or forking and vendoring critical third-party actions. This provides greater control over the supply chain and reduces reliance on external repositories.
- **Automated dependency scanning and alerting mechanism:** Implementing an automated system to monitor changes in remote actions and alert on unexpected or suspicious modifications would provide an early warning system against potential supply chain attacks.

**Preconditions:**
- The CI/CD workflows must have network access to fetch GitHub Actions codebases from external repositories.
- A threat actor must be able to compromise one or more of the external GitHub Action repositories used in the workflows, specifically gaining the ability to modify the `master` branch or other branches referenced by floating tags. This could involve compromising maintainer accounts or exploiting vulnerabilities in the action repository's infrastructure.

**Source code analysis:**
- In multiple workflow files across the repository, including but not limited to `/code/.github/workflows/tag-ovsx.yml`, `/code/.github/workflows/alpha_release.yml`, `/code/.github/workflows/tag.yml`, `/code/.github/workflows/continues_integration.yml`, and `/code/.github/workflows/bump_version.yml`, various actions are used without specifying a version, or explicitly using `@master`, which defaults to the `master` branch.
- Examples from `/code/.github/workflows/tag-ovsx.yml`:
    ```yaml
    uses: dsaltares/fetch-gh-release-asset@master
    uses: codota/replace-action@v2 # While this one is versioned, others from codota are not.
    uses: actions/checkout@v2 # Versioned correctly
    ```
- Other instances across workflows include:
    - `uses: actions/setup-node@v3` (Versioned correctly)
    - `uses: actions/create-release@v1` (Versioned correctly)
    - `uses: actions/upload-release-asset@v1` (Versioned correctly)
    - `uses: rtCamp/action-slack-notify@v2` (Versioned correctly)
    - `uses: martinbeentjes/npm-get-version-action@master`
    - `uses: codota/github-action-get-latest-release@master`
    - `uses: codota/github-commit-timestamp-tagger@master`
    - `uses: codota/visual-regression@master`
    - `uses: codota/wait-action@master`
    - `uses: google-github-actions/auth@v1` (Versioned correctly)
    - `uses: google-github-actions/upload-cloud-storage@v1` (Versioned correctly)
    - `uses: codota/delete-tag-and-release@master`
    - `uses: codota/vsix-name-modifier` (No version specified, defaults to master)
    - `uses: usehaystack/jira-pr-link-action@v4` (Versioned correctly)

- **Visualization:**
  ```mermaid
  graph LR
      A[Tabnine Workflow] --> B{Fetch Action from GitHub};
      B --> C{dsaltares/fetch-gh-release-asset@master};
      C --> D{GitHub Master Branch};
      D -- Malicious Code Injection --> E[Compromised Action Code];
      E --> F[Execute in CI/CD Pipeline];
      F --> G{Potential Malware Injection into Extension};
      G --> H[Compromised Tabnine Extension];
      H --> I[Users Install Extension];
      I --> J[User Machine Compromised];
  ```

**Security test case:**
1. **(Important: Perform this test in a controlled, non-production environment or a dedicated test repository to avoid disrupting the production pipeline).**
2. **Fork the target GitHub Action repository:** Identify a vulnerable action used in Tabnine workflows that uses `@master` (e.g., `dsaltares/fetch-gh-release-asset`). Fork this repository to your personal GitHub account.
3. **Modify the action code in your forked repository:** In your forked repository, navigate to the `master` branch. Modify the action's main code file (e.g., `index.js` or `entrypoint.sh`) to include benign but clearly identifiable malicious code. For example, add a step to print a distinctive message to the workflow logs: `run: echo "Vulnerable Action TEST - Successfully injected code"`.
4. **Modify the Tabnine workflow:** In one of the Tabnine workflow files (e.g., `/code/.github/workflows/continues_integration.yml`), temporarily change the `uses` statement for the chosen action to point to your forked repository and the `master` branch. Replace `uses: dsaltares/fetch-gh-release-asset@master` with `uses: <your-github-username>/fetch-gh-release-asset@master`, substituting `<your-github-username>` with your GitHub username.
5. **Trigger the Tabnine workflow:** Trigger the modified Tabnine workflow. This could be done by pushing a commit to a branch in the Tabnine repository or manually triggering the workflow if possible.
6. **Monitor the workflow logs:** Go to the Actions tab in the Tabnine repository, select the triggered workflow run, and examine the logs for the step that uses the modified action.
7. **Verify successful code injection:** Look for the distinctive message you added to the forked action's code (e.g., "Vulnerable Action TEST - Successfully injected code") in the workflow logs. If you find this message, it confirms that your modified action code was executed as part of the Tabnine workflow, successfully demonstrating the supply chain vulnerability.
8. **Revert changes and clean up:** **Immediately after testing**, revert the changes you made to the Tabnine workflow file to use the original, unmodified action. Delete your forked action repository or make it private to prevent accidental or malicious use of your modified action in the future.
9. **Document and report:** Document the steps taken, the successful demonstration of the vulnerability, and the recommended mitigation (pinning actions to specific SHAs or tags) in a security report.


### 2. Insecure Secrets Handling in Workflow “tmp.yml”

**Description:**
1. The workflow defined in `/code/.github/workflows/tmp.yml` is designed to manage and upload configuration variables, including sensitive secrets, to Google Cloud Storage (GCS).
2. Within this workflow, several critical secrets (`GCS_RELEASE_KEY`, `INSTRUMENTATION_KEY`, `MODIFIER_PAT`, `OVSX_PAT`, `SLACK_RELEASES_CHANNEL_WEBHOOK_URL`, `SLACK_VALIDATE_MARKETPLACE_WEBHOOK`, and `VSCE_PAT`) are retrieved from GitHub Secrets.
3. These secrets are then written in plaintext to a file named `vscode-vars` using a series of `echo` commands and redirection (`>`, `>>`). Each secret is appended to this file in cleartext, one after another.
4. Subsequently, this plaintext file `vscode-vars`, containing all the sensitive secrets, is uploaded to a Google Cloud Storage bucket named “tabnine” using the `google-github-actions/upload-cloud-storage@v1` action.
5. Critically, this upload occurs without any encryption or obfuscation of the sensitive data within the `vscode-vars` file. The file is uploaded as plaintext.
6. If the destination Google Cloud Storage bucket “tabnine” is misconfigured, for example, if it inadvertently allows public read or list access due to incorrect access control settings, an external, unauthenticated attacker could potentially access and download the `vscode-vars` file.
7. Upon downloading the file, the attacker would gain access to all the secrets contained within in plaintext, including credentials for Google Cloud, Open VSX, Slack, and potentially other critical systems.

**Impact:**
Critical. Leakage of these highly sensitive secrets could have severe consequences. An attacker with access to these secrets could:
- Gain unauthorized access to Google Cloud resources associated with the `GCS_RELEASE_KEY` and `INSTRUMENTATION_KEY`, potentially leading to data breaches, resource manipulation, or service disruption.
- Compromise the Open VSX service using `OVSX_PAT`, potentially allowing for malicious modifications or takeovers of Tabnine's extension listings on Open VSX.
- Abuse Slack webhook URLs (`SLACK_RELEASES_CHANNEL_WEBHOOK_URL`, `SLACK_VALIDATE_MARKETPLACE_WEBHOOK`) to send misleading or malicious messages, potentially as part of a social engineering attack or to disrupt internal communications.
- Potentially misuse `MODIFIER_PAT` and `VSCE_PAT` (if these are sensitive authentication tokens for other services) to further compromise related systems or processes.
In essence, the attacker could gain significant control over Tabnine's infrastructure, release pipeline, and communication channels.

**Vulnerability Rank:** critical

**Currently implemented mitigations:**
The workflow utilizes GitHub Secrets to manage and pass the sensitive values during workflow execution, which provides a degree of protection during transmission within the GitHub Actions environment. The workflow also uses the official Google Cloud Storage upload action, which is generally a secure method for interacting with GCS when properly configured. However, these mitigations do not address the core issue of writing secrets to disk in plaintext and uploading them without encryption, nor do they verify the security of the destination bucket.

**Missing mitigations:**
- **Encryption or obfuscation of sensitive data before upload:** The most critical missing mitigation is the encryption or at least obfuscation of the `vscode-vars` file *before* it is written to disk and uploaded. This could be achieved using tools like `gpg`, `age`, or even simple symmetric encryption. Decryption would then need to occur within a secure environment after retrieval from GCS.
- **Enforcement of strict access controls on the target bucket:**  There is no explicit check within the workflow to verify or enforce that the target GCS bucket (“tabnine”) has strict access controls in place and is not publicly accessible.  Automated checks to confirm bucket permissions or using Identity and Access Management (IAM) policies to restrict access to the bucket to only authorized entities are necessary.
- **Secure secret management practices within workflows:**  Consider adopting more secure secret management practices within workflows in general, such as avoiding writing secrets to disk in plaintext whenever possible. Explore alternative methods like using environment variables directly within actions or utilizing secure secret stores if needed.
- **Auditing and monitoring of bucket access:** Implement regular auditing and monitoring of access to the “tabnine” GCS bucket to detect any unauthorized access attempts or misconfigurations that could lead to exposure.

**Preconditions:**
- The `tmp.yml` workflow must be triggered via `workflow_dispatch`. This is the intended trigger for this workflow, so this precondition is likely always met when the workflow is in use.
- The Google Cloud Storage bucket named “tabnine” must be misconfigured to allow public read or list access, or be accessible to unauthorized individuals or roles. This misconfiguration is the key vulnerability enabler.

**Source code analysis:**
- The workflow file `/code/.github/workflows/tmp.yml` contains the following sequence of commands:
    ```yaml
    - name: 📝 Prepare variables
      run: |
        echo ${{ secrets.GCS_RELEASE_KEY }} > vscode-vars
        echo ${{ secrets.INSTRUMENTATION_KEY }} >> vscode-vars
        echo ${{ secrets.MODIFIER_PAT }} >> vscode-vars
        echo ${{ secrets.OVSX_PAT }} >> vscode-vars
        echo ${{ secrets.SLACK_RELEASES_CHANNEL_WEBHOOK_URL }} >> vscode-vars
        echo ${{ secrets.SLACK_VALIDATE_MARKETPLACE_WEBHOOK }} >> vscode-vars
        echo ${{ secrets.VSCE_PAT }} >> vscode-vars
    ```
    This code block explicitly writes multiple sensitive secrets, obtained from GitHub Secrets, to the file `vscode-vars` in plaintext. The use of `>` overwrites the file initially, and `>>` appends to it for subsequent secrets.
- Immediately following this, the workflow uploads the plaintext file:
    ```yaml
    - name: ⬆️ Upload latest stable version to GCS
      uses: google-github-actions/upload-cloud-storage@v1
      with:
        path: vscode-vars
        destination: tabnine
        parent: false
        gzip: false
        headers: |-
          content-type: text/plain
    ```
    This step uses the `google-github-actions/upload-cloud-storage@v1` action to upload the `vscode-vars` file to the “tabnine” bucket.  Crucially, no encryption or access control enforcement is applied at this stage. The `content-type: text/plain` header further indicates that the file is treated as plaintext.

- **Visualization:**
  ```mermaid
  graph LR
      A[tmp.yml Workflow] --> B{Retrieve Secrets from GitHub Secrets};
      B --> C{Write Secrets to vscode-vars (Plaintext)};
      C --> D{Upload vscode-vars to GCS Bucket "tabnine"};
      D --> E{GCS Bucket "tabnine" (Potentially Misconfigured)};
      E -- Publicly Accessible --> F[Attacker Accesses Bucket];
      F --> G[Attacker Downloads vscode-vars];
      G --> H[Secrets Exposed in Plaintext];
  ```


**Security test case:**
1. **Review GCS bucket configuration:** Access the Google Cloud Console and navigate to the Storage section. Locate the bucket named “tabnine”. Review its permission settings. Specifically, check if the bucket allows public access (e.g., "publicly accessible" or "allUsers" with read or list permissions) or if it allows access to a broad range of authenticated users or service accounts that could be accessible to an attacker.
2. **Attempt to list bucket contents from an external network:** From a system outside of the Tabnine's internal network and without explicit Google Cloud authentication (simulating an unauthenticated external attacker), attempt to list the contents of the “tabnine” bucket. This can be done using the `gsutil ls gs://tabnine` command if you have the Google Cloud SDK installed, or by using online GCS bucket explorer tools if available (with caution, as using third-party tools for security testing may carry risks). If the bucket is publicly listable, the command or tool will return a list of objects in the bucket.
3. **Attempt to retrieve the `vscode-vars` file:** If the bucket is publicly listable, attempt to retrieve the `vscode-vars` file. Using `gsutil cp gs://tabnine/vscode-vars ./vscode-vars-test` (or a similar method), try to download the file to your local machine.
4. **Inspect the contents of `vscode-vars`:** Open the downloaded `vscode-vars-test` file with a text editor. Verify if the file contains the expected sensitive secret values in plaintext. Look for strings that resemble API keys, tokens, webhook URLs, or other credentials that were intended to be secrets.
5. **Verify secret exposure:** Confirm that the sensitive secret values are indeed exposed in plaintext within the downloaded file. This confirms the vulnerability.
6. **Document and report:** Document the steps taken, the successful retrieval of the `vscode-vars` file, the plaintext exposure of secrets, and the recommended mitigations (encryption, bucket access control hardening) in a security report.  **Important:** If you are able to access the bucket and download the secrets in a real environment, immediately report this to the Tabnine security team through their responsible disclosure channel, if available, before taking any further action. Avoid misusing the secrets or causing any harm to their systems.