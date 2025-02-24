- **Vulnerability Name:** Potential BREACH Side–Channel Vulnerability in Default gzhttp Compression
  **Description:**
  - When using the default configuration, the gzhttp compression middleware produces deterministic compressed outputs.
  - If an HTTP response intermingles fixed secret values (such as session tokens) with attacker–controlled input (for example, values coming from query parameters or form input), identical compression behavior may be observed.
  - An external attacker can repeatedly request the same resource, varying the attacker–controlled parts, and analyze subtle changes (for example, via the Content–Length header) that correlate with the secret data.
  **Impact:**
  - An attacker may deduce sensitive information (such as CSRF or session tokens), which could result in session hijacking or unauthorized actions performed on behalf of a legitimate user.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The gzhttp package includes an optional random–padding (jitter) mechanism designed to obfuscate these compression–size variations.
  - However, this mechanism is disabled by default and must be explicitly enabled by developers.
  **Missing Mitigations:**
  - The default configuration does not enable the random–padding feature.
  - There is no automatic detection mechanism for cases where sensitive fixed data is combined with attacker–controlled input.
  **Preconditions:**
  - The application is publicly exposed and uses the default gzhttp configuration.
  - HTTP responses include both fixed secret values and attacker–influenceable content.
  **Source Code Analysis:**
  - A review of the gzhttp middleware reveals that with random jitter disabled, identical input data produces identical compression output.
  - Although a helper function exists to inject random–padding, it is not invoked unless the middleware is explicitly configured to do so.
  **Security Test Case:**
  1. **Setup:** Deploy the application with the default gzhttp configuration.
  2. **Endpoint Configuration:** Implement an HTTP endpoint that returns a response mixing a fixed secret (e.g. a session token) with attacker–controlled input (e.g. echoing a query parameter).
  3. **Attack Simulation:** Use a script to send numerous requests that vary only the attacker–controlled input while recording the Content–Length header (or overall response size).
  4. **Observation:** Determine if variations in the response size correlate with the attacker’s input, indicating that secret data might be leaking via compression–side channel.
  5. **Mitigation Verification:** Reconfigure the middleware to enable random–padding and verify that this correlation is no longer observable.

- **Vulnerability Name:** Insecure ZIP Archive Path Handling (Zip Slip) Vulnerability Including Inconsistent File Type Enforcement
  **Description:**
  - The archive/zip package accepts ZIP archives that may contain file entries whose names include relative directory–traversal sequences (e.g. "../evil.txt") or even absolute paths.
  - A secure file–path validation check exists and is activated only when the environment variable `GODEBUG` is set to `"zipinsecurepath=0"`. By default (or when this flag is not set), dangerous file names are accepted.
  - Moreover, while the higher–level API (e.g. the AddFS function) enforces safe file type checks—rejecting entries that represent symbolic links or device files (as verified in tests such as `TestIssue61875`)—lower–level APIs like `CreateHeader` do not apply such checks.
  - Thus, if an application uses these lower–level APIs to process ZIP archives from untrusted sources, an attacker can craft a malicious ZIP file with entries having directory–traversal paths or malicious symlink/device file attributes that bypass sanitization.
  **Impact:**
  - An attacker could cause directory traversal during file extraction, leading to arbitrary file creation or modification outside the intended destination.
  - Such manipulation may allow an attacker to overwrite critical system or application files and, in a worst–case scenario (especially when combined with other vulnerabilities), could pave the way for arbitrary code execution or complete compromise of system integrity.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - During ZIP reader initialization (in, for example, `zip/reader.go`), a check verifies whether file names are “local” (using `filepath.IsLocal`) and rejects names containing backslashes—but this check is only activated when `GODEBUG` is explicitly set to `"zipinsecurepath=0"`.
  - When extracting files via the `fs.FS` interface (using the `Open` method), a helper function (such as `toValidName`) sanitizes the filename so that dangerous components (e.g. "../") are stripped.
  - In addition, tests (e.g. `TestIssue61875`) show that when using the `AddFS` API, the ZIP package enforces safe processing by rejecting dangerous file types (such as symlink and device file entries).
  **Missing Mitigations:**
  - The secure–path check is opt–in rather than enabled by default—if `GODEBUG` is not set to `"zipinsecurepath=0"`, then no validation occurs.
  - There is no uniform enforcement across all APIs; lower–level APIs (e.g. `CreateHeader` or manual ZIP entry processing) do not automatically reject dangerous file names or enforce safe file–type checks (leaving the decision up to the developer).
  - The inconsistent handling means that even though the AddFS function protects against dangerous file types, developers using other APIs may inadvertently process malicious entries.
  **Preconditions:**
  - The application accepts ZIP archives from untrusted external sources.
  - The environment variable `GODEBUG` is unset or not set to `"zipinsecurepath=0"`, or the developer uses lower–level APIs which bypass the secure validation.
  - The application subsequently uses the raw file header values (which may contain malicious names) when extracting files to disk.
  **Source Code Analysis:**
  - In `zip/struct.go` the file entries are represented via a `FileHeader` whose `Name` field is meant to be a relative path, but there is no runtime enforcement within this method.
  - The ZIP reader’s initialization code only performs the secure check when `GODEBUG` is set appropriately; otherwise, malicious names (containing "../" or even absolute paths) are allowed to pass through.
  - Test cases (e.g. `TestIssue61875`) reveal that while the AddFS API rejects ZIP entries with dangerous file modes (such as symlinks and device files), similar checks are absent when using lower–level APIs like `CreateHeader`, leaving a gap for potential exploitation.
  **Security Test Case:**
  1. **Setup:**
     - Craft a malicious ZIP archive that contains at least one file entry with a traversal path (e.g. "../evil.txt") and optionally an entry with a symlink (for example, an entry with name "symlink" whose content is "../link/target").
  2. **Baseline Test (Insecure Behavior):**
     - Ensure that the environment variable `GODEBUG` is unset (or not set to `"zipinsecurepath=0"`).
     - Process the ZIP archive using a lower–level API (for example, by invoking `CreateHeader`) to simulate extraction from untrusted input.
     - Inspect the resulting `FileHeader`—observe that the file name still contains the insecure "../" component and that no file–type enforcement takes place.
  3. **Secure Behavior Verification:**
     - Set the environment variable `GODEBUG` to `"zipinsecurepath=0"` and reprocess the ZIP archive; confirm that the initialization detects the insecure file name and returns an error (such as `ErrInsecurePath`).
     - Alternatively, use the AddFS API and verify that it rejects dangerous file types (evidenced by an error when processing symlink or device file entries).
  4. **Conclusion:**
     - Demonstrate that without explicit enabling of secure path checks or the usage of safe APIs, an attacker can supply a ZIP archive with malicious entries, thereby enabling a Zip Slip attack during file extraction.