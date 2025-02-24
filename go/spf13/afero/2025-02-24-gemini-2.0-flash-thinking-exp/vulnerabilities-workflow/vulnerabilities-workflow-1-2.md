- **Vulnerability Name**: Predictable Temporary File Name Generation  
  **Description**:  
  The functions `TempFile` and `TempDir` (located in `/code/util.go`) derive a “random” suffix using an LCG (linear congruential generator) seeded with the current time and process ID. Because this method is not cryptographically secure, an external attacker who can write to the system’s temporary directory may predict the temporary file or directory name before it is created. By pre-creating (or pre-linking) the file under that name, the attacker can force file–hijacking or race–conditions.  
  **Impact**:  
  An attacker who successfully predicts the temporary file name may hijack sensitive file contents, force failures in file creation, or even influence application logic when temporary files are used in security‐sensitive contexts.  
  **Vulnerability Rank**: High  
  **Currently Implemented Mitigations**:  
  - The code uses an exclusive creation flag (`os.O_CREATE|os.O_EXCL`) when opening temporary files.  
  **Missing Mitigations**:  
  - A cryptographically secure random number generator is not used to produce the temporary suffix.  
  - No atomic “check‐and‐create” mechanism is employed to hide the predictable randomness.  
  **Preconditions**:  
  - The attacker must be able to write to (or influence) the temporary directory (typically the one returned by `os.TempDir()`).  
  - The application uses these functions in a multiuser or publicly accessible environment.  
  **Source Code Analysis**:  
  - In `/code/util.go`, the file–creation loop extracts a prefix and suffix from a pattern and then composes the file name by appending the result of `nextRandom()`.  
  - The helper function `nextRandom()` relies on a linear congruential update that makes future values predictable from the current seed.  
  - Because the flag `os.O_CREATE|os.O_EXCL` only prevents overwrite of an already–existing file (and cannot stop an attacker from pre–creating the file), the predictable name leads to a security risk.  
  **Security Test Case**:  
  1. In an environment where the temporary directory is writable by an attacker, call `TempFile` (or `TempDir`) with a known naming pattern.  
  2. Record the current system time and process ID (or otherwise replicate the known seed conditions).  
  3. Compute the expected “random” suffix using the same LCG algorithm as in `nextRandom()`.  
  4. Pre-create a file (or symbolic link) at the computed temporary name.  
  5. Invoke the application function that creates a temporary file/directory and verify that file creation fails or that the new file’s content/path can be controlled by the attacker.  
  6. Confirm that the vulnerability is exploitable by repeating the test under race conditions.

---

- **Vulnerability Name**: Time‐of‐Check-to-Time‐of-Use (TOCTOU) Race in SafeWriteReader  
  **Description**:  
  The function `SafeWriteReader` (in `/code/util.go`) first checks for file existence by calling `Exists()` and then creates the file via `fs.Create()` if no file is found. This two–step “check then act” process is not atomic. An attacker who can write to the target directory may create the file (or substitute a symbolic link) between the check and the creation call. The safe write operation can thus be hijacked or misdirected.  
  **Impact**:  
  An attacker may force the safe write operation to write data into a file under attacker control or simply cause the operation to fail. In scenarios where the data is sensitive or the file is accessed by another privileged process, this may lead to data corruption or unauthorized data injection.  
  **Vulnerability Rank**: High  
  **Currently Implemented Mitigations**:  
  - The code uses an explicit existence check (`Exists(fs, path)`) before file creation; however, the check and creation remain separate.  
  **Missing Mitigations**:  
  - No atomic “create‐if–not–exists” operation (or exclusive file–creation flag) is used to remove the race window.  
  - There is no additional synchronization between the check and the create steps.  
  **Preconditions**:  
  - The destination directory must be writable by an attacker.  
  - The attacker must be able to perform a file creation (or symlink insertion) between the existence check and the subsequent write operation.  
  **Source Code Analysis**:  
  - In `/code/util.go`, `SafeWriteReader` calls `Exists()` to verify that a file does not exist.  
  - If the file is absent, it then continues to call `fs.Create(path)` and writes data.  
  - The lack of atomicity between checking and creation permits an attacker to intervene and create the file (or a symlink) in the interim, thus hijacking or disrupting the write operation.  
  **Security Test Case**:  
  1. Set up a controlled file system instance where the attacker can simulate concurrent file creation.  
  2. Begin the invocation of `SafeWriteReader` with a given file path and a known input stream.  
  3. Immediately after the existence check, initiate a parallel process (or goroutine) that creates the file at the same path.  
  4. Observe that `SafeWriteReader` either fails with an “already exists” error or writes data to a file controlled by the attacker.  
  5. Repeat the test several times to demonstrate the race condition.

---

- **Vulnerability Name**: TOCTOU Race in GCS File Creation via OpenFile  
  **Description**:  
  In the GCS–backed filesystem implementation (in `/code/gcsfs/fs.go`), the `OpenFile` method handles the `os.O_CREATE` flag by first calling `file.Stat()` to check whether an object exists and then, if no file is found, proceeds to create the file by calling `file.WriteString("")`. Because these are executed as two separate operations (a “check‐then‐act” sequence), an attacker who is able to race the file creation may pre–create an object (or a malicious symbolic link) with the same name in the time gap between the existence check and the write.  
  **Impact**:  
  An attacker exploiting this race condition could influence the outcome of the file creation. This may lead to the file being created under the attacker’s control or result in unexpected file content – ultimately affecting the integrity and security of the data stored in the GCS bucket.  
  **Vulnerability Rank**: High  
  **Currently Implemented Mitigations**:  
  - The code in `OpenFile` calls `file.Stat()` before attempting creation and checks for existence; however, it does not enforce an atomic check‐and‐create operation.  
  **Missing Mitigations**:  
  - An atomic “create–if–not–exists” operation using GCS’s pre–conditions or similar measures is missing.  
  - There is no synchronization to bridge the gap between the separate stat and write operations.  
  **Preconditions**:  
  - The attacker must have—or be able to simulate having—write access to the target GCS bucket (or be in a position to trigger a race condition by concurrently creating objects).  
  - The file creation request must be susceptible to interference by a concurrent process.  
  **Source Code Analysis**:  
  - Within `/code/gcsfs/fs.go`, the relevant code begins by normalizing the file name and then (if `flag & os.O_CREATE` is set) performing a call to `file.Stat()`.  
  - If `Stat()` returns no error (meaning the object exists), the function returns an error (`syscall.EPERM`).  
  - Otherwise, the code proceeds with `file.WriteString("")` to create an empty object.  
  - The non–atomic nature of the two–step process (first checking with `Stat()` and then writing) introduces a window in which an attacker can act.  
  **Security Test Case**:  
  1. In a test setup (for example, using a mocked or staging GCS bucket), invoke `OpenFile` with the `os.O_CREATE` flag for a chosen object name.  
  2. Immediately after the `Stat()` check but before the `WriteString("")` call has been completed, simulate an attacker’s concurrent process that creates an object (or a symlink) with the same name in the bucket.  
  3. Observe that the subsequent file creation logic does not reliably prevent the creation (or overwriting) of the object by the attacker.  
  4. Verify that the function either returns an unexpected successful creation (allowing attacker–controlled file content) or returns an error that indicates the race condition was exposed.  
  5. Repeat this test multiple times to confirm the intermittent nature of the race condition.