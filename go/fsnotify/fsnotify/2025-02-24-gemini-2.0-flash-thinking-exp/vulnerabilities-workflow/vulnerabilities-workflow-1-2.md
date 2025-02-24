- **Vulnerability Name:**
  Symlink TOCTOU Race Vulnerability in Watcher Registration

- **Description:**
  The fsnotify library’s default behavior in its Add/AddWith methods automatically resolves (or “follows”) symbolic links. When a watch is added for a given path, the code uses functions such as os.Stat (in backends like fen) or calls the OS’s inotify API without the “don’t follow” flag (in the inotify backend). An attacker with write permissions in the watched directory may prepare a benign–looking symlink (e.g. “link.txt”) that initially points to a safe file. When the application (running with fsnotify) registers a watch on that symlink, the library resolves it and registers a watch on its target (say, “benign.txt”). However, immediately afterward the attacker can atomically replace or repoint the symlink so that it now points to a sensitive (or attacker‑controlled) file. Subsequent modifications to that sensitive file will then trigger events on the watcher, potentially causing the application to process data from a file it did not expect to watch.

  *Step‑by‑step trigger demonstration:*
  1. An application (or service) calls Add("link.txt") on a directory that an attacker can write to.
  2. Initially, “link.txt” is a symlink pointing to “benign.txt”. The backend (for example, in the Linux/inotify or Solaris/FEN code) calls os.Stat to resolve “link.txt” and then registers a watch on “benign.txt”.
  3. After the watch is registered—but before or during normal event processing—the attacker quickly replaces “link.txt” so that it points to “sensitive.txt” (or some other file that should not be watched).
  4. Later, when “sensitive.txt” is modified, the underlying OS delivers an event that is attributed to the watch registered for “benign.txt” (now effectively “sensitive.txt” from the standpoint of the symlink). The application then receives an event whose Name field corresponds to the sensitive file even though the watch was originally added on the symlink.

- **Impact:**
  Depending on how the application uses the event information, an attacker may be able to:
  • Cause the application to monitor files outside the intended scope (information disclosure).
  • Influence application logic that trusts the file path received in events (for example, by reading or acting on unintended file content).
  If the application blindly acts on events (for example, by auto‑processing a file it “sees”), the TOCTOU race can indirectly lead to unauthorized disclosure of sensitive information or even further compromise if downstream components assume the file is safe.

- **Vulnerability Rank:**
  High

- **Currently Implemented Mitigations:**
  • Some backends (for example, the FEN backend) include logic that distinguishes between explicitly watched directories and files and resolve symlinks only when explicitly requested.
  • A previous patch (v1.5.1) removed an “AddRaw” method intended to avoid following symlinks.
  • Documentation (in the README and FAQ) advises against watching individual files and warns about limitations with symlinks.

- **Missing Mitigations:**
  • **No default “don’t follow” option:** By default the Add/AddWith methods do not set an option (such as WithNoFollow) so that symlinks are preserved in user‑provided form. Instead, they use the OS’s default behavior (which follows links).
  • **Lack of atomicity:** There is no protection against a TOCTOU race after the file’s symlink has been resolved. Even if the function correctly calls os.Stat or adds a watch, there is a window between (a) resolving the symlink and (b) processing incoming events when the symlink target may change.
  • **Insufficient caller guidance:** Although documentation mentions that watching individual files can be problematic, there is no prominent security note to encourage users to use WithNoFollow (which inserts the IN_DONT_FOLLOW flag on Linux) or other OS-specific measures to explicitly guard against symlink races.

- **Preconditions:**
  • The directory where the watch is added must be writable by an attacker.
  • The application (or service) must add a watch on a path that is a symbolic link without explicitly disabling symlink following (i.e. not using a WithNoFollow option).
  • The attacker must be able to atomically change the symlink’s target after the watch is registered.

- **Source Code Analysis:**
  • In the Linux/inotify backend (see `backend_inotify.go`), the function `AddWith` calls a helper `w.add(path, with, false)`.
  • In `w.add(…)`, if the WithNoFollow option is not provided (the default), no flag is added to prevent symlink resolution (e.g. the `unix.IN_DONT_FOLLOW` flag is omitted). Consequently, when `unix.InotifyAddWatch` is executed, the OS follows the symlink and registers a watch on the target file.
  • In the Solaris/FEN backend (`backend_fen.go`), the code calls `os.Stat(name)` without using `os.Lstat`. Since os.Stat follows symlinks, a similar race exists here.
  • The window between the check (symlink resolution) and the actual event processing leaves an opportunity for the symlink target to be swapped—making it a classic TOCTOU vulnerability.
  *Visualization of the race:*
  1. Application invokes `Add("link.txt")`.
  2. `os.Stat("link.txt")` returns file information for “benign.txt”.
  3. The watch is registered on “benign.txt”.
  4. The attacker quickly replaces “link.txt” to point to “sensitive.txt”.
  5. Changes on “sensitive.txt” now trigger notifications though the watch was intended for “benign.txt”.

- **Security Test Case:**
  *Test Objective:* Demonstrate that a watch added on a symlink can be “tricked” into monitoring an unintended file when the symlink’s target is changed after registration.
  1. **Test Setup:**
     - Create a temporary directory (e.g. `/tmp/testwatch`).
     - Create a benign file (e.g. `/tmp/testwatch/benign.txt`) with innocuous content.
     - Create a sensitive file (e.g. `/tmp/testwatch/sensitive.txt`) containing secret data.
     - Create a symlink (`/tmp/testwatch/link.txt`) pointing to `benign.txt`.
     - Using fsnotify (without specifying WithNoFollow), add a watch on the symlink `"link.txt"` (for example, via:
       `w, _ := fsnotify.NewWatcher()`
       `w.Add("link.txt")`).
  2. **Attack Simulation:**
     - After the watch is in place, have an external process (or a goroutine running with write permissions) change the symlink so that `/tmp/testwatch/link.txt` now points to `sensitive.txt`.
     - Make a change (for example, overwrite or append data) to `sensitive.txt`.
  3. **Observation:**
     - The test harness reads from the fsnotify.Events channel and checks the event’s Name field.
     - If the event is reported with a path corresponding to `sensitive.txt` (or the resolved canonical path of `sensitive.txt`), then the test has succeeded in demonstrating the TOCTOU exploitation.
  4. **Expected Result:**
     - The test should capture an event (typically “Write” or “Create”) whose Name is the sensitive file rather than the originally intended benign file, confirming that the TOCTOU window was exploitable.