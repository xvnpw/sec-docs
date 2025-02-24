## Vulnerability List for klauspost/compress Project

### Vulnerability: Random Jitter Padding Predictability

* Description:
    The `RandomJitter` option in `gzhttp` is intended to add padding to compressed responses to obfuscate the actual compressed size, acting as a mitigation against certain types of information leaks, such as CRIME or BREACH attacks. However, the current implementation uses a predictable seed based on a CRC32 or SHA256 checksum of the initial part of the response body if `jitterBuffer` is greater than 0, or a standard `rand.Reader` if `jitterBuffer` is 0. When `jitterBuffer` is used, this makes the padding predictable if an attacker can control or observe the beginning of the response body.

    Steps to trigger the vulnerability:
    1. An attacker needs to understand that the server is using `gzhttp` with `NewWrapper` and the `RandomJitter` option enabled with `jitterBuffer` > 0.
    2. The attacker crafts a request that results in a predictable initial response body content up to `jitterBuffer` size.
    3. The server calculates the CRC32 or SHA256 of this initial part and uses it as a seed for random padding generation.
    4. Since the initial part of the response and the algorithm are known, the attacker can predict the padding length and content added by `RandomJitter`.

* Impact:
    The predictability of the padding undermines the intended security benefit of `RandomJitter`. An attacker might still be able to infer information about the uncompressed content length or other sensitive data despite the padding, especially in scenarios where the initial part of the response is somewhat controllable or predictable. This reduces the effectiveness of `RandomJitter` as a countermeasure against compression-ratio side-channel attacks.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    The `RandomJitter` option itself is intended as a mitigation, but the seed generation method is flawed when `jitterBuffer` > 0, making the padding predictable.

* Missing Mitigations:
    The seed for random padding generation should not depend on a predictable part of the response body when `jitterBuffer` > 0. A cryptographically secure random number generator should be used independently of the response content, or at least the seed should be derived from a source not directly influenced or observable by the attacker. For `jitterBuffer` > 0, a better approach would be to use a combination of a cryptographically secure random seed and the content hash, ensuring that even if the content is somewhat predictable, the final padding remains unpredictable to an external observer. For `jitterBuffer` == 0, `rand.Reader` is used, which is acceptable.

* Preconditions:
    1. The server-side application uses `gzhttp` with `NewWrapper` and the `RandomJitter` option is enabled with `jitterBuffer` > 0.
    2. The attacker has some knowledge or can make assumptions about the initial content of the HTTP response (up to `jitterBuffer` size).

* Source Code Analysis:
    In `compress.go`, within the `startGzip` function:
    ```go
    if len(w.randomJitter) > 0 {
        var jitRNG uint32
        if w.jitterBuffer > 0 {
            if w.sha256Jitter {
                h := sha256.New()
                h.Write(w.buf)
                // Use only up to "w.jitterBuffer", otherwise the output depends on write sizes.
                if len(remain) > 0 && len(w.buf) < w.jitterBuffer {
                    remain := remain
                    if len(remain)+len(w.buf) > w.jitterBuffer {
                        remain = remain[:w.jitterBuffer-len(w.buf)]
                    }
                    h.Write(remain)
                }
                var tmp [sha256.Size]byte
                jitRNG = binary.LittleEndian.Uint32(h.Sum(tmp[:0]))
            } else {
                h := crc32.Update(0, castagnoliTable, w.buf)
                // Use only up to "w.jitterBuffer", otherwise the output depends on write sizes.
                if len(remain) > 0 && len(w.buf) < w.jitterBuffer {
                    remain := remain
                    if len(remain)+len(w.buf) > w.jitterBuffer {
                        remain = remain[:w.jitterBuffer-len(w.buf)]
                    }
                    h = crc32.Update(h, castagnoliTable, remain)
                }
                jitRNG = bits.RotateLeft32(h, 19) ^ 0xab0755de
            }
        } else {
            // Get from rand.Reader
            var tmp [4]byte
            _, err := rand.Read(tmp[:])
            if err != nil {
                return fmt.Errorf("gzhttp: %w", err)
            }
            jitRNG = binary.LittleEndian.Uint32(tmp[:])
        }
        jit := w.randomJitter[:1+jitRNG%uint32(len(w.randomJitter)-1)]
        w.gw.(writer.GzipWriterExt).SetHeader(writer.Header{Comment: jit})
    }
    ```
    - When `w.jitterBuffer > 0`, the `jitRNG` is derived from `crc32.Update` or `sha256.New` based on `w.buf` and potentially `remain` (initial part of the response body). This makes the seed predictable if `w.buf` and `remain` are predictable.
    - When `w.jitterBuffer == 0`, `jitRNG` is derived from `rand.Reader`, which is cryptographically secure and not predictable based on response content.

* Security Test Case:
    1. Set up a test server using `gzhttp.NewWrapper` with `RandomJitter(256, 1024, false)` option and a handler that returns a predictable initial response body (e.g., "PREDICTABLE_PREFIX" + random string).
    2. Make two requests to the server that generate the same predictable prefix in the response body.
    3. Capture the compressed responses for both requests.
    4. Decompress the responses and extract the gzip header comment, which contains the jitter padding.
    5. Compare the jitter padding from both responses. If the vulnerability exists, the jitter padding will be the same for both responses because the predictable prefix leads to the same seed.
    6. If the jitter padding is identical, the test case proves the predictability of the padding and thus the vulnerability.

### Vulnerability: Potential Integer Overflow in Index Loading

* Description:
    In the `Index.Load` function within `index.go`, there are several places where integer overflows could potentially occur when reading varint-encoded values, especially for `entries`, `uOff`, and `cOff`. While the code includes checks like `v < 0` and `v > maxIndexEntries`, these might not be sufficient to prevent all forms of integer overflows, especially in edge cases or on 32-bit systems. If an attacker can manipulate the index data to cause an integer overflow during loading, it could lead to unexpected behavior, incorrect offset calculations, or potentially memory corruption if these values are used as sizes or offsets in subsequent operations.

    Steps to trigger the vulnerability:
    1. An attacker needs to provide a crafted S2 index to be loaded by the `Index.Load` function. This could be achieved if the index is loaded from an external source controlled by the attacker, or if there is a vulnerability allowing modification of existing index data.
    2. The attacker crafts the index data in a way that when varint-decoded, certain values like `entries`, `uOff`, or `cOff` result in integer overflows. For example, providing a very large varint value for the number of entries or offsets could trigger an overflow.
    3. The `Index.Load` function processes this crafted data, and the integer overflow occurs.
    4. Depending on how the overflowed value is used, it could lead to various consequences, such as incorrect index structure, out-of-bounds access when using the index, or other unexpected behavior.

* Impact:
    Integer overflows in index loading could lead to unpredictable behavior, incorrect offset lookups, and potentially memory safety issues if overflowed values are used in memory operations. This could undermine the integrity and reliability of the index functionality and potentially the security of applications relying on it. While direct memory corruption is not guaranteed, the potential for incorrect behavior and data processing makes this a high-rank vulnerability.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    The code includes checks like `v < 0`, `v > maxIndexEntries`, and `uOff <= prev` during index loading, which provide some level of input validation. However, these checks may not fully prevent integer overflows, especially in edge cases or on different architectures.

* Missing Mitigations:
    More robust integer overflow checks should be implemented during varint decoding in `Index.Load`. Specifically, when reading `entries`, `uOff`, and `cOff`, the code should explicitly check for potential overflows before casting to `int` or `int64` or performing arithmetic operations. Using libraries or built-in functions that provide overflow detection during arithmetic operations would be beneficial. For example, using `math/bits.Add64` to check for overflow during addition of offsets. Input validation should be strengthened to reject indices with excessively large values that are likely to cause overflows.

* Preconditions:
    1. The application loads an S2 index using the `Index.Load` function.
    2. The attacker can provide or influence the content of the index data being loaded.

* Source Code Analysis:
    In `index.go`, within the `Index.Load` function, multiple `binary.Varint` calls are made to read index metadata and offset values.

    ```go
    func (i *Index) Load(b []byte) ([]byte, error) {
        // ...
        var entries int
        if v, n := binary.Varint(b); n <= 0 { // Reading 'entries'
            return b, ErrCorrupt
        } else {
            if v < 0 || v > maxIndexEntries { // Check, but overflow before this?
                return b, ErrCorrupt
            }
            entries = int(v) // Potential overflow during cast if v is very large
            b = b[n:]
        }
        // ...
        for idx := range i.info {
            var uOff int64
            if hasUncompressed != 0 {
                // Load delta
                if v, n := binary.Varint(b); n <= 0 { // Reading 'uOff' delta
                    return b, ErrCorrupt
                } else {
                    uOff = v // Potential overflow if v is very large
                    b = b[n:]
                }
            }

            if idx > 0 {
                prev := i.info[idx-1].uncompressedOffset
                uOff += prev + (i.estBlockUncomp) // Potential overflow during addition
                if uOff <= prev { // Check after addition, but overflow might have happened
                    return b, ErrCorrupt
                }
            }
            if uOff < 0 { // Check after addition, but overflow might have happened
                return b, ErrCorrupt
            }
            i.info[idx].uncompressedOffset = uOff
        }

        // ... similar pattern for cOff ...
    }
    ```
    - The code reads varint values for `entries`, `uOff`, and `cOff` without explicit checks for integer overflows *before* casting to `int` or `int64` or performing arithmetic operations.
    - The checks `v < 0`, `v > maxIndexEntries`, and `uOff <= prev` are performed *after* potential overflows might have already occurred during decoding or arithmetic.
    - On 32-bit systems or with sufficiently large crafted varint inputs, these operations could wrap around, leading to incorrect values being used for index metadata or offsets.

* Security Test Case:
    1. Craft a malicious S2 index binary. Create a program that generates a valid S2 index structure but inserts a very large varint value for the "entries" field, close to the maximum value for a 64-bit integer.
    2. Prepare a test application that loads this crafted index using `Index.Load`.
    3. Run the test application with the crafted index.
    4. Observe the behavior of the application. If the application exhibits unexpected behavior, crashes, or produces incorrect results when using the loaded index, it indicates a potential integer overflow vulnerability.
    5. Specifically, try to trigger a `Find` operation after loading the crafted index and check if it leads to out-of-bounds access or incorrect offset results due to the overflowed `entries` value.
    6. Repeat the test by crafting large varint values for `uOff` and `cOff` deltas to see if overflows in offset calculations can be triggered.
    7. Run these tests on both 64-bit and 32-bit architectures to confirm the vulnerability across different platforms.

### Vulnerability: Potential Path Traversal in `filepathx.Glob` and `Globs.Expand`

* Description:
    The `filepathx.Glob` and `Globs.Expand` functions in `filepathx.go` are designed to handle glob patterns, including double-star (`**`) for recursive directory traversal. While the code uses `filepath.Walk` to traverse directories, it doesn't explicitly sanitize or validate the paths returned by `filepath.Glob` or during the walk. If a malicious pattern is crafted, it might be possible to bypass intended directory boundaries and access files outside the intended scope, leading to a path traversal vulnerability. This is especially concerning if `filepathx.Glob` is used in contexts where user-provided input is directly used as a glob pattern.

    Steps to trigger the vulnerability:
    1. An attacker needs to control or influence the glob pattern passed to `filepathx.Glob` or `Globs.Expand`. This could occur if the application uses user input to construct file paths or glob patterns.
    2. The attacker crafts a malicious glob pattern that includes path traversal sequences like `..` (e.g., `testdir/**/../../../sensitive_file`).
    3. `filepathx.Glob` or `Globs.Expand` processes this pattern.
    4. Due to the lack of explicit path sanitization, `filepath.Walk` might traverse directories outside the intended base directory, and `filepath.Glob` might match files outside the intended scope if the underlying OS and filesystem allow path traversal through symlinks or other mechanisms.
    5. The application might then perform operations (e.g., read, compress, decompress) on these files outside the intended scope, leading to unauthorized file access.

* Impact:
    A path traversal vulnerability could allow an attacker to access sensitive files or directories that should not be accessible. This could lead to information disclosure, unauthorized modification of files, or other security breaches, depending on how the application uses the files matched by the glob pattern. The impact is high because it allows bypassing intended access controls and potentially reading arbitrary files on the system if the application has sufficient permissions.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    The code uses standard Go functions like `filepath.Glob` and `filepath.Walk`, which provide some level of path handling safety. However, these functions alone do not prevent path traversal if the input pattern itself is malicious. There are no explicit sanitization or validation steps in `filepathx.Glob` or `Globs.Expand` to prevent path traversal sequences.

* Missing Mitigations:
    Input validation and sanitization should be implemented in `filepathx.Glob` and `Globs.Expand`. Before processing the glob pattern or the paths returned by `filepath.Glob` and `filepath.Walk`, the code should:
    1. Validate the glob pattern to reject patterns containing suspicious sequences like `..`. A regular expression or custom parsing logic could be used to detect and reject such patterns.
    2. After getting the matched paths, canonicalize them using `filepath.Clean` and verify that they are still within the intended base directory. This can be done by resolving both the base directory and the matched path to their absolute forms and checking if the matched path is a prefix of the base directory.
    3. Consider using chroot or similar sandboxing techniques if the application needs to process files from untrusted sources, to further limit the impact of path traversal vulnerabilities.

* Preconditions:
    1. The application uses `filepathx.Glob` or `Globs.Expand` to process file paths.
    2. The glob pattern used in `filepathx.Glob` or `Globs.Expand` is derived from user input or an untrusted source.

* Source Code Analysis:
    In `filepathx.go`, the `Glob` and `Expand` functions use `filepath.Glob` and `filepath.Walk` without additional path sanitization.

    ```go
    // Glob adds double-star support to the core path/filepath Glob function.
    func Glob(pattern string) ([]string, error) {
        if !strings.Contains(pattern, "**") {
            // passthru to core package if no double-star
            return filepath.Glob(pattern)
        }
        return Globs(strings.Split(pattern, "**")).Expand()
    }

    // Expand finds matches for the provided Globs.
    func (globs Globs) Expand() ([]string, error) ([]string, error) {
        var matches = []string{""} // accumulate here
        for _, glob := range globs {
            var hits []string
            var hitMap = map[string]bool{}
            for _, match := range matches {
                paths, err := filepath.Glob(match + glob) // Potentially vulnerable call
                if err != nil {
                    return nil, err
                }
                for _, path := range paths {
                    err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error { // Potentially vulnerable walk
                        if err != nil {
                            return err
                        }
                        // save deduped match from current iteration
                        if _, ok := hitMap[path]; !ok {
                            hits = append(hits, path)
                            hitMap[path] = true
                        }
                        return nil
                    })
                    if err != nil {
                        return nil, err
                    }
                }
            }
            matches = hits
        }
        return matches, nil
    }
    ```
    - The code directly uses `filepath.Glob(match + glob)` and `filepath.Walk(path, ...)` which can be vulnerable to path traversal if `glob` or `match` contains malicious sequences.
    - There are no checks to ensure that the matched paths stay within the intended directory or to sanitize the input glob patterns.

* Security Test Case:
    1. Create a test directory `testdir` and within it, create a subdirectory `subdir`. Inside `testdir`, create a file `safe_file.txt`. Outside `testdir` (e.g., in the temporary directory), create a sensitive file `sensitive_file.txt`.
    2. Write a test program that uses `filepathx.Glob` to find files based on a user-provided pattern, and then attempts to read the content of the matched files.
    3. Provide the test program with a malicious glob pattern like `testdir/**/../../../sensitive_file.txt`.
    4. Run the test program. If the vulnerability exists, the program will be able to access and potentially read the content of `sensitive_file.txt` outside the `testdir` directory, demonstrating path traversal.
    5. Check if the program outputs the content of `sensitive_file.txt` or if it throws an error indicating that it could not access the file due to path restrictions. If it reads the sensitive file, the test case is successful in demonstrating the path traversal vulnerability.

### Vulnerability: Potential Buffer Overflow in FSE Decompression Tables

* Description:
    In `fse/decompress.go` and `zstd/fse_decoder.go`, the `readNCount` function reads the symbol distribution from the input stream to construct decoding tables. There are checks to prevent excessively large `tableLog` and `symbolLen` values. However, if a crafted input provides a large `tableLog` value close to `tablelogAbsoluteMax` (9 in `zstd/fse_decoder.go` and implicitly 15 in `fse/decompress.go`) and a large number of symbols, the allocated decoding tables (`s.decTable` in `fse/decompress.go` and `s.dt` in `zstd/fse_decoder.go`) might become very large (up to 2^tablelogAbsoluteMax entries). If the subsequent decompression process attempts to access entries beyond the allocated size based on corrupted state or incorrect tableLog, it could lead to a buffer overflow read. This is especially relevant if the `DecompressLimit` is not properly enforced or bypassed.

    Steps to trigger the vulnerability:
    1. An attacker crafts a malicious FSE compressed stream with a `tableLog` value close to `tablelogAbsoluteMax` and a large `symbolLen`.
    2. The `readNCount` function in `fse/decompress.go` or `zstd/fse_decoder.go` reads the header and allocates a potentially large decoding table (e.g., `s.decTable` of size 2^tableLog).
    3. During the `decompress` function, due to corrupted or crafted input data following the header, the decoder state might transition to an invalid state index that is outside the bounds of the allocated `s.decTable`.
    4. When `s.decTable[state]` is accessed in `decoder.next` or `decoder.nextFast`, it results in an out-of-bounds read, potentially leading to a crash or information disclosure.

* Impact:
    A buffer overflow read in FSE decompression tables could lead to a crash, denial of service, or potentially information disclosure if sensitive memory regions are accessed. Although it's a read overflow, it can still have security implications, especially if it can be exploited further. The vulnerability is ranked high due to the potential for crashing the application and the complexity of FSE decompression logic, which might hide further exploitable conditions.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - There are checks in `readNCount` to limit `tableLog` and `symbolLen` to prevent excessively large tables.
    - `DecompressLimit` is intended to limit the output size, but it might not directly prevent table-related buffer overflows during decompression.

* Missing Mitigations:
    - More robust bounds checking should be implemented in the `decoder.next` and `decoder.nextFast` functions to ensure that the state index is always within the valid range of the `s.decTable`.
    - Fuzzing should be performed specifically targeting the FSE decompression logic with crafted inputs that attempt to trigger out-of-bounds table accesses, especially around maximum `tableLog` and `symbolLen` values and with corrupted compressed data following the header.
    - Consider adding explicit size checks before accessing `s.decTable` using the table size derived from `actualTableLog`.

* Preconditions:
    1. The application uses FSE decompression on untrusted or attacker-controlled compressed data.
    2. The attacker can craft a malicious FSE compressed stream with specific header values and potentially corrupted data following the header.

* Source Code Analysis:
    In `fse/decompress.go` and `zstd/fse_decoder.go`, the `readNCount` function reads table parameters and allocates `decTable` (or `dt`). Then, in `decompress` and `decoder.next/nextFast`, the `decTable` is accessed using `state` as an index.

    In `fse/decompress.go`:
    ```go
    func (s *Scratch) decompress() error {
        // ...
        var s1, s2 decoder
        // Initialize and decode first state and symbol.
        s1.init(br, s.decTable, s.actualTableLog)
        s2.init(br, s.decTable, s.actualTableLog)
        // ...
        for br.off >= 8 { // Main loop
            // ...
            tmp[off+0] = s1.nextFast() // Accessing s.decTable using s1.state
            tmp[off+1] = s2.nextFast() // Accessing s.decTable using s2.state
            // ...
        }
        // ...
    }

    type decoder struct {
        state uint16
        br    *bitReader
        dt    []decSymbol // s.decTable is passed here
    }

    func (d *decoder) nextFast() uint8 {
        n := d.dt[d.state] // Accessing d.dt (s.decTable) using d.state
        lowBits := d.br.getBitsFast(n.nbBits)
        d.state = n.newState + lowBits
        return n.symbol
    }
    ```

    Similar pattern exists in `zstd/fse_decoder.go` for `fseDecoder` and `fseState`. The vulnerability lies in the potential for `d.state` to become out of bounds due to corrupted input, leading to an out-of-bounds read when accessing `d.dt[d.state]`.

* Security Test Case:
    1. Craft a malicious FSE compressed stream. Create a program that generates a valid FSE header with a `tableLog` close to `tablelogAbsoluteMax` and a large `symbolLen`.
    2. Append corrupted or crafted data after the header in the compressed stream. This data should be designed to manipulate the decoder state during decompression.
    3. Prepare a test application that uses `fse.Decompress` or `zstd decoder` to decompress this crafted stream. Set a large `DecompressLimit` if necessary to avoid premature termination.
    4. Run the test application with the crafted compressed stream.
    5. Monitor the application for crashes or unexpected behavior. Use memory debugging tools (like AddressSanitizer if available) to detect out-of-bounds reads during decompression.
    6. If a crash or memory error is detected during the table access in `decoder.next` or `decoder.nextFast`, it indicates a successful trigger of the buffer overflow read vulnerability.
    7. Vary the crafted data and `tableLog`/`symbolLen` values to explore different out-of-bounds scenarios.

### Vulnerability: Potential Integer Overflow in Skippable Frame Size Calculation

* Description:
    The `calcSkippableFrame` function in `frameenc.go` calculates the size of a skippable frame to add padding. The function takes `written` (bytes already written) and `wantMultiple` (padding multiple) as `int64`. While the function checks if `wantMultiple <= 0` and `written < 0`, it does not explicitly check for integer overflows during the calculation of `toAdd`. If `wantMultiple` is very large and `written` is also large, the calculation `wantMultiple - leftOver` and subsequent additions of `wantMultiple` within the loop could potentially lead to an integer overflow, resulting in a negative or unexpectedly small `toAdd` value. This could lead to writing a skippable frame smaller than `skippableFrameHeader` or other unexpected behavior when creating skippable frames.

    Steps to trigger the vulnerability:
    1. An attacker cannot directly trigger this vulnerability through external input to the compression library itself. However, if an application using this library allows an attacker to control or influence the `wantMultiple` parameter passed to `calcSkippableFrame` and the amount of data being written, they might be able to trigger an overflow indirectly. This is highly unlikely in most real-world scenarios where padding is controlled server-side.
    2. An attacker needs to find a way to manipulate the `wantMultiple` and `written` values within the application's logic that calls `calcSkippableFrame`.
    3. If `wantMultiple` and `written` are crafted such that the calculation `wantMultiple - leftOver` or subsequent additions in the loop overflow, `toAdd` will become a small or negative value.
    4. When `skippableFrame` is called with this overflowed `total` value, it might lead to an error if `total < skippableFrameHeader` or unexpected behavior due to the incorrect padding size.

* Impact:
    Integer overflow in `calcSkippableFrame` could lead to incorrect padding sizes for skippable frames, potentially causing errors during frame creation or unexpected behavior in applications relying on consistent padding. While not a direct memory corruption or information disclosure vulnerability, it can lead to denial of service if frame creation fails or unexpected application behavior. The vulnerability is ranked high due to the potential for unexpected behavior in security-sensitive padding logic, although the direct exploitability by an external attacker is low.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    The function includes checks for `wantMultiple <= 0` and `written < 0` to prevent invalid inputs, but no explicit integer overflow checks during the calculation of `toAdd`.

* Missing Mitigations:
    Integer overflow checks should be added to the `calcSkippableFrame` function, especially during the calculation of `toAdd`. Before adding `wantMultiple` in the loop, the code should check if `toAdd + wantMultiple` would overflow the `int` type. Alternatively, using a larger integer type (like `int64`) for intermediate calculations and then casting to `int` with overflow checks could mitigate this issue. Input validation should be considered for `wantMultiple` to ensure it is within a reasonable range that will not cause overflows in typical usage scenarios.

* Preconditions:
    1. The application uses `calcSkippableFrame` to calculate padding size for skippable frames.
    2. An attacker can indirectly influence the `wantMultiple` and `written` parameters passed to `calcSkippableFrame` through application logic.

* Source Code Analysis:
    In `frameenc.go`, the `calcSkippableFrame` function performs calculations that are potentially vulnerable to integer overflow.

    ```go
    // calcSkippableFrame will return a total size to be added for written
    // to be divisible by multiple.
    // The value will always be > skippableFrameHeader.
    // The function will panic if written < 0 or wantMultiple <= 0.
    func calcSkippableFrame(written, wantMultiple int64) int {
        if wantMultiple <= 0 {
            panic("wantMultiple <= 0")
        }
        if written < 0 {
            panic("written < 0")
        }
        leftOver := written % wantMultiple
        if leftOver == 0 {
            return 0
        }
        toAdd := wantMultiple - leftOver // Potential overflow if wantMultiple is very large and leftOver is small
        for toAdd < skippableFrameHeader {
            toAdd += wantMultiple // Potential overflow in repeated addition
        }
        return int(toAdd)
    }
    ```
    - The lines `toAdd := wantMultiple - leftOver` and `toAdd += wantMultiple` in the loop are potential locations for integer overflows if `wantMultiple` is sufficiently large.
    - The return value `int(toAdd)` is a cast from `int64` to `int`, which could also truncate or wrap around if `toAdd` is outside the valid range of `int`.

* Security Test Case:
    1. Create a test program that calls `calcSkippableFrame` with very large `wantMultiple` values (close to `math.MaxInt64`) and varying `written` values to try to trigger an integer overflow in the `toAdd` calculation.
    2. Run the test program and check the returned `toAdd` values. If `toAdd` becomes negative or unexpectedly small when large inputs are used, it indicates an integer overflow vulnerability.
    3. Specifically, check if `skippableFrame` called with the potentially overflowed `toAdd` value results in an error due to `total < skippableFrameHeader` or if it creates a skippable frame with an invalid size.
    4. Monitor the behavior of the application and check for any panics or unexpected results caused by the overflowed padding size.

### Vulnerability: Potential Out-of-bounds Read in FSE Decoding - AMD64 Assembly Optimization

* Description:
    The assembly optimized `buildDtable_asm` function in `zstd/fse_decoder_amd64.go` for building FSE decoding tables might contain vulnerabilities if not carefully implemented. Specifically, if the assembly code incorrectly calculates table indices or performs memory accesses, it could lead to out-of-bounds reads from the `s.norm` or `s.stateTable` arrays, or writes to `s.dt` outside its allocated bounds. While Go code provides memory safety, assembly code can bypass these checks if not written correctly. A crafted compressed stream designed to exploit potential flaws in the assembly logic could trigger an out-of-bounds read, potentially leading to information disclosure or crashes.

    Steps to trigger the vulnerability:
    1. An attacker crafts a malicious FSE compressed stream with specific header values designed to trigger a specific code path in the `buildDtable_asm` function.
    2. The crafted header might aim to manipulate `tableLog`, `symbolLen`, or the normalized counts (`s.norm`) in a way that causes the assembly code to calculate invalid memory addresses.
    3. During the execution of `buildDtable_asm`, an out-of-bounds read occurs when accessing `s.norm`, `s.stateTable`, or when writing to `s.dt` due to incorrect index calculations in the assembly code.
    4. This out-of-bounds read could potentially leak sensitive information from process memory or cause a crash, depending on the nature and location of the read.

* Impact:
    An out-of-bounds read in the assembly optimized FSE decoding table construction could lead to information disclosure, denial of service (crash), or potentially further exploitation if the read data can be controlled or observed. The vulnerability is ranked high due to the potential for serious security impacts and the complexity of analyzing assembly code for memory safety issues, especially in the context of a complex decompression algorithm.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    The Go code surrounding the assembly function (`fseDecoder.buildDtable`) includes some checks and type safety, but these may not fully prevent vulnerabilities in the assembly implementation itself. The `readNCount` function performs checks on `tableLog` and `symbolLen`, but the assembly code might still have logical flaws leading to out-of-bounds accesses within the allowed table sizes.

* Missing Mitigations:
    - Thorough manual review and verification of the `buildDtable_asm` assembly code are necessary to ensure memory safety and correctness, especially concerning index calculations and bounds checking.
    - Automated tools for assembly code analysis or symbolic execution could be used to detect potential out-of-bounds read vulnerabilities.
    - Fuzzing should be performed with crafted FSE compressed streams specifically targeting the assembly optimized decoding path to attempt to trigger out-of-bounds reads during table construction. Memory sanitizers (like AddressSanitizer) should be used during fuzzing to detect memory access violations.
    - Add assertions within the assembly code (if feasible and without significant performance impact) to check for valid memory access ranges before performing reads or writes to the decoding tables.

* Preconditions:
    1. The application uses Zstandard decompression on an AMD64 architecture where assembly optimizations are enabled (`amd64 && !appengine && !noasm && gc` build tag).
    2. The attacker can provide a crafted Zstandard compressed stream that utilizes FSE encoding for literals or sequences and is designed to trigger the vulnerable code path in `buildDtable_asm`.

* Source Code Analysis:
    In `zstd/fse_decoder_amd64.go`, the `buildDtable_asm` function is called by `fseDecoder.buildDtable`. The assembly code (not provided in the Go file itself, but would be in a separate `.s` file or generated) is responsible for building the decoding table `s.dt` based on the normalized counts in `s.norm` and state table `s.stateTable`.

    ```go
    // buildDtable will build the decoding table.
    func (s *fseDecoder) buildDtable() error {
        ctx := buildDtableAsmContext{
            stateTable: &s.stateTable[0],
            norm:       &s.norm[0],
            dt:         (*uint64)(&s.dt[0]),
        }
        code := buildDtable_asm(s, &ctx)

        if code != 0 {
            // ... error handling ...
        }
        return nil
    }
    ```

    The vulnerability would reside within the `buildDtable_asm` assembly implementation. Without access to the assembly source code, static analysis is limited. However, potential areas of concern include:

    - **Index calculations**: Incorrectly calculated indices when accessing `s.norm`, `s.stateTable`, or `s.dt` based on `tableSize`, `highThreshold`, `step`, `position`, or loop variables.
    - **Memory access patterns**: Flaws in how memory addresses are derived and accessed in assembly, potentially leading to reads outside the intended bounds of the allocated tables.
    - **State management**: Errors in managing the decoder state during table construction in assembly, causing incorrect table entries or out-of-bounds accesses in subsequent decoding stages.

* Security Test Case:
    1. Craft a malicious Zstandard compressed stream. Create a program that generates a Zstandard stream with an FSE encoded block. The FSE header should be crafted with specific `tableLog` and `symbolLen` values, and the compressed data following the header should be designed to trigger the assembly optimized `buildDtable_asm` function.
    2. Prepare a test application that uses the Go Zstandard decoder to decompress this crafted stream. Ensure the application is built and run on an AMD64 architecture with assembly optimizations enabled.
    3. Run the test application with the crafted compressed stream.
    4. Monitor the application for crashes or unexpected behavior. Use memory debugging tools like AddressSanitizer (if available and compatible with assembly code) or Valgrind to detect out-of-bounds memory reads or writes during the execution of `buildDtable_asm`.
    5. If a crash or memory error is detected within `buildDtable_asm` or during table access after table construction, it indicates a successful trigger of the out-of-bounds read vulnerability.
    6. Vary the crafted header values and compressed data to explore different code paths in the assembly function and attempt to trigger different out-of-bounds scenarios.

### Vulnerability: Potential Out-of-bounds Write in `fastGen.addBlock` History Buffer Management

* Description:
    The `fastGen.addBlock` function in `fast_encoder.go` manages a history buffer (`e.hist`) to store previously processed data for efficient compression. When the buffer is full, it attempts to move the last `maxMatchOffset` bytes to the beginning of the buffer using unsafe pointer casting and slice manipulation. If the length of `e.hist` is less than `maxMatchOffset` at the time of buffer reset, the memory copy operation `*(*[maxMatchOffset]byte)(e.hist) = *(*[maxMatchOffset]byte)(e.hist[offset:])` could lead to an out-of-bounds write, as it attempts to write `maxMatchOffset` bytes into a potentially smaller slice. This could lead to memory corruption.

    Steps to trigger the vulnerability:
    1. Craft an input stream that causes the `fastGen.addBlock` function to be called repeatedly, filling up the history buffer `e.hist`.
    2. Ensure that at some point during the compression process, the length of `e.hist` becomes less than `maxMatchOffset` due to specific compression logic or input patterns (this scenario needs further investigation to reliably trigger).
    3. Provide more input data that triggers the buffer reset condition in `addBlock` (`len(e.hist) + len(src) > cap(e.hist)`).
    4. When the code reaches the memory copy `*(*[maxMatchOffset]byte)(e.hist) = *(*[maxMatchOffset]byte)(e.hist[offset:])` with `len(e.hist) < maxMatchOffset`, an out-of-bounds write occurs.

* Impact:
    An out-of-bounds write in `fastGen.addBlock` can lead to memory corruption, potentially causing crashes, unpredictable behavior, or exploitable conditions. While direct external exploitability might be low, memory corruption vulnerabilities are generally considered high severity due to their potential security implications.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    The code includes a check `if cap(e.hist) < maxMatchOffset*2` which is intended to prevent unexpected buffer sizes, but it does not directly prevent the out-of-bounds write if `len(e.hist)` is less than `maxMatchOffset` during the copy operation.

* Missing Mitigations:
    - Before performing the memory copy in `fastGen.addBlock`, ensure that `len(e.hist)` is always at least `maxMatchOffset`. If it's not, handle this case gracefully, possibly by allocating a new buffer or adjusting the copy logic to avoid out-of-bounds access.
    - Add explicit bounds checks before the memory copy to verify that the source and destination ranges are within the allocated memory for `e.hist`.
    - Thoroughly review the code paths that lead to `fastGen.addBlock` to understand under what conditions `len(e.hist)` could become less than `maxMatchOffset` before a buffer reset, and ensure these scenarios are handled safely.
    - Fuzzing with diverse input data, especially edge cases and boundary conditions, should be performed to try and trigger this potential out-of-bounds write. Memory sanitizers should be used during fuzzing to detect memory access violations.

* Preconditions:
    1. The application uses flate compression with fast encoding levels (1-6).
    2. The attacker can provide input data that is processed by the flate encoder, potentially influencing the state of the `fastGen` history buffer.

* Source Code Analysis:
    In `flate/fast_encoder.go`, the `fastGen.addBlock` function contains the potentially vulnerable memory copy operation:

    ```go
    func (e *fastGen) addBlock(src []byte) int32 {
        // ...
        else {
            if cap(e.hist) < maxMatchOffset*2 {
                panic("unexpected buffer size")
            }
            // Move down
            offset := int32(len(e.hist)) - maxMatchOffset
            // copy(e.hist[0:maxMatchOffset], e.hist[offset:])
            *(*[maxMatchOffset]byte)(e.hist) = *(*[maxMatchOffset]byte)(e.hist[offset:]) // Potential out-of-bounds write
            e.cur += offset
            e.hist = e.hist[:maxMatchOffset]
        }
        // ...
    }
    ```

    - The line `*(*[maxMatchOffset]byte)(e.hist) = *(*[maxMatchOffset]byte)(e.hist[offset:])` performs a direct memory copy using unsafe pointer casting.
    - If `len(e.hist)` is less than `maxMatchOffset`, then `e.hist[:maxMatchOffset]` would attempt to access memory beyond the bounds of the allocated slice, resulting in an out-of-bounds write.
    - The condition `if cap(e.hist) < maxMatchOffset*2` is a precondition, but it does not guarantee that `len(e.hist)` will always be >= `maxMatchOffset` when the copy is performed.

* Security Test Case:
    1. Create a test program that uses the flate compressor with a fast encoding level (e.g., BestSpeed).
    2. Construct a crafted input byte stream that is designed to manipulate the state of the `fastGen` history buffer and potentially reduce its length below `maxMatchOffset` before triggering a buffer reset. (This step might require some experimentation and understanding of the flate compression algorithm and encoder state management.)
    3. Compress the crafted input using the flate writer.
    4. Run the test program with memory sanitizers (like AddressSanitizer) enabled to detect out-of-bounds writes during the compression process.
    5. If AddressSanitizer reports an out-of-bounds write within the `fastGen.addBlock` function, it confirms the vulnerability.
    6. Vary the crafted input to explore different scenarios and potentially refine the test case to reliably trigger the vulnerability.

### Vulnerability: Potential Zip Path Traversal via crafted filenames

* Description:
    The `zip` package, specifically in `zip/reader.go`, does not adequately sanitize filenames within zip archives. When extracting files from a zip archive using functions like `OpenReader` and subsequently `File.Open`, a maliciously crafted zip file containing filenames with path traversal sequences (e.g., `../`, leading `/`) can lead to files being extracted outside the intended destination directory. While the `toValidName` function attempts to sanitize paths for `fs.FS.Open`, it is not consistently applied during file extraction, especially when directly using `File.Open` to access file contents. This can be exploited by an attacker to write files to arbitrary locations on the filesystem if the application processes attacker-controlled zip files and extracts them without proper sanitization.

    Steps to trigger the vulnerability:
    1. An attacker crafts a malicious zip file. This zip file contains entries with filenames designed to perform path traversal, such as `../../../sensitive_file` or `/absolute/path/sensitive_file`.
    2. The application uses `zip.OpenReader` to open the malicious zip file from an untrusted source (e.g., user upload, network download).
    3. The application iterates through the files in the zip archive using `r.File` and calls `f.Open()` to get an `io.ReadCloser` for each file.
    4. If the application then proceeds to write the content read from the `io.ReadCloser` to disk using the `f.Name` without proper sanitization, the path traversal sequences in the filename will be honored by the operating system during file creation, leading to files being written outside the intended directory.

* Impact:
    A path traversal vulnerability allows an attacker to write files to arbitrary locations on the filesystem, potentially overwriting critical system files, placing executable files in startup directories, or accessing sensitive data outside the intended scope. This can lead to arbitrary code execution, data exfiltration, or denial of service, depending on the application's permissions and the attacker's payload. The severity is critical as it can lead to full system compromise in vulnerable scenarios.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    The `toValidName` function in `zip/reader.go` attempts to sanitize filenames for use with `fs.FS.Open`, but this sanitization is not consistently applied throughout the zip package, especially when using `File.Open` directly for content extraction. The `zipinsecurepath` go debug variable provides some mitigation by returning an error if insecure paths are detected, but this is not a default or robust security measure.

* Missing Mitigations:
    - **Filename Sanitization during Extraction**: Implement mandatory and robust filename sanitization within the `File.Open` function or at the point where filenames are used for file creation during extraction. This should include:
        - Validating that the extracted path, after cleaning (e.g., using `filepath.Clean`), remains within the intended destination directory.
        - Rejecting or sanitizing filenames containing path traversal sequences like `..` or leading `/`.
        - Consider using a safe path join function that prevents traversal outside the base directory.
    - **Default Secure Behavior**: Ensure that path sanitization is enabled by default and is not reliant on environment variables or build flags. The secure behavior should be the standard operation of the library.
    - **Documentation and Warnings**: Clearly document the path traversal vulnerability and the importance of filename sanitization when extracting zip files, especially from untrusted sources. Warn users against directly using `f.Name` for file creation without validation.

* Preconditions:
    1. The application uses the `zip` package to extract files from zip archives.
    2. The application processes zip archives from untrusted sources, such as user uploads or network downloads.
    3. The application uses `f.Name` from `zip.File` to create files on the filesystem during extraction without proper path validation and sanitization.

* Source Code Analysis:
    In `zip/reader.go`, the `File` struct contains the `Name` field, which is directly populated from the zip archive's directory header without sanitization in `readDirectoryHeader`.

    ```go
    func readDirectoryHeader(f *File, r io.Reader) error {
        // ...
        f.Name = string(d[:filenameLen])
        // ...
    }
    ```

    When `File.Open` is called, it returns an `io.ReadCloser` to access the file content, but does not perform any sanitization on `f.Name` itself.

    ```go
    func (f *File) Open() (io.ReadCloser, error) {
        // ...
        return rc, nil
    }
    ```

    The `toValidName` function is used in `Reader.Open` (fs.FS interface), but this is a different `Open` method and the sanitization is not applied when directly extracting content from `File` objects obtained from `NewReader`.

    ```go
    func (r *Reader) Open(name string) (fs.File, error) {
        // ...
        if !fs.ValidPath(name) {
            return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
        }
        e := r.openLookup(name)
        // ...
    }

    // toValidName coerces name to be a valid name for fs.FS.Open.
    func toValidName(name string) string {
        name = strings.ReplaceAll(name, `\`, `/`)
        p := path.Clean(name)
        p = strings.TrimPrefix(p, "/")
        for strings.HasPrefix(p, "../") {
            p = p[len("../"):]
        }
        return p
    }
    ```

    The vulnerability exists because applications might directly use `NewReader` and `File.Open` to extract zip contents and use `f.Name` for file creation, bypassing the `fs.FS.Open` path sanitization, leading to path traversal.

* Security Test Case:
    1. Craft a malicious zip file named `malicious.zip`. This zip file should contain at least one entry with a path traversal filename, for example: `../../../evil.txt`. The content of `evil.txt` can be arbitrary, e.g., "This is evil content.".
    2. Create a test program in Go that uses `zip.OpenReader` to open `malicious.zip`.
    3. In the test program, iterate through the `r.File` slice obtained from `zip.Reader`.
    4. For each `zip.File`, use `f.Open()` to get an `io.ReadCloser`.
    5. Attempt to create a file on the filesystem using `f.Name` directly as the file path and write the content read from the `io.ReadCloser` into this file. Assume the intended destination directory is a temporary directory created for the test.
    6. Run the test program.
    7. After execution, check if the file `evil.txt` has been created outside the intended temporary directory, specifically in a parent directory based on the path traversal sequence (e.g., three levels up from the temporary directory).
    8. If `evil.txt` is found outside the temporary directory, it confirms the path traversal vulnerability. Verify the content of `evil.txt` to ensure it matches the content from the malicious zip entry.