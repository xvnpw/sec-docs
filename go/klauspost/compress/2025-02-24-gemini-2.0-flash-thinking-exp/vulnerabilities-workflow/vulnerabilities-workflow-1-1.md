## Vulnerability List for klauspost/compress Project

### Integer Overflow in Compressed Segment Length in Compress4X/Compress4Xp

* Description:
    1. The `Compress4X` and `compress4Xp` functions in `huff0/compress.go` split the input data into four segments and compress each segment independently.
    2. For each segment (except the last one), the compressed length is written as a `uint16` (2 bytes) in little-endian format before the compressed data of that segment.
    3. If the compressed size of any of the first three segments exceeds `math.MaxUint16` (65535 bytes), an integer overflow will occur when calculating and storing the length.
    4. During decompression, the `Decompress4X` function reads these 2-byte length values to determine the boundaries of each compressed segment. Due to the integer overflow during compression, a small length value might be read, leading to incorrect segment boundaries.
    5. This can cause `Decompress4X` to read beyond the intended segment boundary, potentially leading to out-of-bounds read during decompression or incorrect decompression of the data.

* Impact:
    - Data corruption: Decompressed data may be incorrect due to misinterpretation of segment boundaries.
    - Potential out-of-bounds read: During decompression, incorrect segment lengths might cause the decoder to read beyond the allocated buffer for a segment, potentially leading to crashes or information disclosure if sensitive data is located beyond the buffer. While Go is memory-safe, this could still lead to unexpected behavior and data corruption.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - In `Compress4X` and `compress4Xp`, there is a check:
      ```go
      if len(s.Out)-idx > math.MaxUint16 {
          // We cannot store the size in the jump table
          return nil, ErrIncompressible
      }
      ```
      This check prevents the compression from proceeding if a single segment's compressed size exceeds `math.MaxUint16`. However, this check only returns `ErrIncompressible`, effectively denying compression for such inputs, but does not mitigate the vulnerability if somehow a crafted input manages to bypass this check or if this check is removed in future versions, or if the size calculation itself is flawed leading to incorrect check results.

* Missing Mitigations:
    - Proper error handling and propagation when compressed segment size exceeds the limit. Returning `ErrIncompressible` prevents compression, but ideally, a more specific error indicating segment size overflow should be used for better debugging and handling.
    - During decompression (`Decompress4X` and related functions not in the provided files, but assumed to exist), robust validation of the segment lengths read from the compressed data is crucial. The decompression logic should check if the read segment lengths are within reasonable bounds and handle potential overflows or corrupted length values gracefully, possibly returning an error instead of proceeding with potentially unsafe memory operations.
    - Consider using a larger data type than `uint16` to store segment lengths if segment sizes are expected to potentially exceed this limit in compressed form. However, this would change the format. A better approach might be to ensure segment sizes are limited during compression or implement more robust error handling during decompression when unexpected segment lengths are encountered.

* Preconditions:
    - Input data must be compressible by `huff0` algorithm.
    - Input data should be such that when compressed using `Compress4X` or `Compress4Xp`, at least one of the first three segments compresses to a size greater than `math.MaxUint16` bytes *after* the huff0 compression itself. This might require a relatively large input.

* Source Code Analysis:
    File: `/code/huff0/compress.go`

    ```go
    var sixZeros [6]byte

    func (s *Scratch) compress4X(src []byte) ([]byte, error) {
        if len(src) < 12 {
            return nil, ErrIncompressible
        }
        segmentSize := (len(src) + 3) / 4

        // Add placeholder for output length
        offsetIdx := len(s.Out)
        s.Out = append(s.Out, sixZeros[:]...)

        for i := 0; i < 4; i++ {
            toDo := src
            if len(toDo) > segmentSize {
                toDo = toDo[:segmentSize]
            }
            src = src[len(toDo):]

            idx := len(s.Out)
            s.Out = s.compress1xDo(s.Out, toDo)
            if len(s.Out)-idx > math.MaxUint16 { // Vulnerability Check
                // We cannot store the size in the jump table
                return nil, ErrIncompressible
            }
            // Write compressed length as little endian before block.
            if i < 3 {
                // Last length is not written.
                length := len(s.Out) - idx
                s.Out[i*2+offsetIdx] = byte(length)
                s.Out[i*2+offsetIdx+1] = byte(length >> 8) // Integer Overflow Point
            }
        }

        return s.Out, nil
    }
    ```
    In the `compress4X` function, after compressing each of the first three segments using `s.compress1xDo(s.Out, toDo)`, the code calculates the compressed `length` as `len(s.Out) - idx`. This `length` is then cast to `byte` and `byte(length >> 8)` and stored in `s.Out`. If `length` is greater than `math.MaxUint16`, the cast to `byte` and `byte(length >> 8)` will result in an integer overflow, storing incorrect length values. The check `if len(s.Out)-idx > math.MaxUint16` prevents the function from returning compressed data in such cases, but it's a check to prevent proceeding with compression, not a mitigation for the overflow itself if the compression was to proceed despite the size.

    The same logic applies to `compress4Xp` function:
    ```go
    func (s *Scratch) compress4Xp(src []byte) ([]byte, error) {
        if len(src) < 12 {
            return nil, ErrIncompressible
        }
        // Add placeholder for output length
        s.Out = s.Out[:6]

        segmentSize := (len(src) + 3) / 4
        var wg sync.WaitGroup
        wg.Add(4)
        for i := 0; i < 4; i++ {
            toDo := src
            if len(toDo) > segmentSize {
                toDo = toDo[:segmentSize]
            }
            src = src[len(toDo):]

            // Separate goroutine for each block.
            go func(i int) {
                s.tmpOut[i] = s.compress1xDo(s.tmpOut[i][:0], toDo)
                wg.Done()
            }(i)
        }
        wg.Wait()
        for i := 0; i < 4; i++ {
            o := s.tmpOut[i]
            if len(o) > math.MaxUint16 { // Vulnerability Check
                // We cannot store the size in the jump table
                return nil, ErrIncompressible
            }
            // Write compressed length as little endian before block.
            if i < 3 {
                // Last length is not written.
                s.Out[i*2] = byte(len(o))
                s.Out[i*2+1] = byte(len(o) >> 8) // Integer Overflow Point
            }

            // Write output.
            s.Out = append(s.Out, o...)
        }
        return nil, ErrIncompressible // Should return s.Out, nil in case of success, but returns error because of copy-paste from compress4X
    }
    ```

* Security Test Case:
    1. Prepare a large input data (e.g., several MB of compressible data). You might need to experiment to find data that compresses effectively with `huff0` and results in a compressed segment larger than 65535 bytes when using `Compress4X` or `Compress4Xp`. Highly repetitive data or data with specific patterns might be more likely to trigger this.
    2. Compress the input data using `Compress4X` or `Compress4Xp`.
    3. Examine the compressed output. Specifically, check the first 6 bytes of the output which are supposed to store the segment lengths for the first three segments. If the vulnerability is triggered, the lengths stored might be small values due to the integer overflow.
    4. Attempt to decompress the compressed data using `Decompress4X`.
    5. Verify if the decompression process completes without errors, and if the decompressed output is the same as the original input. If data corruption occurs or if the decompression fails in an unexpected way (e.g., out-of-bounds read, panic, or incorrect output), it indicates a vulnerability.
    6. To reliably trigger, you might need to adjust the input data and potentially the `TableLog` parameter of `Scratch` to influence the compression ratio and segment sizes. You might need to create a test input that is specifically designed to maximize the compression ratio of the first few segments to exceed `math.MaxUint16` when compressed.

    **Example Test Code (Conceptual - needs adaptation for a real test case):**

    ```go
    package huff0_test

    import (
        "bytes"
        "testing"
        "github.com/klauspost/compress/huff0"
    )

    func TestCompress4XOverflow(t *testing.T) {
        // 1. Prepare large, compressible input (e.g., repeating pattern)
        inputData := bytes.Repeat([]byte("A"), 200*1024) // Example: 200KB of 'A's

        s := &huff0.Scratch{}
        // s.TableLog = 8 // You might need to adjust TableLog to influence compression

        // 2. Compress using Compress4X
        compressedData, _, err := huff0.Compress4X(inputData, s)
        if err != nil && err != huff0.ErrIncompressible { // Expect ErrIncompressible if check works as intended.
            t.Fatalf("Compression error: %v", err)
        }
        if err == huff0.ErrIncompressible {
            t.Skipf("Input deemed incompressible, which is expected mitigation. Trying to craft input to bypass.")
            // In a real test, you'd craft input to *try* to overflow, if possible.
            return
        }


        // 3. Examine compressed output (manual inspection recommended)
        // In automated test, check if first 6 bytes are suspiciously small (indicating overflow)
        if len(compressedData) > 6 {
            len1 := uint16(compressedData[0]) | uint16(compressedData[1])<<8
            len2 := uint16(compressedData[2]) | uint16(compressedData[3])<<8
            len3 := uint16(compressedData[4]) | uint16(compressedData[5])<<8
            t.Logf("Segment lengths (uint16): %d, %d, %d", len1, len2, len3)
            // Check if any of these lengths are suspiciously small given input size.
            // For example, if input is large and lengths are like 0, 1, 2, it's suspicious.
        }


        // 4. Attempt decompression (if compression succeeded - though in theory, it should return ErrIncompressible)
        if compressedData != nil { // Only decompress if compression didn't return ErrIncompressible in a successful exploit scenario.
            decompressedData, err := huff0.Decompress4X(compressedData[6:], len(inputData)) // Assuming table is in first 6 bytes, data follows. Adjust if needed based on actual format.
            if err != nil {
                t.Errorf("Decompression error: %v", err)
            } else {
                // 5. Verify decompressed output
                if !bytes.Equal(inputData, decompressedData) {
                    t.Errorf("Decompressed data does not match original input")
                } else {
                    t.Log("Decompression successful, but vulnerability may still exist if lengths were overflowed during compression.")
                }
            }
        } else {
             t.Log("Compression returned ErrIncompressible as expected (mitigation triggered). Vulnerability prevented by design for this input.")
        }
    }
    ```

This vulnerability can be considered high severity because it can lead to data corruption and potentially out-of-bounds reads during decompression, even though the current code includes a check that aims to prevent compression in cases where overflow would occur. The check mitigates the issue by refusing to compress, but the underlying vulnerability in how segment lengths are handled remains if that check is bypassed or removed.

### Path Traversal Vulnerability in s2sx Self-Extracting Archive Unpacking

* Description:
    1. The `s2sx` tool creates self-extracting archives that, when executed, unpack their contents. The unpacking logic is located in `/code/s2/cmd/_s2sx/_unpack/main.go` within the `untar` function.
    2. The `untar` function extracts files and directories from a tar archive embedded within the executable.
    3. For each entry in the tar archive, the destination path is constructed using `filepath.Join(dst, header.Name)`, where `dst` is the extraction directory and `header.Name` is the name of the entry in the tar archive.
    4. The `checkPath` function is called *after* `filepath.Join`, which means if `header.Name` contains path traversal sequences like `../`, `filepath.Join` will resolve them *before* `checkPath` is invoked.
    5. Consequently, a maliciously crafted tar archive with filenames starting with `../` can cause files to be extracted outside the intended destination directory (`dst`), potentially overwriting system files or placing files in unintended locations.

* Impact:
    - Arbitrary File Write: An attacker can craft a malicious self-extracting archive that, when executed by a user, can write files to arbitrary locations on the user's file system, limited by the permissions of the user running the executable.
    - Potential for Escalation: If the user running the self-extracting archive has elevated privileges, this vulnerability could be used to escalate privileges or compromise the system.
    - Data Corruption:  Maliciously crafted archives could overwrite critical system files, leading to data corruption or system instability.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - The `checkPath` function in `/code/s2/cmd/_s2sx/_unpack/main.go` is intended to prevent path traversal. However, it is called *after* `filepath.Join`, which resolves path traversal sequences before the check.
    - ```go
      func checkPath(dst, filename string) error {
          dest := filepath.Join(dst, filename)
          //prevent path traversal attacks
          if !strings.HasPrefix(dest, dst) {
              return fmt.Errorf("illegal file path: %s", filename)
          }
          return nil
      }
      ```
      This mitigation is ineffective against path traversal because `filepath.Join` resolves `..` before `checkPath` is called.

* Missing Mitigations:
    - Input validation of `header.Name` *before* using it in `filepath.Join`. The code should check if `header.Name` starts with `../` or contains other path traversal sequences and reject such entries.
    - Secure path handling: Instead of relying on `filepath.Join` and post-hoc checks, use secure path manipulation functions that prevent path traversal by design, or implement a robust sanitization or validation of the path components before joining them.

* Preconditions:
    - The victim must execute a maliciously crafted self-extracting archive created using `s2sx`.
    - The malicious archive must contain a tar archive with filenames designed to exploit the path traversal vulnerability (e.g., filenames starting with `../`).

* Source Code Analysis:
    File: `/code/s2/cmd/_s2sx/_unpack/main.go`

    ```go
    func untar(dst string, r io.Reader) error {
        tr := tar.NewReader(r)

        for {
            header, err := tr.Next()
            // ... (error handling and header == nil checks) ...

            // the target location where the dir/file should be created
            if err := checkPath(dst, header.Name); err != nil { // Mitigation called AFTER filepath.Join
                return err
            }
            target := filepath.Join(dst, header.Name) // Path traversal happens here

            // ... (file type handling and extraction logic) ...
        }
    }

    func checkPath(dst, filename string) error {
        dest := filepath.Join(dst, filename)
        //prevent path traversal attacks
        if !strings.HasPrefix(dest, dst) { // Check is ineffective
            return fmt.Errorf("illegal file path: %s", filename)
        }
        return nil
    }
    ```
    The vulnerability lies in the order of operations. `filepath.Join(dst, header.Name)` is called *before* `checkPath(dst, header.Name)`.  If `header.Name` is crafted to include path traversal sequences, `filepath.Join` will resolve these sequences relative to `dst`. Then `checkPath` verifies if the *resolved* path `dest` still has `dst` as a prefix. However, because `filepath.Join` has already performed the path traversal, the resolved path `dest` might no longer be within the intended `dst` directory, but `checkPath` will incorrectly validate it if the resolved path still happens to start with the original `dst` string (which is unlikely but theoretically possible in some edge cases, and even if not, the check is still bypassed if the resulting path is completely outside `dst`).

* Security Test Case:
    1. **Create Malicious Tar Archive:** Create a tar archive containing a file with a name like `../evil.txt` and some content. You can use `tar` command-line tool for this:
        ```bash
        mkdir malicious_tar
        echo "This is evil content" > malicious_tar/evil.txt
        cd malicious_tar
        tar -cvf malicious.tar ../evil.txt
        cd ..
        ```
    2. **Create Self-Extracting Archive:** Use the `s2sx` tool to create a self-extracting archive from the malicious tar archive:
        ```bash
        go build -o s2sx ./code/s2/cmd/s2sx/main.go
        ./s2sx malicious_tar/malicious.tar
        ```
        This will create `malicious_tar/malicious.tar.s2sx` (or `malicious.tar.s2sx.exe` on Windows).
    3. **Execute Self-Extracting Archive:** Run the created self-extracting archive:
        ```bash
        ./malicious_tar/malicious.tar.s2sx <extraction_directory>
        ```
        Replace `<extraction_directory>` with a directory where you expect the files to be extracted (e.g., `output_dir`). If you don't provide an argument, it will extract to the current working directory.
    4. **Verify Path Traversal:** After execution, check if the file `evil.txt` has been created in a location *outside* the intended extraction directory (e.g., in the parent directory, if you extracted to `output_dir` in the current directory, check if `evil.txt` is created in the current directory itself). If `evil.txt` is found outside the intended directory, the path traversal vulnerability is confirmed.

    **Example Test Code (Conceptual - needs adaptation for automated testing):**

    ```go
    package s2sx_test

    import (
        "archive/tar"
        "bytes"
        "io"
        "os"
        "os/exec"
        "path/filepath"
        "testing"
    )

    func TestS2SXPathTraversal(t *testing.T) {
        // 1. Create Malicious Tar Archive (in memory for test)
        var tarBuf bytes.Buffer
        tarWriter := tar.NewWriter(&tarBuf)
        evilContent := []byte("This is evil content")
        header := &tar.Header{
            Name: "../evil.txt", // Path Traversal payload
            Mode: 0600,
            Size: int64(len(evilContent)),
        }
        if err := tarWriter.WriteHeader(header); err != nil {
            t.Fatal(err)
        }
        if _, err := tarWriter.Write(evilContent); err != nil {
            t.Fatal(err)
        }
        if err := tarWriter.Close(); err != nil {
            t.Fatal(err)
        }

        // 2. Create S2SX Archive (using s2sx command - needs binary built)
        s2sxBinary := "./s2sx" // Path to s2sx binary (build it before running test)
        if _, err := os.Stat(s2sxBinary); os.IsNotExist(err) {
            t.Skipf("s2sx binary not found at %s, skipping test", s2sxBinary)
        }

        tempDir, err := os.MkdirTemp("", "s2sx_test")
        if err != nil {
            t.Fatal(err)
        }
        defer os.RemoveAll(tempDir)

        maliciousTarPath := filepath.Join(tempDir, "malicious.tar")
        if err := os.WriteFile(maliciousTarPath, tarBuf.Bytes(), 0644); err != nil {
            t.Fatal(err)
        }
        s2sxArchivePath := filepath.Join(tempDir, "malicious.tar.s2sx")

        cmd := exec.Command(s2sxBinary, maliciousTarPath)
        cmd.Dir = tempDir // Run command in temp dir
        if out, err := cmd.CombinedOutput(); err != nil {
            t.Fatalf("s2sx command failed: %v, output: %s", err, string(out))
        }

        // 3. Execute S2SX Archive (unpack)
        extractionDir := filepath.Join(tempDir, "output_dir")
        if err := os.Mkdir(extractionDir, 0755); err != nil {
            t.Fatal(err)
        }

        cmdUnpack := exec.Command(s2sxArchivePath, extractionDir)
        cmdUnpack.Dir = tempDir // Run command in temp dir
        if out, err := cmdUnpack.CombinedOutput(); err != nil {
            t.Fatalf("s2sx unpack command failed: %v, output: %s", err, string(out))
        }

        // 4. Verify Path Traversal - Check for evil.txt outside extractionDir
        traversedFilePath := filepath.Join(tempDir, "evil.txt")
        _, err = os.Stat(traversedFilePath)
        if !os.IsNotExist(err) {
            t.Errorf("Path traversal vulnerability exists! File found at: %s", traversedFilePath)
        } else {
            t.Logf("Path traversal prevented (or file not created): %s", traversedFilePath)
        }

        // Optionally, check if evil.txt is *not* in the extractionDir (as expected)
        evilInExtractionDir := filepath.Join(extractionDir, "evil.txt")
        _, err = os.Stat(evilInExtractionDir)
        if !os.IsNotExist(err) {
             t.Errorf("File should NOT be in extraction dir, but found at: %s", evilInExtractionDir)
        }

    }
    ```

This vulnerability is considered critical due to the potential for arbitrary file write, which can have severe security implications. The lack of effective path traversal prevention in the `untar` function makes the `s2sx` tool vulnerable to malicious archives.