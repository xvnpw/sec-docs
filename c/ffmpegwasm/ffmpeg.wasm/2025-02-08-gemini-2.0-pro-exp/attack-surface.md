# Attack Surface Analysis for ffmpegwasm/ffmpeg.wasm

## Attack Surface: [Codec Parsing Vulnerabilities](./attack_surfaces/codec_parsing_vulnerabilities.md)

*   **Description:** Exploits targeting vulnerabilities in specific audio or video codec implementations within FFmpeg. These vulnerabilities often involve memory corruption (buffer overflows, use-after-free, etc.) during the decoding process.  This is the most direct and likely attack vector against `ffmpeg.wasm`.
*   **How ffmpeg.wasm Contributes:** `ffmpeg.wasm` includes a vast array of codecs, each with its own complex parsing logic, increasing the likelihood of undiscovered vulnerabilities. The library itself is the source of the risk.
*   **Example:** A crafted H.264 video file with a malformed NAL unit triggers a buffer overflow in the H.264 decoder within `ffmpeg.wasm`, leading to arbitrary code execution within the WebAssembly sandbox.  Another example: a specially designed FLAC audio file exploits a heap overflow in the FLAC decoder.
*   **Impact:** Potential for arbitrary code execution within the WebAssembly sandbox, leading to data breaches (of data within the sandbox), denial of service, or potentially further exploitation if combined with browser vulnerabilities.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Codec Whitelisting:**  Strictly limit the supported codecs to the absolute minimum required.  Reject any input using unsupported codecs.
    *   **Input Validation:** Perform preliminary checks on the input file's structure *before* passing it to `ffmpeg.wasm`.
    *   **Regular Updates:**  Keep `ffmpeg.wasm` updated to the latest version.
    *   **Fuzzing:**  Conduct regular fuzzing of the specific codecs used.
    *   **Memory Limits:** Enforce strict memory limits on the WebAssembly module.

## Attack Surface: [Container Format Parsing Vulnerabilities](./attack_surfaces/container_format_parsing_vulnerabilities.md)

*   **Description:** Exploits targeting vulnerabilities in the parsing of container formats (e.g., MP4, AVI, MKV, WebM) used to encapsulate media streams. These vulnerabilities can also lead to memory corruption.
*   **How ffmpeg.wasm Contributes:** `ffmpeg.wasm` directly implements the parsing logic for numerous container formats, making it the source of this vulnerability class.
*   **Example:** A malformed MP4 file with an invalid atom structure triggers an out-of-bounds read in the MP4 demuxer within `ffmpeg.wasm`. Another example: a crafted AVI file with an oversized chunk causes a buffer overflow.
*   **Impact:** Similar to codec vulnerabilities: potential for arbitrary code execution within the WebAssembly sandbox, denial of service, or data exfiltration (within the sandbox).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Container Format Whitelisting:**  Strictly limit the supported container formats.
    *   **Input Validation:**  Perform basic structural checks on the container format *before* decoding.
    *   **Regular Updates:**  Keep `ffmpeg.wasm` updated.
    *   **Fuzzing:**  Fuzz the container format parsers.
    *   **Memory Limits:** Enforce strict memory limits.

## Attack Surface: [Command String Manipulation (If Applicable - High Risk Subset)](./attack_surfaces/command_string_manipulation__if_applicable_-_high_risk_subset_.md)

*   **Description:** *Specifically when* the application allows user input to influence the FFmpeg command string *and* this input is used to construct file paths or protocol handlers within the `ffmpeg.wasm` virtual file system. This is a *subset* of the broader command string manipulation issue, focusing on the direct interaction with `ffmpeg.wasm`.
*   **How ffmpeg.wasm Contributes:** While `ffmpeg.wasm` doesn't execute shell commands, its internal file handling and protocol support can be abused if the application improperly handles user-provided filenames or paths. The vulnerability arises from the *interaction* between the application's (poor) input handling and `ffmpeg.wasm`'s features.
*   **Example:** An application allows users to specify an output filename within the virtual file system. An attacker provides a filename like `"../sensitive_data.txt"` or `"concat:file1|file2"` (using FFmpeg's `concat` protocol) to attempt to access or manipulate files outside the intended output directory *within the WebAssembly sandbox*.
*   **Impact:** Potential for arbitrary file access *within the WebAssembly virtual file system*, leading to data leaks or modification of data within the sandbox.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Direct Command String Construction:** *Never* directly construct FFmpeg command strings from user input.
    *   **Use API for Parameter Setting:** Use the `ffmpeg.wasm` API to set options programmatically.
    *   **Strict Input Sanitization:** Implement *extremely* strict sanitization and validation of any user input that affects file paths or protocol handlers. Whitelist allowed characters and patterns.
    *   **Virtual File System Isolation:** Ensure that FFmpeg only has access to the intended files within the virtual file system. Use a dedicated, isolated directory for user-provided output.

