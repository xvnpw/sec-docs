# Threat Model Analysis for ffmpegwasm/ffmpeg.wasm

## Threat: [Codec Exploitation (Remote Code Execution within WASM)](./threats/codec_exploitation__remote_code_execution_within_wasm_.md)

*   **Threat:** Codec Exploitation (Remote Code Execution within WASM)

    *   **Description:** An attacker crafts a malicious media file (video, audio, or image) that exploits a vulnerability in one of FFmpeg's codecs or demuxers.  The attacker uploads this file, and when `ffmpeg.wasm` processes it, the vulnerability is triggered, allowing the attacker to execute arbitrary code *within* the WebAssembly sandbox.
    *   **Impact:**
        *   Compromise of the `ffmpeg.wasm` module's memory space.
        *   Potential data exfiltration from the WASM environment (e.g., other processed media data).
        *   Denial of Service (DoS) of the `ffmpeg.wasm` module (crashing the worker/tab).
        *   *Potential* (though less likely) for WASM sandbox escape (which would elevate the impact significantly).
    *   **Affected Component:** Specific vulnerable codec(s) or demuxer(s) within the FFmpeg library (e.g., `libavcodec`, `libavformat`). The precise function depends on the specific vulnerability.
    *   **Risk Severity:** Critical (if a reliable RCE exploit exists); High (if a less reliable exploit or DoS is possible).
    *   **Mitigation Strategies:**
        *   **Regular Updates:**  Keep `ffmpeg.wasm` and its underlying FFmpeg version up-to-date. Prioritize security-related updates.
        *   **Codec Whitelisting/Blacklisting:**  Restrict the set of supported codecs and formats to the absolute minimum. Disable unnecessary or known-vulnerable codecs. Configure `ffmpeg.wasm` to use only the whitelisted codecs.
        *   **Input Sanitization (Limited):** Perform basic checks (file size, magic numbers) to reject obviously malformed files. This is *not* a primary defense.
        *   **Resource Limits:** Enforce strict limits on memory, CPU time, and execution time for the `ffmpeg.wasm` module. Use Web Worker `terminate()` if limits are exceeded.
        *   **Web Worker Isolation:** Run `ffmpeg.wasm` in a dedicated Web Worker.

## Threat: [Denial of Service (Resource Exhaustion)](./threats/denial_of_service__resource_exhaustion_.md)

*   **Threat:** Denial of Service (Resource Exhaustion)

    *   **Description:** An attacker provides a media file (or sequence of files) designed to consume excessive resources (CPU, memory) when processed by `ffmpeg.wasm`. This could be a very large file, a file with extremely high resolution/bitrate, or a file crafted to trigger computationally expensive operations.
    *   **Impact:**
        *   Denial of Service (DoS) of the `ffmpeg.wasm` module, making it unresponsive.
        *   Potential browser tab/window crash due to resource exhaustion.
        *   Degraded performance of the web application for the affected user.
    *   **Affected Component:** The entire `ffmpeg.wasm` module, especially the core processing functions within `libavcodec` and `libavformat`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Resource Limits:** Enforce very strict limits on memory usage, CPU time, and overall execution time. Use Web Worker `terminate()` to stop processing if limits are exceeded.
        *   **Input Validation (Size/Complexity):** Implement checks on input file size, resolution, bitrate, and other parameters to reject excessively large or complex files.
        *   **Rate Limiting:** Limit the number of files or total data a user can process within a time period.
        *   **Progressive Processing (if applicable):** Process media in chunks, allowing for early termination if resource limits are approached.

## Threat: [Supply Chain Compromise (Malicious ffmpeg.wasm Build)](./threats/supply_chain_compromise__malicious_ffmpeg_wasm_build_.md)

*   **Threat:** Supply Chain Compromise (Malicious ffmpeg.wasm Build)

    *   **Description:** An attacker compromises the build process or distribution channel for `ffmpeg.wasm`. The attacker replaces the legitimate `ffmpeg.wasm` file with a malicious version containing backdoors or other exploits.
    *   **Impact:**
        *   Complete compromise of the `ffmpeg.wasm` module, leading to arbitrary code execution within the WASM sandbox.
        *   Potential for all impacts listed in other threats (RCE, DoS, information disclosure).
    *   **Affected Component:** The entire `ffmpeg.wasm` module.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Use Official Sources:** Obtain `ffmpeg.wasm` *only* from the official GitHub repository (https://github.com/ffmpegwasm/ffmpeg.wasm) or a highly trusted mirror.
        *   **Subresource Integrity (SRI):** Use SRI tags in your HTML to verify the integrity of the downloaded `ffmpeg.wasm` file. This is *essential*. Example:
            ```html
            <script src="ffmpeg.wasm" integrity="sha384-yourGeneratedHashHere" crossorigin="anonymous"></script>
            ```
        *   **Dependency Management:** If using a package manager (e.g., npm), use a locked version of `ffmpeg.wasm` and audit dependencies regularly.
        *   **Content Security Policy (CSP):** Use a strict CSP to restrict the sources from which your application can load WASM files.

