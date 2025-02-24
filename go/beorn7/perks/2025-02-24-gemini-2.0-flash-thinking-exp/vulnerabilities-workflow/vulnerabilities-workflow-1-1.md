- Vulnerability name: Inaccurate Quantile Calculation due to Broken Merge Function
- Description: The `Merge` function in the `quantile` package is implemented incorrectly. When merging samples from multiple streams, the resulting quantile calculations can be inaccurate. An attacker could potentially exploit this by providing crafted sets of samples to be merged, leading to significant deviations in the calculated quantiles compared to the expected true quantiles of the combined dataset. This is because the current implementation incorrectly merges pre-compressed summaries instead of the raw data points.
- Impact: Incorrect quantile values. If an application relies on the accuracy of merged quantiles for security-sensitive decisions, such as anomaly detection, rate limiting, or access control based on percentile thresholds, this vulnerability can lead to security bypasses or misconfigurations. For example, if a system uses the 99th percentile of request latency to detect anomalies, and the merged quantile is significantly lower than the actual 99th percentile due to the broken merge function, legitimate anomalies might be missed, or conversely, false positives might occur if the merged quantile is artificially inflated.
- Vulnerability rank: High
- Currently implemented mitigations: None. The code itself is flawed, and the issue is acknowledged in comments and broken tests within the codebase. The comments explicitly state that the `Merge` function is broken and provides incorrect results. Tests related to merging are marked as "BrokenTest".
- Missing mitigations: The `Merge` function needs to be reimplemented correctly. The correct implementation should either merge the raw data points from all streams before compression or implement a proper algorithm for merging compressed quantile summaries as described in the research paper "Effective Computation of Biased Quantiles over Data Streams".
- Preconditions:
    - The application must use the `Merge` function of the `quantile` package to combine quantile streams from different sources.
    - The security logic of the application must depend on the accuracy of the quantiles calculated after merging.
    - An attacker needs to be able to influence the data streams being merged, either by directly injecting malicious data points or by manipulating the data distribution of the streams being merged.
- Source code analysis:
    - File: `/code/quantile/stream.go`
    - Function: `Stream.Merge(samples Samples)`
    - The function's documentation includes the warning: `ATTENTION: This method is broken and does not yield correct results. The underlying algorithm is not capable of merging streams correctly.`
    - The code within the `Merge` function attempts to merge samples by iterating through the input `samples` and inserting them into the stream's internal sample list (`s.l`).
    - A comment within the `stream.merge` function further clarifies the issue: `// TODO(beorn7): This tries to merge not only individual samples, but whole summaries. The paper doesn't mention merging summaries at all. Unittests show that the merging is inaccurate. Find out how to do merges properly.`
    - The implementation attempts to calculate `delta` during merging, but it is marked with a `// TODO(beorn7): How to calculate delta correctly?` comment, indicating a lack of clarity and potential correctness issues in this part of the algorithm.
    - The test suite in `/code/quantile/stream_test.go` includes tests like `BrokenTestTargetedMerge`, `BrokenTestLowBiasedMerge`, and `BrokenTestHighBiasedMerge`, all marked as "Broken", which confirms the functional issue with the `Merge` function.
    ```go
    // File: /code/quantile/stream.go
    func (s *Stream) Merge(samples Samples) {
    	sort.Sort(samples)
    	s.stream.merge(samples) // Calls the broken stream.merge function
    }

    // File: /code/quantile/stream.go
    func (s *stream) merge(samples Samples) {
    	// TODO(beorn7): This tries to merge not only individual samples, but
    	// whole summaries. The paper doesn't mention merging summaries at all.
    	// Unittests show that the merging is inaccurate. Find out how to
    	// do merges properly.
    	var r float64
    	i := 0
    	for _, sample := range samples {
    		for ; i < len(s.l); i++ {
    			c := s.l[i]
    			if c.Value > sample.Value {
    				// Insert at position i.
    				s.l = append(s.l, Sample{})
    				copy(s.l[i+1:], s.l[i:])
    				s.l[i] = Sample{
    					sample.Value,
    					sample.Width,
    					math.Max(sample.Delta, math.Floor(s.ƒ(s, r))-1), // TODO(beorn7): How to calculate delta correctly?
    					// TODO(beorn7): How to calculate delta correctly?
    				}
    				i++
    				goto inserted
    			}
    			r += c.Width
    		}
    		s.l = append(s.l, Sample{sample.Value, sample.Width, 0})
    		i++
    	inserted:
    		s.n += sample.Width
    		r += sample.Width
    	}
    	s.compress()
    }
    ```
- Security test case:
    1. Set up two separate instances of the `Stream` object, `stream1` and `stream2`, using `quantile.NewTargeted` with the same target quantiles.
    2. Populate `stream1` with a set of numerical data points, for example, integers from 1 to 100.
    3. Populate `stream2` with a different set of numerical data points, for example, integers from 101 to 200.
    4. Create a combined dataset by concatenating the data points used to populate `stream1` and `stream2`.
    5. Calculate the true 90th percentile of the combined dataset using a standard sorting algorithm and selecting the element at the 90th percentile rank. Let's call this `true_p90`.
    6. Merge `stream2` into `stream1` using `stream1.Merge(stream2.Samples())`.
    7. Query the 90th percentile from the merged stream `stream1` using `stream1.Query(0.90)`. Let's call this `merged_p90`.
    8. Compare `merged_p90` with `true_p90`. If the absolute difference `|merged_p90 - true_p90|` is significantly larger than the expected error margin for quantile approximation (which depends on the epsilon values provided to `NewTargeted`), it demonstrates the inaccuracy caused by the broken `Merge` function. The significance threshold should be determined based on the epsilon values and the dataset size, but a difference exceeding 10% of `true_p90` can be considered significant for demonstration purposes.
    9. To further emphasize the vulnerability, repeat steps 1-8 with different datasets and target quantiles (e.g., 50th, 99th percentiles) to show the inconsistency and unreliability of the `Merge` function across various scenarios.