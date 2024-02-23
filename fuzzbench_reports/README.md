# Fuzzing Restarts: Fuzzbench Reports

Here you can find the Fuzzbench reports from our paper. After cloning the repository, just open the `.html` files with a browser to display the reports.
There are the following reports:

- `coverage_reports` - refers to **Experiment 1 - 4** in the paper
- `sampling_reports` - refers to **Experiment 5** in the paper
- `bug_reports` - refers to **Experiment 6** in the paper

## Notes

The names of our Sileo strategies differ in our code compared to the paper, each strategy refers to a own fuzzer in FuzzBench and can be found in `fuzzers/sileo_aflpp_*`. In the following, you can find the mapping between the name from our code and the name in the paper:

- *corpus_del*: Sileo Corus Pruning
- *input_shuffle*: Sileo Input Shuffle
- *rnd*: Sileo Reset
- *tree_chopper*: Sileo Tree Chopper
- *tree_planter*: Sileo Tree Planter
- *timeback_plain*: Sileo Timeback
- *adaptive*: Sileo Ensemble
- *continue*: Not named in the paper, but refers to *input_shuffle* without copying all inputs (See Discussion Section). We recommend this instead of input_shuffle to reduce disk usage.

The fuzzer names also show its restart heuristic:

- *\*_purge*: threshold-based restarts
- *\*_force_MINUTES*: force restart after restart time in MINUTES
- *\*_sampling*: the fuzzer / strategy is configured using our patched aflplusplus (for sampling experiments)
- *\*_cmin*: the fuzzer / strategy uses *afl-cmin* (using AFL++ 4.06)
