#!/bin/bash
set -euo pipefail

# This script runs the evaluation with different monitored flow ratio values.
# Many evaluations are executed and all of their results are saved.

# Sampling ratios to test
sampling_ratios=(1.00 0.50 0.25 0.15 0.10 0.05 0.03 0.01)
echo "The following sampling ratios will be tested: ${sampling_ratios[*]}"

# Cleaning the previous results
make clean-all

# Run the evaluation for each sampling ratio
for sampling_ratio in "${sampling_ratios[@]}"; do
    echo "Running the evaluation with sampling ratio ${sampling_ratio}..."
    make eval-simulate "MONITORED_FLOW_RATIO=${sampling_ratio}"
    mkdir -p "work/out_for_many_eval/ratio_${sampling_ratio}"
    mv work/log* work/out "work/out_for_many_eval/ratio_${sampling_ratio}"
    make clean
done

echo ""
echo "Done!"
echo "Complete results can be found at work/out_for_many_eval"

echo ""
echo "Results summary:"
for sampling_ratio in "${sampling_ratios[@]}"; do
    scores=$(grep -Po "Overall F1 score: .+" "work/out_for_many_eval/ratio_${sampling_ratio}/log/controller.log")
    echo "${sampling_ratio} => ${scores}"
done
