#!/bin/bash
set -euo pipefail

# This script runs the evaluation three times.

# Cleaning the previous results
make clean-all

# Run the evaluation three times
for i in {1..3}; do
    echo "Running evaluation ${i}..."
    make eval-simulate
    mkdir -p "work/out_for_many_eval/${i}"
    mv work/log* work/out "work/out_for_many_eval/${i}"
    make clean
done

echo ""
echo "Done!"
echo "Complete results can be found at work/out_for_many_eval"

echo ""
echo "Results summary:"
for i in {1..3}; do
    scores=$(grep -Po "Overall F1 score: .+" "work/out_for_many_eval/${i}/log/controller.log")
    echo "${i} => ${scores}"
done
