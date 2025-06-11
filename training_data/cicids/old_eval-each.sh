#!/usr/bin/env bash
set -euo pipefail

# Calls `make eval-simulate` and `make eval-results` for each day in the CICIDS dataset.
# The results are saved to work/log_<day> and are summarized to the standard output.
# Keep in mind that a single RF model will be used for each day: no retraining is executed.

days=$(for day in ./training_data/cicids/*/; do echo "$day"; done | xargs -l basename)
echo "Detected days: $days"

# Iterate over the days in the training_data/cicids directory and run the evaluation
for day in $days; do
  echo "Running day $day..."
  make eval-simulate EVAL_PCAP=training_data/cicids/"$day"/features.pcap
  make eval-results DATA_SOURCE=cicids DATA_PATH=training_data/cicids/"$day"
  mv work/log work/log_"$day"
done

echo ""
echo "Done!"
echo "Full log files can be found at: work/log/pcap_eval_*.log"

# Iterate over the days in the training_data/cicids directory and summarize the results
for day in $days; do
  echo ""
  echo "Summary of day $day:"
  grep "model_eval" -A 999 work/log_"$day"/pcap_eval.log
done

# Iterate over the days in the training_data/cicids directory and print the F1 scores
echo ""
echo "F1 scores for each day:"
for day in $days; do
  score=$(grep -Eo "F1 score: [^ ]+" work/log_"$day"/pcap_eval.log)
  echo "$day $score"
done
