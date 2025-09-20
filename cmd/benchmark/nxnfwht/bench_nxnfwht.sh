#!/bin/bash
# FWHT benchmark runner
set -e

EXPS=$(seq 10 18)           # exp range (10 ~ 30)
PROCS=(1)          # number of processes
ITERS=1                     # number of iterations
MODES=("rand")      # benchmark modes

# Run benchmarks
for mode in "${MODES[@]}"; do
  for exp in $EXPS; do
    for procs in "${PROCS[@]}"; do
      echo "Running FWHT: mode=$mode, procs=$procs, exp=$exp"
      go run main.go $exp $ITERS $procs $mode
    done
  done
done

echo "FWHT benchmark completed!"
