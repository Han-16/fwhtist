#!/bin/bash
# FWHT benchmark runner
set -e

EXPS=$(seq 29 30)           # exp range (10 ~ 30)
PROCS=(1 3 5 7 10)          # number of processes
ITERS=1                     # number of iterations
MODES=("const")      # benchmark modes

# Run benchmarks
for mode in "${MODES[@]}"; do
  for exp in $EXPS; do
    for procs in "${PROCS[@]}"; do
      echo "Running FWHT: mode=$mode, procs=$procs, exp=$exp"
      go run ../../fwhtbench $exp $ITERS $procs $mode
    done
  done
done

echo "FWHT benchmark completed!"
