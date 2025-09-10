#!/bin/bash
set -e

EXPS=$(seq 10 30)           # exp range (10 ~ 30)
PROCS=(10)          # number of processes
ITERS=1                     # number of iterations
MODES=("const")      # benchmark modes: "const", "rand"

# Run benchmarks
for mode in "${MODES[@]}"; do
  for exp in $EXPS; do
    for procs in "${PROCS[@]}"; do
      echo "Running MSM: mode=$mode, procs=$procs, exp=$exp"
      go run ../../msmtest $exp $ITERS $procs $mode
    done
  done
done

echo "MSM benchmark completed!"
