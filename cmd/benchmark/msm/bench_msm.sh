#!/bin/bash

for exp in $(seq 10 30); do
  for procs in $(seq 1 10); do
    echo "Running exp=$exp, iters=1, procs=$procs"
    go run ../../msmtest $exp 1 $procs
  done
done
