#!/bin/bash

echo "io_uring Disk I/O Benchmark"
echo "=========================="
echo ""
echo "For accurate read performance measurements, run with sudo:"
echo "  sudo ./uring_disk_io"
echo ""
echo "This allows the benchmark to drop filesystem caches between write and read tests."
echo ""
echo "Running benchmark..."
echo ""

./uring_disk_io