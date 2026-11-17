# Benchmarks

`python bench/run.py` runs the three example requests against the example vendor master 20,000 times.

On a shared 2-vCPU Linux box with CPython 3.13: about 13,000 checks per second. The check is not on any hot path; it runs once per payment, before the send.
