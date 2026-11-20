#!/bin/bash
# selftest/plant-links.sh <suffix> - plant symlinks in /workspace that point
# at the server's own environment, as a model could from a script. The
# self-test then asks the server-run read and grep tools to follow them.
ln -sfn /proc/self/environ "/workspace/.selftest-link-$1" && ln -sfn /proc/1 "/workspace/.selftest-proc-$1" && echo selftest-ok
