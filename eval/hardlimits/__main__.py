"""`python3 /root/job`: the hard-limit eval with a neutral command line
(red-team round 7 R3-2). /proc/<pid>/cmdline is world-readable, so the
model could otherwise read `run_eval.py --mode live --out ...` from the
process list. With no arguments, the options come from the file named by
JOB_ARGS (live.args or stub.args here), which sits under root-only /root
and which the harness checks uid 1000 cannot read. Arguments, if given,
are used as they are (local runs).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval  # noqa: E402

if len(sys.argv) > 1:
    sys.exit(run_eval.main())
path = os.environ.get("JOB_ARGS")
if not path:
    print("[hardlimit-eval] no arguments and no JOB_ARGS: name an options file (eval/hardlimits/live.args)", file=sys.stderr)
    sys.exit(2)
try:
    opts = run_eval.options_from_file(path)
except (OSError, ValueError) as exc:
    print("[hardlimit-eval] cannot read the options file: %s" % exc, file=sys.stderr)
    sys.exit(2)
sys.exit(run_eval.main(opts, options_file=path))
