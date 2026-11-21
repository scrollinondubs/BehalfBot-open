# Example heartbeat prompt

This is the prompt file referenced by the commented example in
`HEARTBEATS.md.template`. When a heartbeat fires, the dispatcher pipes this
file (plus the gathered JSON, appended under a "Gathered Data" heading) into
`opencode run`.

Replace this with real instructions for your heartbeat. Two conventions the
dispatcher understands in your OUTPUT:

1. Write your result as markdown. It lands in `briefings/YYYY-MM-DD-<name>.md`.
2. To ping the operator, start the output with `notify: true`. The
   dispatcher raises a Matrix alert naming the heartbeat and its output
   file. The alerts room is not end-to-end encrypted, so nothing you write
   is copied into it; the operator reads the output on Jill's side.

Task: read the gathered data below and reply with the single word OK if the
count field is greater than zero.
