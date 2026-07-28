# Example heartbeat prompt

This is the prompt file referenced by the commented example in
`HEARTBEATS.md.template`. When a heartbeat fires, the dispatcher pipes this
file (plus the gathered JSON, appended under a "Gathered Data" heading) into
`opencode run`.

Replace this with real instructions for your heartbeat. Two conventions the
dispatcher understands in your OUTPUT:

1. Write your result as markdown. It lands in `briefings/YYYY-MM-DD-<name>.md`.
2. To ping the operator's Discord webhook, start the output with:

   ```
   notify: true
   summary: <one-line summary for the notification>
   ```

Task: read the gathered data below and reply with the single word OK if the
count field is greater than zero.
