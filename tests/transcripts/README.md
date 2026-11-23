# CLI transcripts

Each `.txt` file is a script of `pm` commands with their expected exit code and
output, run by `tests/cli_transcripts.rs`. Every file gets its own temporary
home, config, data directory and server port, and its server is stopped
afterwards. Files run in parallel.

```
# A comment line.
% file logins.csv          <- write a file into the sandbox ({root})
name,url,username,password
% end
$ pm --password-stdin add --name Example
< synthetic-password        <- a stdin line (repeatable)
? 0                         <- expected exit code (default 0)
Added "Example" ...         <- expected stdout
! warning text              <- expected stderr line
```

- **Wildcards:** `[..]` matches any text within a line, and a line containing
  only `...` matches any number of lines. Use them for generated passwords,
  codes, IDs and times.
- **Placeholders:** `{root}` is the sandbox directory and `{port}` is the server
  port. Both are substituted in commands and normalized in output, so
  transcripts are the same on every machine and OS.
- **Sandbox:** every command already runs with `--port {port}` and the
  sandbox's environment.
- **Updating expectations:** write the commands, then run
  `PM_BLESS=1 cargo test --test cli_transcripts`. It records the actual output
  for every step that doesn't match, and rewrites `UNCOVERED`. Review the diff,
  then replace volatile values with `[..]`.

`every_subcommand_has_a_transcript` walks `pm --help` and fails when a leaf
subcommand appears in no transcript. Commands still waiting for one are listed
in `UNCOVERED`. Remove a line there once a transcript runs that command.
