---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

`exec` and `openSession` take a secret env: variables for the process they start and no other.
The wire field is `ExecArgs.secret_env` (field 14) and `OpenSessionArgs.secret_env` (field 11), a
list of `SecretEnvVar { key, value }`. The client's `exec`, `execAttached` and `openSession` take
it as `secretEnv`.

The process gets each value exactly as sent, set over its `env`. sealantd masks the value in
everything it records of that process: stdout and stderr, a session's journal and input, the
events and the spool. The patterns are the process's own, so another process that prints the
same value is recorded as it wrote it. The exec-attach channel is a live forward that is never
recorded, and it carries the value as the process wrote it.

sealantd refuses a secret env with `invalid-argument`, and starts nothing, when an entry breaks a
rule. The error names the entry's index and the rule, never its name or value. Names follow
`[A-Za-z_][A-Za-z0-9_]*` and are at most 128 bytes. Values are 6 to 4096 bytes and hold no NUL. A
value that is part of `***REDACTED***`, starts with the marker's end or ends with its start is
refused, since a masked span beside it could complete it. A map holds at most 128 entries and
32 KiB. A duplicate name, a name also in `env`, a `SEALANT_` name, an identity name (`HOME`,
`USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `XDG_RUNTIME_DIR`, `PATH`, `TERM`), or a proxy variable
sealantd sets (`HTTP_PROXY`, `HTTPS_PROXY`, in any case) is refused rather than replaced.

`supports` names `process.secret-env.v1`. A daemon without it ignores the field, so the client
asks the daemon on the same connection first and throws, sending nothing, when the daemon does not
name it. `request()` applies the same check to any `exec` or `openSession` that carries
`secretEnv`, and sends the command as it was when called. A call without `secretEnv` is sent at
once, as before. The package exports the name as `SECRET_ENV_CAPABILITY`.
