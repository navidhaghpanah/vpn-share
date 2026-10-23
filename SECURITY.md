# Security status

The pre-remediation 0.4.2 source audit found one high and two medium issues. Build 0.4.3 addresses:

- Elevated PowerShell search-path resolution: use the absolute Windows system executable. A same-name working-directory regression check passes.
- Installer validation race: copy/download into an administrator/SYSTEM-owned protected directory, verify its digest and signature, and retain a read handle denying write/delete until installation ends. Tampered-digest rejection passes; elevated storage self-test awaits live execution.
- Linux DNS resource exhaustion: absolute frame deadlines and per-client concurrency budgets. Deterministic deadline and fairness tests pass.

Additional hardening rejects untrusted owners/reparse points for protected state. The source audit is not a penetration-test certification. Real client leak/drop/recovery tests remain pending. Do not expose diagnostics publicly without reviewing local adapter names, addresses and hardware identifiers. Wi-Fi passwords are excluded from exported diagnostics.
