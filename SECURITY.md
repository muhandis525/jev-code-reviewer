# Security policy

This project is an alpha analysis tool. It can miss vulnerabilities and produce
false positives. Do not use it as the sole security control or as a replacement
for manual review, compiler checks, dependency scanning, or a mature SAST tool.

Online mode sends only redacted candidate metadata and a short source window to
TypeSafe AI. Redaction is best-effort, not a guarantee. Use `--offline` for code
that cannot leave the machine.

Never commit a Jev API key. Supply it through `TYPESAFE_API_KEY`, `JEV_API_KEY`,
or an explicit `--key-file` outside the repository.

Report vulnerabilities privately to the repository owner. Include a minimal
reproduction and avoid attaching real credentials or proprietary source code.
