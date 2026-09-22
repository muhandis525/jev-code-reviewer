# Third-party notices

The benchmark fetchers reference but do not redistribute two external corpora:

- OWASP Benchmark Java, GPL-2.0;
- Vul4J dataset metadata, CC-BY-4.0, and framework code, GPL-3.0.

Their source trees are downloaded only into the ignored `.benchmarks/`
directory. Users running those evaluations are responsible for their licenses.

This project invokes Semgrep as a separate command-line dependency. Semgrep
Community Edition is distributed under the GNU Lesser General Public License
2.1. See <https://github.com/semgrep/semgrep>.

The rules in `jev_code_reviewer/rules.yml` are original project rules and are
distributed under this project's Apache License 2.0. They do not copy Semgrep
Registry rules.

`--semgrep-config auto` is an explicit opt-in that downloads rules from the
Semgrep Registry. Those rules are governed by the Semgrep Rules License, not
this project's Apache License 2.0. Review <https://semgrep.dev/legal/rules-license/>
before commercial, competing, or hosted use.

Online triage uses TypeSafe AI's Jev service and is subject to TypeSafe's terms
and privacy policy. Users provide their own API key.
