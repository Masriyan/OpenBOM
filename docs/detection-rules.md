# Detection Rules

What the agent flags *without* an advisory: heuristic IOC scanning of package source, typosquat
detection, and the special handling of known-malicious advisories. All heuristic findings are
**investigation leads, not verdicts**.

| Finding id | Severity | Produced by |
|------------|----------|-------------|
| `MAL-*` (from OSV) | CRITICAL | OpenSSF malicious-packages advisory matched the installed version |
| `MALICIOUS_HEURISTIC` | CRITICAL (strong indicator) or HIGH (≥ 2 weak categories) | `scan_heuristics()` |
| `TYPOSQUAT_SUSPECT` | MEDIUM | `check_typosquat()` |

On the backend, heuristic ids are namespaced per package (`MALICIOUS_HEURISTIC::PyPI::colourama`)
because they are observations about one package, not global advisories.

## When heuristics run

| `--heuristics` | IOC source scan | Typosquat check |
|----------------|-----------------|-----------------|
| `new` (default) | PyPI/npm packages labelled `[NEW]`, `[UPGRADED]` or `[DOWNGRADED]` by `--diff` | same packages |
| `all` | every installed PyPI/npm package on the host | every PyPI/npm package |
| `off` | — | — |

The IOC scan reads **installed host packages only** (it needs files on disk). For `--path`, `--image`,
`--rootfs` and `--sbom` targets only the typosquat check applies. Without `--diff`, `new` scans nothing
and the agent logs a hint. On the very first `--diff` run every package is `[NEW]`, so the first run
doubles as a full baseline scan.

### Which files are read

* PyPI: the files recorded in the distribution's `RECORD` (`importlib.metadata`), falling back to the
  package directory in site-packages.
* npm: `$(npm root -g)/<package>`; its `package.json` install hooks are checked first.
* Suffixes: `.py .pth .js .mjs .cjs .sh`. At most 800 files per package, 512 KiB per file. Files are
  read as text and never executed. Symlinks are not followed.

## Indicator model

Real malware combines techniques (obfuscation, download-and-execute, exfiltration); legitimate code
often contains *one* suspicious-looking line (an AWS SDK mentions `~/.aws/credentials`, a clipboard
helper shells out to `powershell`). Rules are therefore split:

* **Strong** — malicious on its own → finding with severity **CRITICAL**.
* **Weak** — reported only when **at least two different weak categories** occur in the same package →
  severity **HIGH**. Weak hits inside test directories (`test/`, `tests/`, `testing/`, `__tests__/`,
  `spec/`) are ignored.

The model was tuned on a real workstation (565 PyPI/npm packages incl. botocore, pandas, torch, tqdm,
coverage, pycryptodome): zero false positives with `--heuristics all`.

### Strong indicators

| Label | Matches (case-insensitive) |
|-------|----------------------------|
| `eval(base64)` | `eval(base64…`, `eval(__import__('base64')…`, `eval(Buffer.from(…`, `eval(atob(…` |
| `exec(base64)` | `exec(base64…`, `exec(__import__('base64')…`, `exec(zlib.decompress…`, `exec(marshal.loads…` |
| `os.system(url)` | `os.system("http…")`, `os.system("curl …")`, `os.system("wget …")` |
| `reverse_shell` | `/dev/tcp/<host>/<port>`, `pty.spawn("/bin/sh")` / `("/bin/bash")` |
| `crypto_miner` | `stratum+tcp://`, `xmrig`, `coinhive` |
| npm install hook (download-exec) | `preinstall`/`install`/`postinstall`/`prepare` script piping `curl`/`wget` into `sh`/`bash`, or using `/dev/tcp/` |

### Weak indicators

| Label | Matches |
|-------|---------|
| `subprocess+download` | `subprocess.<fn>(["curl"…` / `"wget"` / `"powershell"` |
| `child_process+download` | `.exec/.execSync/.spawn/.spawnSync("curl…` / `wget` / `powershell` / `bash -c` / `sh -c` |
| `paste/tunnel C2` | `pastebin.com/raw`, `ngrok.io`, `ngrok-free.app`, `paste.ee`, `transfer.sh`, `pipedream.net`, `interact.sh`, `oast.{fun,live,me,pro,site}` |
| `chat exfil webhook` | `discord.com/api/webhooks/`, `discordapp.com/api/webhooks/`, `api.telegram.org/bot` |
| `credential_access` | `.ssh/id_rsa`/`id_ed25519`/`id_ecdsa`, `.aws/credentials`, `Login Data`, `.config/google-chrome` |
| `suspicious_import` | `__import__('socket')`, `('ctypes')`, `('winreg')` |
| `.pth auto-exec` | a `.pth` file with an `import …` line (except `distutils-precedence`, `*-nspkg`, `_virtualenv`, `__editable__*`) |
| npm install hook (other) | install hook containing `curl`, `wget`, `node -e`, `base64`, a URL or `powershell` (without piping to a shell) |

Example: a package that reads `~/.ssh/id_rsa` **and** posts to a Discord webhook → HIGH
("credential_access" + "chat exfil webhook"). A package that only mentions `.aws/credentials` → nothing.

The finding summary lists up to five `rule in file:line` locations; the full list (max 10) is in the debug log.

## Typosquat detection

A PyPI/npm package is flagged when its normalised name is **exactly one edit** (insertion, deletion,
substitution or adjacent transposition — optimal string alignment distance) away from a name in the
built-in popular list, and:

* the name has at least 5 characters (short names collide too often),
* it is not itself a popular name,
* it is not scoped (`@scope/x`),
* it is not on the allowlist of legitimate look-alikes.

PyPI names are normalised per PEP 503 (`Python_DateUtil` → `python-dateutil`).

Allowlist (known-legitimate near-neighbours):

* PyPI: `pyaml requests-oauthlib colorlog termcolor jinja pillow-heif gsutil pycryptodomex unicorn scapy torchx psycopg fastai cchardet dockerx requests3 httpx2 paramiko-ng pyjwt2`
* npm: `preact color requests mysql2 classname chalk-template eslint-scope react-is rollup-plugin async-each debug-log colors-option`

## Known-malicious packages (OSV `MAL-*`)

OpenSSF's malicious-packages project publishes advisories in OSV format with ids starting `MAL-`.
They carry **no severity**, so most tools show them as "unknown". OpenBOM:

* sets severity **CRITICAL** and `is_malicious = true` (also when a GHSA record aliases a `MAL-` id),
* replaces the recommendation with "REMOVE … NOW — treat the host as compromised",
* sorts them before every other finding, adds +30 to the asset risk score,
* always exits with code 2 (unless `--fail-on never`), alerts via webhook and shows a red banner in the console.

Withdrawn advisories (OSV `withdrawn` field) are ignored — OSV has withdrawn automated false positives before.

## Tuning

| Goal | How |
|------|-----|
| Silence a reviewed heuristic hit | `.openbomignore`: `MALICIOUS_HEURISTIC <package>  # reviewed, ticket X` (or triage it as `false_positive` in the console) |
| Silence a reviewed typosquat | `TYPOSQUAT_SUSPECT <package>` in the ignore file |
| Add a rule | Append an `IocRule(label, strong, pattern)` to `HEURISTIC_RULES`; add a positive case to `test_scan_content_rules` and a legit-code negative case |
| Add a popular name / allowlist entry | Edit `POPULAR_PACKAGES` / `TYPOSQUAT_ALLOWLIST` and extend `test_typosquat_detected` / `test_typosquat_not_flagged` |

After changing rules, re-run `--heuristics all` on a real machine and confirm no new false positives.
