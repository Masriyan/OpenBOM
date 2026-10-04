# CI/CD Integration

The agent is a single file with three pip dependencies, so it drops into any pipeline. In CI you
normally scan the **repository** (`--path`) or the **built image** (`--image`), publish SARIF and let
the exit code gate the build.

## Building blocks

| Need | Flags |
|------|-------|
| Scan the checkout | `--path .` (implies `--check-osv`) |
| Scan the built image | `--image "$IMAGE"` (needs podman or docker on the runner) |
| Code-scanning annotations | `--sarif openbom.sarif` |
| SBOM artefacts | `--cyclonedx sbom.cdx.json --spdx sbom.spdx.json` |
| Gate on severity | `--fail-on critical` (KEV, known-malicious and license violations always fail) |
| License policy | `--license-deny GPL-3.0,AGPL,SSPL` |
| Accepted risks | `--vex .openbom/openvex.json --ignore .openbomignore` |
| Report to the fleet console | `--server-url "$OPENBOM_URL" --api-key "$OPENBOM_API_KEY"` |
| Faster repeat runs | cache `$OPENBOM_STATE_DIR` (OSV/KEV/EOL caches) between jobs |

Exit code `2` fails the job; `1` means the scan itself could not run (no packages, bad VEX file).

## GitHub Actions

```yaml
name: openbom
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      OPENBOM_STATE_DIR: ${{ github.workspace }}/.openbom-cache
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}

      - name: Fetch OpenBOM agent
        run: |
          git clone --depth 1 https://github.com/Masriyan/OpenBOM.git /tmp/openbom
          pip install httpx rich jinja2 packaging

      - uses: actions/cache@v4
        with:
          path: .openbom-cache
          key: openbom-${{ runner.os }}-${{ github.run_id }}
          restore-keys: openbom-${{ runner.os }}-

      - name: OpenBOM scan
        run: |
          python3 /tmp/openbom/agent/openbom_agent.py \
            --path . --no-eol \
            --sarif openbom.sarif --cyclonedx sbom.cdx.json \
            --license-deny AGPL,SSPL --fail-on critical \
            --output-dir openbom-out

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: openbom.sarif, category: openbom}

      - uses: actions/upload-artifact@v4
        if: always()
        with: {name: openbom, path: "openbom-out\nsbom.cdx.json\nopenbom.sarif"}
```

The SARIF results appear under *Security → Code scanning*, located at the lockfile that introduced the
package (e.g. `web/package-lock.json`).

## GitLab CI

```yaml
openbom:
  image: python:3.12-slim
  variables:
    OPENBOM_STATE_DIR: "$CI_PROJECT_DIR/.openbom-cache"
  cache:
    key: openbom
    paths: [.openbom-cache]
  script:
    - apt-get update -qq && apt-get install -y -qq git >/dev/null
    - git clone --depth 1 https://github.com/Masriyan/OpenBOM.git /tmp/openbom
    - pip install -q httpx rich jinja2 packaging
    - python3 /tmp/openbom/agent/openbom_agent.py --path . --no-eol
        --sarif gl-openbom.sarif --cyclonedx gl-sbom.cdx.json --fail-on high
  artifacts:
    when: always
    paths: [gl-openbom.sarif, gl-sbom.cdx.json, output/]
    reports:
      cyclonedx: gl-sbom.cdx.json
```

## Jenkins (declarative)

```groovy
pipeline {
  agent any
  environment { OPENBOM_API_KEY = credentials('openbom-api-key') }
  stages {
    stage('OpenBOM') {
      steps {
        sh '''
          python3 /opt/openbom/agent/openbom_agent.py --image "$IMAGE" \
            --sarif openbom.sarif --fail-on critical \
            --server-url https://openbom.internal --hostname "ci:${JOB_NAME}"
        '''
      }
      post { always { archiveArtifacts artifacts: 'openbom.sarif, output/**', allowEmptyArchive: true } }
    }
  }
}
```

## Scanning images built in the pipeline

```bash
docker build -t app:$GIT_SHA .
python3 openbom_agent.py --image app:$GIT_SHA --fail-on critical --sarif image.sarif
```

The image is unpacked with `docker create` + `docker export` into a temporary directory that is
deleted afterwards. OS packages are matched for Debian, Ubuntu, AlmaLinux, Rocky Linux and Alpine bases.

## Tips

* `--no-eol` keeps CI output focused on the code; EOL matters for images and hosts.
* Use `--diff` on long-lived branches to report only packages that changed since the previous run
  (the baseline is stored per target in the cached state dir).
* Pin the agent to a tag or commit instead of `--depth 1` of the default branch for reproducible builds.
* Keep `.openbomignore` entries short-lived (`until=`); expired entries fail the build again.
