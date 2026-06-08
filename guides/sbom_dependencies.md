# How to create an SBOM from a Cabal plan on GitHub

For projects hosted on GitHub, you can create a **Software Bill of Materials** (SBOM) file with information about dependencies.

Steps:

1. Enable Dependency Submission for the GitHub project: `Insights` > `Dependency graph`.

2. Add a GitHub workflow, for example `.github/workflows/dependency-graph.yml`, using [cabal-plan-submit](https://github.com/dancewithheart/cabal-plan-submit):

```yaml
name: Dependency submission

on:
  push:
    branches: [master, main]
  pull_request:
  workflow_dispatch:

concurrency:
  group: dependency-submission-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: write          # dependency submission API

jobs:
  submit-dependencies:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout target project
        uses: actions/checkout@v6
        with:
          path: project

      - name: Checkout cabal-plan-submit
        uses: actions/checkout@v6
        with:
          repository: dancewithheart/cabal-plan-submit
          path: cabal-plan-submit

      - name: Setup Haskell
        uses: haskell-actions/setup@v2
        with:
          ghc-version: "9.6.7"
          cabal-version: "3.14"

      - name: Cache Cabal store
        uses: actions/cache@v4
        with:
          path: |
            ~/.cabal/store
            ~/.cabal/packages
            cabal-plan-submit/dist-newstyle
            project/dist-newstyle
          key: ${{ runner.os }}-ghc-9.6.7-cabal-3.14-${{ hashFiles('project/**/*.cabal', 'project/cabal.project*', 'cabal-plan-submit/**/*.cabal', 'cabal-plan-submit/cabal.project*') }}
          restore-keys: |
            ${{ runner.os }}-ghc-9.6.7-cabal-3.14-

      - name: Build target project
        working-directory: project
        run: cabal build all --dry-run

      - name: Build cabal-plan-submit
        working-directory: cabal-plan-submit
        run: cabal build exe:cabal-plan-submit

      - name: Render and validate dependency snapshot
        working-directory: project
        env:
          SHA: ${{ github.sha }}
          REF: ${{ github.ref }}
        run: |
          BIN="$(cd ../cabal-plan-submit && cabal list-bin exe:cabal-plan-submit | tail -n 1)"
          "$BIN" render-snapshot dist-newstyle/cache/plan.json "$SHA" "$REF" > ../snapshot.json
          "$BIN" validate-snapshot ../snapshot.json

      - name: Submit dependency snapshot
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REPO: ${{ github.repository }}
        run: |
          owner="${REPO%/*}"
          repo="${REPO#*/}"

          response="$(
            curl \
              --fail-with-body \
              -X POST \
              -H "Accept: application/vnd.github+json" \
              -H "Authorization: Bearer $GITHUB_TOKEN" \
              -H "X-GitHub-Api-Version: 2022-11-28" \
              "https://api.github.com/repos/$owner/$repo/dependency-graph/snapshots" \
              --data-binary @snapshot.json
          )"

          echo "$response" | jq .

          snapshot_id="$(echo "$response" | jq -r '.id')"
          snapshot_url="https://api.github.com/repos/$owner/$repo/dependency-graph/snapshots/$snapshot_id"

          echo "Snapshot API URL: $snapshot_url"
          echo "Snapshot result: $(echo "$response" | jq -r '.result')"
          echo "Snapshot message: $(echo "$response" | jq -r '.message')"
```

This workflow runs `cabal build all --dry-run` to create Cabal's `plan.json`, transforms the plan into a GitHub dependency snapshot, validates the snapshot, and submits it using the [GitHub Dependency Submission API](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/use-dependency-submission-api).

The workflow logs also print the snapshot API URL, which can be queried with a GET request.

3. After a successful workflow run, `Insights` > `Dependency graph` should be populated with dependencies. You can then download the SBOM by clicking `Export SBOM`.
