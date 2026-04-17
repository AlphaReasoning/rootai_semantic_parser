# Evidence of Reproducible Findings

The following findings were produced against real repositories available in the local workspace using the packaged CLI. They are **technical validation artifacts**: reproducible, non-trivial taint paths on real codebases. They are **not** proof of confirmed vulnerabilities or exploitability.

Verification levels:

- `L1`: tool runs
- `L2`: findings are reproducible
- `L3`: findings are correct true positives
- `L4`: findings are exploitable

This document demonstrates `L2`, not `L3/L4`.

## Commands

```bash
/home/alphareasoning/.venv-rootai/bin/python -m rootai_semantic_parser \
  --profile bugbounty \
  --quick-mode \
  --min-score 70 \
  /home/alphareasoning/envoy \
  ci-scan \
  --format bounty-json
```

```bash
/home/alphareasoning/.venv-rootai/bin/python -m rootai_semantic_parser \
  --profile bugbounty \
  --quick-mode \
  --min-score 70 \
  /home/alphareasoning/workflow \
  ci-scan \
  --format bounty-json
```

## Reproducible Findings

1. `envoy/mobile/library/java/org/chromium/net/impl/CronvoyUrlRequestContext.java:390`
   Potential Impact: `Potential RCE`
   Exploitability: `unconfirmed`
   Explainability: `CronvoyUrlRequestContext.java -> run -> postObservationTaskToExecutor`

2. `envoy/mobile/library/python/envoy_mobile/async_client/client.py:42`
   Potential Impact: `Potential RCE`
   Exploitability: `unconfirmed`
   Explainability: `_send_request -> self -> __aenter__ -> AsyncioExecutor`

3. `envoy/test/integration/python/hotrestart_handoff_test.py:185`
   Potential Impact: `Potential RCE`
   Exploitability: `unconfirmed`
   Explainability: `request_url -> _full_http_request -> url -> asyncio.create_subprocess_exec`

4. `envoy/mobile/test/java/org/chromium/net/testing/TestUrlRequestCallback.java:348`
   Potential Impact: `Potential RCE`
   Exploitability: `unconfirmed`
   Explainability: `TestUrlRequestCallback.java -> maybeThrowCancelOrPause -> checkExecutorThread`

5. `workflow/packages/builders/src/esbuild-tsconfig.test.ts:17`
   Potential Impact: `Potential generic taint sink`
   Exploitability: `unconfirmed`
   Explainability: `buildInputs -> writeFile`

## Notes

- These findings demonstrate that the engine surfaces non-trivial taint paths on large real codebases.
- They still require analyst validation before being treated as true positives or exploitable vulnerabilities.
- The feedback loop can now ingest analyst verdicts and tune future ranking.
- A full security validation pass would need source controllability proof, sanitization review, and PoC validation for selected findings.
