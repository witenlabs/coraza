# Witen Coraza core companion

This experimental downstream branch starts from Coraza `v3.8.1`
(`9f8521398d1ff023b958fad0b944cac265763866`), the engine used by the Witen
Caddy connector. Upstream main is retained separately. The Apache-2.0 license,
history and attribution are preserved. This branch does not establish an upstream
maintainer role, a stable release or a security support promise.

The narrow runtime changes are:

- Return serial audit sink write errors instead of discarding them. Coraza's
  transaction debug logger can report the error independently of the failed sink
  when SecDebugLogLevel is at least 1 and its error output is enabled. HTTP remains
  governed by the rule engine and application; debug level 0 suppresses this signal.
- Close an initialized audit writer once when its WAF retires. Pending transactions
  retain it through logging and their own Close. The final transaction returns a
  deferred writer-close error; subsequent WAF Close calls retain that error.
- Release resources when NewWAF fails. This follows the construction cleanup
  already present on upstream main in `2080714`; the release predates that fix.

Stop creating transactions before WAF Close. Every transaction must be closed
exactly once, after ProcessLogging, as required by the transaction pooling API.
Closing a generation does not wait for its pending requests, and a nil return from
Close while requests remain is not proof that later writer cleanup succeeded.
Connectors must observe transaction-close errors too. The lifetime counter adds
one short mutex section when acquiring and releasing a transaction; representative
throughput qualification remains necessary.

The serial writer keeps its open file across renames. Rotate by renaming the old
file, creating the new target with the reviewed owner/mode, and forcing a Caddy
reload. The new generation opens the new target; old requests finish against the
renamed file. Wait for draining/readers before retiring it. There is no automatic
rotation, disk durability guarantee or delivery retry/spool in this patch.

The separate file-backed pmFromFile cache issue is unchanged. Qualified connector
builds continue to require `coraza.no_memoize`. Rules, redacting formatters,
Warden ingestion, health canaries and enforcement policy remain outside core.

CI uses Go 1.26.10. Run the default and no_memoize race suites, the full CRS tag
matrix, vet and lint before publishing a candidate. Passing these focused gates
does not qualify TinyGo/WASM/FIPS or a production rollout. The engine's retained
upstream automation is restricted to upstream; only Witen's verification workflow
runs here. No upstream issue, PR or maintainer offer is made by this fork.
