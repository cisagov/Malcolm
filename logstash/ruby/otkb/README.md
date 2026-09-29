# OTKB enrichment tests

These tests exercise `logstash/ruby/otkb_enrich.rb` without using or redistributing any real fixture records/rules. Every protocol, function, relationship, identifier, description, and ATT&CK ID in `fixtures/otkb_json_fixture.synthetic.json` is deliberately invented test data.

The suite uses a small dependency-free test runner instead of adding RSpec to the Logstash image. It uses the same Faraday and concurrent-ruby gems already available to the production filter.

## Run in the Logstash container

```bash
docker compose -f docker-compose.yml exec -T logstash \
  bash /usr/share/logstash/malcolm-ruby/otkb/run_otkb_enrich_tests.sh
```

The runner also accepts an explicit production script path:

```bash
bash /usr/share/logstash/malcolm-ruby/otkb/run_otkb_enrich_tests.sh /path/to/otkb_enrich.rb
```

## Inline startup tests

Several inline tests are also included in `/usr/share/logstash/malcolm-ruby/otkb_enrich.rb`. Logstash will run them whenever it creates the pipeline, and a failure will prevent the pipeline from starting.

```
logstash-1  | [2026-09-17T18:53:31,850][INFO ][logstash.filters.ruby.script] Test run complete {script_path: "/usr/share/logstash/malcolm-ruby/otkb_enrich.rb", results: {passed: 8, failed: 0, errored: 0}}
```

The inline fixture is embedded in the test block and contains only invented data. The inline tests share a snapshot built from that data under `https://otkb-inline-test.invalid/api/v1`, so the startup tests do not actually call a real OTKB API endpoint. The test runner constructs all test events before executing them, so the inline tests share one synthetic snapshot. That snapshot remains tagged with the `.invalid` test source URL. The live filter rejects it because its configured source URL differs and refreshes the cache normally on the first eligible event.

## Coverage

The suite checks:

- registration parsing for enable, URL, TTL, and TLS verification settings;
- Faraday base URL, `Authorization: Token`, JSON middleware, and SSL verification configuration;
- case-insensitive equality, decimal/hex equality, numeric ranges, nested AND/OR rules, and scores;
- safe non-matches for malformed, incomplete, or missing rules;
- fixture validation, transport and ATT&CK ID normalization, lookup indexes, and deep freezing;
- Zeek and Wireshark enrichment, relationship expansion, ECS threat fields, and copy isolation;
- most-specific match selection and deterministic UUID tie-breaking;
- IEC 104 symbolic ASDU normalization and the direct function index;
- initial API load, endpoint path, request timeouts, TTL reuse, refresh, failure fallback, and retry
  suppression;
- same-source sharing, different-source isolation, and concurrent first-use behavior.

The HTTP layer is intentionally faked. The suite never opens a network connection and the token is a nonfunctional synthetic value.
