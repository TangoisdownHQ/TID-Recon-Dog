AWS deployment artifacts are generated from the CLI:

```sh
npm run cloud:bundle
```

That command writes an `exports/cloud-bundle-*` directory containing:

- `ecs/task-definition.json`
- `s3/` runtime archives
- `sqs/` message envelopes
- `kinesis/` record envelopes

The checked-in repo stays provider-neutral while the generated bundle captures the current port map and runtime data.
