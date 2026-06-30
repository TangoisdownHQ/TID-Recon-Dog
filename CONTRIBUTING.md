# Contributing

Thanks for your interest in TID-Recon-Dog.

## Dev setup

```sh
npm install
npm run build           # tsc + copies web assets to dist/
npm start               # all services + operator TUI
node dist/index.js serve-dashboard   # operator web GUI only
```

Docs live in [`docs/`](docs/README.md) — start with
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map.

## Guidelines

- **TypeScript** in `src/`; build with `npm run build` before committing.
- Match the surrounding style (ESM `.js` import specifiers, dependency-light).
- Keep the **two planes separate**: attacker-facing decoys must never expose the
  operator API/GUI, and responder output must pass through `responders/safety.ts`.
- New attacker-facing content goes through the deterministic responders /
  `fakeFilesystem.ts` / `webPanels.ts`; new operator features under `operator/`.
- Don't commit secrets, `runtime/` data, `node_modules/`, `dist/`, or model
  artifacts (see `.gitignore`).
- Test your change end-to-end (run the relevant service + hit it) before a PR.

## Pull requests

1. Branch off `main`.
2. Keep PRs focused; describe what changed and how you verified it.
3. Note any new env vars / endpoints in the README + `docs/`.
