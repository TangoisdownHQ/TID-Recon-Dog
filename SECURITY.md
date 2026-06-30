# Security Policy

## Intended use

TID-Recon-Dog is a **defensive deception platform** (honeypot + CTI). It is meant
to be deployed on infrastructure you own or are explicitly authorized to operate,
to observe and analyze unsolicited/malicious activity. It also contains dual-use
capabilities (fake credentials, an explorable decoy filesystem, attacker
interaction). Use it lawfully and only where you have authorization. Do not use
it to entrap, target third parties, or in violation of your provider's AUP.

## Operating it safely

- Keep the **operator plane private** — bind it to localhost / ClusterIP and
  reach it over SSH/SSM port-forward or an authenticated ingress. Never expose
  the operator API/GUI to the internet.
- Set a strong `OPERATOR_TOKEN` (don't rely on the auto-generated one in prod).
- All attacker-facing credentials, hosts, and files in this repo are **fake**.
- Do not commit real secrets — `runtime/`, `.env`, host keys, and model
  artifacts are git-ignored.

## Reporting a vulnerability

If you find a security issue in this project (e.g., the honeypot leaking host
secrets, the operator plane being reachable when it shouldn't be, or a way to
fingerprint/escape the deception):

- **Do not** open a public issue.
- Report it privately to the maintainer via GitHub (open a private security
  advisory on the repository, or contact `contact@tidhq.net`).

Please include reproduction steps and the commit/version. We aim to acknowledge
reports within a few days.
