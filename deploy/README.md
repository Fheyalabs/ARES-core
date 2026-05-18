# Homelab deployment

Recipes for running the three ARES-core example apps (auction,
ride-share, recurring cohort ranking) on a homelab that fronts
`api.fheya.de` / `auth.fheya.de`. Only one example service is active at
a time; switching is a `systemctl stop A && systemctl start B`.

## One-time setup

1. Install OpenFHE on the homelab and confirm `pkg-config --libs
   OPENFHEpke OPENFHEbinfhe OPENFHEcore` resolves. Same install Fheya
   uses today.

2. Build the binaries once:

   ```bash
   cd /opt/ares-core
   bash deploy/scripts/build.sh
   ```

   This produces:
   - `bin/openfhe-helper`          (built with `-tags openfhe`)
   - `bin/auction-service`         (stub-capable, helper-capable)
   - `bin/rideshare-service`
   - `bin/cohort-service`

3. Install the systemd units (root):

   ```bash
   sudo cp deploy/systemd/*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. Drop the Caddy snippet into your existing Caddyfile and reload:

   ```bash
   sudo cp deploy/caddy/api.fheya.de.snippet /etc/caddy/api.fheya.de
   sudo systemctl reload caddy
   ```

   The snippet routes `https://api.fheya.de` to whichever local port the
   active example service is listening on (default 8000). Auth requests
   continue to flow through whatever you already have for
   `auth.fheya.de`.

## Activating an app

Only one service runs at a time. To swap:

```bash
sudo bash /opt/ares-core/deploy/scripts/swap.sh auction
sudo bash /opt/ares-core/deploy/scripts/swap.sh rideshare
sudo bash /opt/ares-core/deploy/scripts/swap.sh cohort-formation
sudo bash /opt/ares-core/deploy/scripts/swap.sh cohort-weekly
```

`swap.sh` stops every `ares-*` unit, then starts the named one. Make
sure the Fheya production service is also stopped — the example apps
will conflict with it on api.fheya.de.

## Modes

Each service supports two scoring modes (set by env var; defaults to
helper mode in the systemd units):

| Mode | Effect | Use case |
|------|--------|----------|
| `ARES_HELPER_BINARY=…/bin/openfhe-helper` | Spawns the helper as a subprocess; PhaseArgmax/PhaseScore/PhaseArgmaxScoring run real CKKS argmax. | Production smoke. |
| Unset | Phases use stub bytes. | Wire-only smoke; helps debug transport without OpenFHE. |

To run a service in stub mode, edit the systemd unit and remove the
`Environment=ARES_HELPER_BINARY=...` line, or override at runtime:

```bash
sudo systemctl set-environment ARES_HELPER_BINARY=
sudo systemctl restart ares-auction
```

## Smoke from the Mac

The Python client lives in `clients/python/`. To run a smoke against the
homelab:

```bash
cd clients/python
pip install -e .
export ARES_SERVER=https://api.fheya.de
export ARES_WS_SECRET=<the same secret the systemd unit uses>
python -m ares_client \
    --config examples.auction_config \
    --participants 6 \
    --session-id auction-$(date +%s)
```

For a fully-real CKKS smoke that exercises the helper end-to-end
(including threshold keygen from Python), see
`clients/python/tests/test_openfhe.py::test_argmax_picks_winner` for the
shape — it does the complete N-party keygen + encrypt + argmax + threshold
decrypt + fuse, all via the helper IPC. A homelab-ready smoke runner
that combines `ARESSession` (WS to the session-service) with
`OpenFHEHelper` (subprocess for crypto) is the next step.

## Logs

Each service logs to `journalctl -u ares-<name>`. The hub's DROP / SKIP
/ client-removed / heartbeat-timeout logs are the production diagnostic
surface (validated by the Fheya smoke on conc=2 baseline).
