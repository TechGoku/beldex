# Beldex Light Wallet Server

The light wallet server (LWS) lets wallets see their balance and transaction
history without holding the blockchain themselves. It scans the chain against
every registered account, stores what it finds in an LMDB database, and serves
the [lightwallet REST API](lightwallet_rest.md).

It is made up of four binaries:

| Binary | Purpose |
|---|---|
| `beldex-lws-daemon` | Scans the chain and serves the REST API |
| `beldex-lws-admin` | Inspects and administers the database from the command line |
| `beldex-lws-backup` | Takes verified backups while the server keeps running |
| `beldex-lws-rebuild` | Rescans or rolls back into a new database, with no downtime |

Every one of them has a detailed `--help`. This document covers how they fit
together and the procedures you will actually run.

---

## Contents

- [Requirements](#requirements)
- [Building](#building)
- [Quick start](#quick-start)
- [beldex-lws-daemon](#beldex-lws-daemon)
- [beldex-lws-admin](#beldex-lws-admin)
- [beldex-lws-backup](#beldex-lws-backup)
- [beldex-lws-rebuild](#beldex-lws-rebuild)
- [Procedures](#procedures)
- [Operational notes](#operational-notes)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- A synced `beldexd` the LWS can reach over JSON-RPC. It does not have to be on
  the same machine, but a local one is faster and avoids exposing the RPC port.
- Disk for the LWS database, which grows with accounts and their outputs — it
  is far smaller than the blockchain itself.
- The LWS and `beldexd` must be on the **same network**. Pointing a mainnet
  database at a testnet daemon is refused at startup.

> **Set `--db-path` explicitly on anything but mainnet.** The default is
> `~/.beldex/light_wallet_server` and it does **not** change with `--network`,
> so a testnet and a mainnet server left on the default would both open the
> same directory.

---

## Building

The LWS binaries are built from the main Beldex tree:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target \
    beldex-lws-daemon beldex-lws-admin beldex-lws-backup beldex-lws-rebuild \
    -j$(nproc)
```

They are written to `build/bin/`.

To build and run the LWS test suite as well:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
cd build && ctest -R "lws-"
```

---

## Quick start

A local test server, with both REST ports on loopback:

```bash
# 1. beldexd, already running and synced
beldexd --testnet --non-interactive

# 2. the light wallet server
beldex-lws-daemon --network test \
    --db-path ~/.beldex/testnet/light_wallet_server \
    --daemon http://127.0.0.1:29091 \
    --rest-server http://127.0.0.1:8090 \
    --admin-rest-server http://127.0.0.1:8091

# 3. confirm it is scanning
beldex-lws-admin --network test \
    --db-path ~/.beldex/testnet/light_wallet_server list_accounts
```

Wallets register themselves by calling `/login` on the public REST port. There
is nothing to create by hand.

---

## beldex-lws-daemon

The server itself. It runs two independent things in one process: a pool of
scan threads that walk the chain, and a REST server that answers wallets.

### Setting it up

```bash
beldex-lws-daemon \
    --db-path /var/lib/beldex-lws \
    --daemon http://127.0.0.1:19091 \
    --rest-server https://0.0.0.0:8443 \
    --rest-ssl-key /etc/beldex-lws/key.pem \
    --rest-ssl-certificate /etc/beldex-lws/cert.pem \
    --admin-rest-server http://127.0.0.1:8091 \
    --confirm-external-bind
```

Key points:

- **`--rest-server` defaults to `https`**, so it needs `--rest-ssl-key` and
  `--rest-ssl-certificate`. Use an `http://` address for local testing.
- **`--confirm-external-bind`** is required to bind a non-loopback address over
  plain http. It exists to stop you exposing an unencrypted wallet API by
  accident.
- **`--admin-rest-server` is off unless you pass it.** See
  [Operational notes](#operational-notes) before enabling it.

### Failover

`--daemon-backup` takes a comma-separated list of additional `beldexd`
endpoints. If the primary becomes unreachable, both the scanner and the REST
tier fail over to the next one, so a `beldexd` restart does not take every
wallet's balance query down with it.

```bash
--daemon http://127.0.0.1:19091 \
--daemon-backup http://10.0.0.2:19091,http://10.0.0.3:19091
```

`--daemon-spread` additionally fans the scan threads across every endpoint at
once. It only helps when accounts sit at genuinely different heights — during a
bulk catch-up, for instance. In steady state the threads all request the same
blocks and the shared fetch cache already collapses those into one request.

### Config file

Any option can go in a file instead of on the command line:

```ini
# /etc/beldex-lws/lws.conf
db-path=/var/lib/beldex-lws
daemon=http://127.0.0.1:19091
rest-server=https://0.0.0.0:8443
admin-rest-server=http://127.0.0.1:8091
```

```bash
beldex-lws-daemon --config-file /etc/beldex-lws/lws.conf
```

---

## beldex-lws-admin

Acts on the database directly, without going through the running server.

```bash
beldex-lws-admin [options] <command> [arguments]
```

Commands marked `*` in `--help` open the database **read-only**: they never take
the LMDB writer lock and cannot modify a byte, so they are safe to run against
the database a live daemon is writing.

| Read-only (safe on a live server) | What it does |
|---|---|
| `list_accounts` | Accounts with their scan heights |
| `list_requests` | Requests awaiting approval |
| `list_admin` | Accounts that may make admin calls |
| `export_accounts <file>` | Addresses, view keys and heights — **contains secrets** |
| `debug_database` | Whole database as JSON |
| `compact <dest>` | Compacted copy of the database |
| `retire_db <path> confirm` | Permanently deletes a *different*, unused database |

Everything else — `add_account`, `rescan`, `rollback`, `import_accounts`,
`accept_requests`, `modify_account_status` — opens the database read-write and
will stall a running daemon's scanner for as long as it takes. The tool warns
you when you run one.

### Creating the admin key

Admin REST calls are authorised by the view key of an account flagged as admin:

```bash
beldex-lws-admin --db-path /var/lib/beldex-lws create_admin
```

It prints an address and a `key`. Save that key somewhere only root can read —
it authorises administering the server, including replacing its database:

```bash
echo '<key>' > /etc/beldex-lws/admin.key
chmod 600 /etc/beldex-lws/admin.key
```

`create_admin` opens the database read-write, so run it during a quiet moment
or before starting the daemon.

---

## beldex-lws-backup

Takes a consistent backup of a database that is being actively written.

The source is opened read-only, so the backup never takes the writer lock and
cannot slow or modify the running server. Each backup is written to a
`.partial` directory, opened and read back exactly the way the daemon would
open it, and renamed only once that succeeds — an interrupted run cannot leave
behind something that looks like a good backup.

One backup now, for a cron job or systemd timer:

```bash
beldex-lws-backup \
    --db-path /var/lib/beldex-lws \
    --backup-path /var/backups/beldex-lws \
    --once
```

Or run it as a service, every 6 hours, keeping the newest 14:

```bash
beldex-lws-backup \
    --db-path /var/lib/beldex-lws \
    --backup-path /var/backups/beldex-lws \
    --interval-hours 6 --keep 14
```

`--keep` only ever deletes once a **new** backup has been verified, so a failed
run can never be the reason a good backup is removed. `--keep 0` deletes
nothing.

### Restoring

A backup is an ordinary LWS database. Point the daemon at it:

```bash
beldex-lws-daemon --db-path /var/backups/beldex-lws/lws-backup-20260913-162634
```

It will catch up from wherever the backup left off.

---

## beldex-lws-rebuild

Rescans every account into a **new** database while the live server keeps
serving.

Rescanning in place is an outage: it holds the writer lock and drags accounts
backwards while it runs. This builds a second database instead — the *shadow* —
in its own LMDB environment. The live database is opened read-only and never
modified, so throughout the rebuild the server keeps serving balances,
accepting transactions and registering new accounts.

The shadow starts empty, so every output is rebuilt from the chain: a wrong row
cannot survive. Accounts that register while the rebuild runs are picked up and
seeded at their own start height.

```bash
beldex-lws-rebuild \
    --db-path /var/lib/beldex-lws \
    --shadow-path /var/lib/beldex-lws-rebuilt \
    --daemon http://127.0.0.1:19091 \
    --rescan-height 0
```

`--rescan-height 0` rebuilds from the very start of the chain. **A rollback is
the same command with a lower height** — there is no separate rollback
operation and no long-held transaction.

### Watching it

It prints progress on its own cadence:

```
progress: scanned 1,204,000 / 4,193,021 (28.71%) | 23 account(s) | +12,345 blocks in 30s (411/s) | eta 2h 1m
```

Progress is measured by how far the **accounts** have been scanned, not by the
shadow's block table — the latter reaches the daemon's tip within seconds and
then never moves. The furthest-behind account is what decides when the rebuild
is done.

Check from another shell at any time:

```bash
beldex-lws-rebuild --db-path /var/lib/beldex-lws \
    --shadow-path /var/lib/beldex-lws-rebuilt --status
```

### Stopping and resuming

Stopping is safe at any point. Every scanned batch is committed before it
exits, and **re-running the same command resumes from where it stopped**. On a
resume it says so:

```
RESUMING an existing rebuild: 23 account(s) already scanned to height 1,774,000
    (1,764,000 blocks done, 2,419,021 to go)
```

`--rescan-height` must stay the same across resumes. Changing it is refused,
because resuming at a different height would leave a database rebuilt from two
different points.

### Cutting over

When the shadow has caught up, the running daemon is switched onto it. The
switch happens **inside the daemon** — it is a separate process, and only it can
change which database its own handlers and scanner read from.

Automatically, as part of the rebuild:

```bash
beldex-lws-rebuild \
    --db-path /var/lib/beldex-lws \
    --shadow-path /var/lib/beldex-lws-rebuilt \
    --daemon http://127.0.0.1:19091 \
    --switch-when-ready \
    --switch-admin http://127.0.0.1:8091 \
    --switch-admin-key-file /etc/beldex-lws/admin.key \
    --switch-backup-path /var/backups/beldex-lws
```

Or by hand, whenever you choose:

```bash
curl -X POST http://127.0.0.1:8091/switch_db \
  -H 'Content-Type: application/json' \
  -d '{"auth":"<admin view key>",
       "params":{"path":"/var/lib/beldex-lws-rebuilt",
                 "backup_path":"/var/backups/beldex-lws"}}'
```

Both take the identical path through the daemon. Before it switches, the daemon:

1. Checks that every live account and every pending request exists in the
   incoming database, that the chain has caught up, and that no account is
   still mid-scan.
2. Takes a **verified backup of the database it is leaving**, and abandons the
   whole switch if that fails.
3. Briefly pauses *account creation only* — reads, balance queries and
   transaction submission are never paused — re-checks for anything registered
   during the backup, and swaps.

Listening sockets are never closed and in-flight requests finish against the
database they started on, so no request is dropped.

Requirements for the cutover:

- The daemon must have been started with `--admin-rest-server`.
- It must be a build new enough to have `/switch_db`; older builds return 404.

### Afterwards

The database that was switched away from is **left in place**, so reverting is
another `/switch_db` pointed back at it. Restart the daemon with `--db-path`
pointing at the new database so it comes back on the right one.

Nothing in the rebuild or switch ever deletes a database. Removing an old one
is a separate, deliberate act:

```bash
beldex-lws-admin retire_db /var/lib/beldex-lws-old confirm
```

---

## Procedures

### Rescan every account with no downtime

1. Build the shadow and let it catch up:
   `beldex-lws-rebuild --shadow-path <new> --daemon <url> --rescan-height 0`
2. Watch `--status` until it reports `ready: yes`.
3. Cut over with `--switch-when-ready`, or by calling `/switch_db`.
4. Restart the daemon with `--db-path <new>`.
5. Once you are satisfied, `beldex-lws-admin retire_db <old> confirm`.

Leave the rebuild running until you switch, so the shadow keeps following the
tip and keeps picking up new accounts.

### Roll back to a height

Exactly the procedure above with `--rescan-height <height>`.

### Move a server to new hardware

```bash
# on the old server
beldex-lws-admin --db-path <old db> export_accounts accounts.json

# on the new one, after it has synced a chain
beldex-lws-admin --db-path <new db> import_accounts accounts.json 0
```

The export carries addresses, view keys, heights and account status — enough to
rebuild the whole database from chain. **It contains secret view keys**; it is
written `0600`, and should be moved over a secure channel and deleted after.

### Inspect a live server safely

Every read-only command works against the live database with no interruption:

```bash
beldex-lws-admin --db-path /var/lib/beldex-lws list_accounts
beldex-lws-admin --db-path /var/lib/beldex-lws list_requests
```

---

## Operational notes

**The admin port is dangerous.** Anyone who can reach `--admin-rest-server` and
holds an admin view key can register accounts, trigger rescans, and replace the
database the server runs on. Bind it to loopback and reach it over SSH, or put
it behind something that authenticates.

**Keep the admin key out of `ps`.** `beldex-lws-rebuild` reads it from
`--switch-admin-key-file` rather than an argument for exactly this reason: a
command line is visible to every user on the machine.

**Exports contain secrets.** `export_accounts` writes view keys in plaintext.
It is created `0600`; treat it like a key file.

**Run tools as the daemon's user.** The database files are `0600`, and even a
read-only LMDB open must write a reader slot into `lock.mdb`.

**One writer at a time.** LMDB allows a single writer across the whole
database. Read-only tools are unaffected, but any read-write admin command
competes with the scanner for that lock.

**Stop cleanly.** `SIGTERM` and `SIGINT` are handled: in-flight transactions are
released and reader slots freed. A `SIGKILL` leaves stale reader slots behind,
which block LMDB from reclaiming freed pages until they are swept. The daemon
sweeps them at startup and periodically thereafter.

---

## Troubleshooting

**`parse error ... last read: 'N'` in the logs**
The `--daemon` URL is wrong. `beldexd` answered with a non-JSON "Not found".
Both the bare address and the full `/json_rpc` URL are accepted; check the host
and port.

**`Refusing to sync: daemon is on 'testnet' but this server is configured for 'mainnet'`**
`--network` and the `beldexd` behind `--daemon` disagree. This check exists
because a foreign chain would otherwise look like a reorg and roll back real
accounts.

**`no LWS database at <path>`**
A read-only command was pointed at a path with no database. Read-only commands
will not create one — check `--db-path`, or start the daemon against it once.

**`the shadow chain is empty after syncing from <url>`**
The `beldexd` the rebuild is scanning against has no blocks to serve yet, most
likely because it is still syncing. Check its height and retry.

**`/switch_db` returns 404**
The running daemon predates the endpoint. Rebuild and restart it.

**`/switch_db` refuses with accounts missing**
The shadow has not picked up accounts that registered recently. Let the rebuild
run through another sync interval and retry. It refuses rather than switching
because those accounts would otherwise be lost.

**The rebuild reports `STALLED`**
Nothing has been committed for several progress intervals. Re-run with
`--log-level 1` to see the scanner's per-batch output, and check that `beldexd`
is reachable and not itself stuck.
