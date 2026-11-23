#!/usr/bin/env bun
// Gate for migration 0013 (the log lookup indexes). It runs three steps on a throwaway PostgreSQL:
// an upgrade from the previous gateway with log appends running, the mine check through the real
// client, and the rollback from docs/gateway.md followed by the previous gateway and its mine check.
//
// Usage: GATE_DIR=<scratch dir> bun scripts/log-lookup-migration-gate.ts <previous-bin-dir> <new-bin-dir>
//   previous-bin-dir: open-pact-gateway, open-pact-client and open-pact-witness built before 0013
//   new-bin-dir: the same three built from this checkout (target/release)
// Needs docker. It starts a postgres:17-alpine container, and it stops every process and removes
// the container it started. Exit 0 when every check and budget passes.

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const [previousDir, newDir] = Bun.argv.slice(2);
const work = Bun.env.GATE_DIR;
if (!previousDir || !newDir || !work) {
  console.error("usage: GATE_DIR=<scratch dir> bun scripts/log-lookup-migration-gate.ts <previous-bin-dir> <new-bin-dir>");
  process.exit(2);
}
const root = resolve(import.meta.dir, "..");
const FIXTURE_ROWS = 200_000;
const STALL_BUDGET_MS = 2000; // longest append while the index build runs
const STARTUP_BUDGET_MS = 5000; // process start to /healthz; the chart starts liveness at 10 s
const container = `op-s5-gate-${crypto.randomUUID().slice(0, 8)}`;
const dbPassword = crypto.randomUUID(); // local throwaway container only
const procs: Bun.Subprocess[] = [];
const failures: string[] = [];
const report: Record<string, unknown> = {};
const expect = (ok: boolean, what: string) => {
  if (!ok) failures.push(what);
};

function freePort(): number {
  const listener = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  const port = listener.port;
  listener.stop(true);
  return port;
}

async function run(cmd: string[], opts: { env?: Record<string, string>; input?: string } = {}) {
  const p = Bun.spawn(cmd, {
    cwd: root,
    env: { PATH: Bun.env.PATH ?? "", HOME: Bun.env.HOME ?? "", ...opts.env },
    stdin: opts.input === undefined ? "ignore" : new Blob([opts.input]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [out, err] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text()]);
  return { code: await p.exited, out, err };
}

function start(cmd: string[], env: Record<string, string>, log: string): Bun.Subprocess {
  const p = Bun.spawn(cmd, {
    cwd: root,
    env: { PATH: Bun.env.PATH ?? "", HOME: Bun.env.HOME ?? "", ...env },
    stdout: Bun.file(log),
    stderr: Bun.file(log),
  });
  procs.push(p);
  return p;
}

async function stop(p: Bun.Subprocess) {
  p.kill();
  await p.exited;
}

/** Milliseconds from `since` until the URL answers 2xx; throws at the timeout. */
async function waitHttp(url: string, since: number, timeoutMs: number): Promise<number> {
  while (performance.now() - since < timeoutMs) {
    try {
      const r = await fetch(url);
      if (r.ok) return performance.now() - since;
    } catch {
      // not listening yet
    }
    await Bun.sleep(25);
  }
  throw new Error(`no answer from ${url} within ${timeoutMs} ms`);
}

// The SQL of translog::mine, read from the gateway source at run time, so the plan check runs the query the gateway runs.
const MINE_SQL_TEXT = (() => {
  const source = readFileSync(join(root, "crates/open-pact-gateway/src/translog.rs"), "utf8");
  const body = source.slice(source.indexOf("pub async fn mine("));
  const open = body.indexOf('"', body.indexOf("query_as::<_, Row>(")) + 1;
  const close = body.indexOf('",', open);
  if (open <= 0 || close < 0) throw new Error("translog::mine SQL not found");
  // A Rust string line ends in a backslash: the newline and the next line's indent are skipped.
  return body.slice(open, close).split("\\\n").map((part, i) => (i === 0 ? part : part.trimStart())).join("");
})();
const digest = (text: string) => new Bun.CryptoHasher("sha256").update(text).digest("hex");
const COMMITMENT = digest("fixture-commitment-42");
const INDEXED_KINDS = ["device_enrolled", "device_approved", "device_revoked", "manifest_accepted"];
const WRITER_KINDS = [...INDEXED_KINDS, "retention_purge"];
const CLOCK_MS = "SELECT (extract(epoch from clock_timestamp()) * 1000)::float8 AS ms";
let planCounter = 0;
/** EXPLAIN ANALYZE of translog::mine with its three bind parameters, prepared on one connection. */
async function minePlan(sql: Bun.SQL, size: number, manifest: string, commitment: string): Promise<string[]> {
  const name = `mine_plan_${planCounter++}`;
  return sql.begin(async (tx) => {
    await tx.unsafe("SET LOCAL plan_cache_mode = force_custom_plan");
    await tx.unsafe(`PREPARE ${name} (bigint, text, text) AS ${MINE_SQL_TEXT}`);
    const lines = (await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS) EXECUTE ${name}(${size}, '${manifest}', '${commitment}')`)).map((r) => r["QUERY PLAN"] as string);
    await tx.unsafe(`DEALLOCATE ${name}`);
    return lines;
  });
}
/** Resolves whether cond becomes true within timeoutMs. */
async function waitUntil(cond: () => boolean, timeoutMs: number): Promise<boolean> {
  const until = performance.now() + timeoutMs;
  while (!cond() && performance.now() < until) await Bun.sleep(10);
  return cond();
}

const pgPort = freePort();
const gatewayPort = freePort();
const witnessPort = freePort();
const dbUrl = `postgres://postgres:${dbPassword}@127.0.0.1:${pgPort}/gate`;
const gatewayUrl = `http://127.0.0.1:${gatewayPort}`;
const gatewayEnv: Record<string, string> = {
  DATABASE_URL: dbUrl,
  LISTEN_ADDR: `127.0.0.1:${gatewayPort}`,
  DEV_INSECURE_KEK: "1",
  LOG_ORIGIN: "pact.example.com/log",
  PUBLIC_URL: gatewayUrl,
  AUTO_APPROVE: "false",
  WITNESS_URLS: `http://127.0.0.1:${witnessPort}`,
};
const home = join(work, "device-home");
let admin: Bun.SQL | undefined;
let db: Bun.SQL | undefined;

try {
  // 1. A throwaway PostgreSQL 17.
  const up = await run(["docker", "run", "-d", "--name", container, "-e", `POSTGRES_PASSWORD=${dbPassword}`, "-p", `127.0.0.1:${pgPort}:5432`, "postgres:17-alpine"]);
  if (up.code !== 0) throw new Error(`docker run: ${up.err}`);
  for (let attempt = 0; ; attempt++) {
    try {
      admin = new Bun.SQL(`postgres://postgres:${dbPassword}@127.0.0.1:${pgPort}/postgres`, { max: 1 });
      await admin.unsafe("SELECT 1");
      break;
    } catch (error) {
      if (attempt > 120) throw error;
      await Bun.sleep(500);
    }
  }
  await admin.unsafe("CREATE DATABASE gate");
  db = new Bun.SQL(dbUrl, { max: 4 });

  // 2. The previous gateway migrates the empty database to 0012.
  let t = performance.now();
  const prev0 = start([join(previousDir, "open-pact-gateway")], gatewayEnv, join(work, "previous-migrate.log"));
  await waitHttp(`${gatewayUrl}/healthz`, t, 60_000);
  await stop(prev0);
  const applied = await db.unsafe("SELECT count(*)::int AS n, max(version)::int AS v FROM _sqlx_migrations WHERE success");
  report.previousSchema = applied[0];
  expect(applied[0].n === 12 && applied[0].v === 12, "previous gateway did not leave migrations 1 to 12 applied");

  // 3. Fixture: the kind mix of the load test at 8,000 devices (16,001 rows: two device entries per
  //    device, one manifest entry), scaled to 200,000 rows. Commitments have the gateway's form, a
  //    SHA-256 hex digest. Every 500th row is device_revoked and every 1000th is manifest_accepted,
  //    so each indexed kind is present. The last row is one retention purge.
  // The previous gateway already wrote its startup entry (the manifest), so the fixture fills the rest.
  const existing = (await db.unsafe("SELECT count(*)::int AS n FROM log_entries"))[0].n as number;
  expect(existing >= 1, "the previous gateway wrote no startup entry");
  await db.unsafe(`INSERT INTO log_entries (idx, kind, data)
    SELECT g,
           CASE WHEN g % 1000 = 0 THEN 'manifest_accepted'
                WHEN g % 500 = 1 THEN 'device_revoked'
                WHEN g % 2 = 1 THEN 'device_enrolled'
                ELSE 'device_approved' END,
           jsonb_build_object('commitment', encode(sha256(convert_to('fixture-commitment-' || ((g - 1) / 2), 'UTF8')), 'hex'))
    FROM generate_series(${existing}, ${FIXTURE_ROWS - 2}) AS g
    UNION ALL
    SELECT ${FIXTURE_ROWS - 1}, 'retention_purge', '{}'::jsonb`);
  await db.unsafe("ANALYZE log_entries");
  const rows = await db.unsafe("SELECT count(*)::int AS n FROM log_entries");
  report.fixtureRows = rows[0].n;
  expect(rows[0].n === FIXTURE_ROWS, "fixture row count");
  const fixtureKinds: Record<string, number> = Object.fromEntries((await db.unsafe("SELECT kind, count(*)::int AS n FROM log_entries GROUP BY kind ORDER BY kind")).map((k) => [k.kind as string, k.n as number]));
  report.fixtureKinds = fixtureKinds;
  expect(WRITER_KINDS.every((k) => k in fixtureKinds), "the fixture lacks an indexed kind or the purge");

  const explain = () => minePlan(db!, FIXTURE_ROWS, "fixture-manifest", COMMITMENT);
  const before = await explain();
  report.explainBefore = before;
  expect(before.some((l) => l.includes("Seq Scan on log_entries")), "previous schema should scan log_entries");

  // 4. The upgrade. A writer appends one entry every 20 ms from before the new gateway starts until
  //    it answers. Each append has the gateway's shape (lock, count, insert) and cycles through the
  //    indexed kinds and a retention purge. Each append keeps its span on the database clock.
  const appends = { count: 0, max: 0, errors: [] as string[], kinds: {} as Record<string, number>, spans: [] as { startMs: number; endMs: number }[] };
  let appending = true;
  const appender = (async () => {
    const writer = new Bun.SQL(dbUrl, { max: 1 });
    try {
      for (let i = 0; appending; i++) {
        const kind = WRITER_KINDS[i % WRITER_KINDS.length];
        const data = kind === "retention_purge" ? {} : { commitment: digest(`writer-commitment-${i}`) };
        const s = performance.now();
        try {
          const span = await writer.begin(async (tx) => {
            const [{ ms: startMs }] = await tx.unsafe(CLOCK_MS);
            await tx.unsafe("SELECT pg_advisory_xact_lock(hashtext('open-pact log_entries'))");
            const [{ n }] = await tx.unsafe("SELECT count(*)::int AS n FROM log_entries");
            await tx.unsafe("INSERT INTO log_entries (idx, kind, data) VALUES ($1::bigint, $2, $3::jsonb)", [n, kind, JSON.stringify(data)]);
            const [{ ms: endMs }] = await tx.unsafe(CLOCK_MS);
            return { startMs: startMs as number, endMs: endMs as number };
          });
          appends.count += 1;
          appends.kinds[kind] = (appends.kinds[kind] ?? 0) + 1;
          appends.spans.push(span);
          appends.max = Math.max(appends.max, performance.now() - s);
        } catch (error) {
          appends.errors.push(String(error));
        }
        await Bun.sleep(20);
      }
    } finally {
      await writer.close();
    }
  })();
  expect(await waitUntil(() => appends.count >= 1, 10_000), "the writer committed no append before the new gateway started");
  t = performance.now();
  const next = start([join(newDir, "open-pact-gateway")], gatewayEnv, join(work, "new-start.log"));
  const startupMs = await waitHttp(`${gatewayUrl}/healthz`, t, 60_000);
  appending = false;
  await appender;
  report.startupMs = Math.round(startupMs);
  report.appends = { count: appends.count, maxMs: Math.round(appends.max), errors: appends.errors.length, kinds: appends.kinds };
  expect(startupMs <= STARTUP_BUDGET_MS, `startup ${Math.round(startupMs)} ms over ${STARTUP_BUDGET_MS} ms`);
  expect(appends.max <= STALL_BUDGET_MS, `append stall ${Math.round(appends.max)} ms over ${STALL_BUDGET_MS} ms`);
  expect(appends.errors.length === 0, "appends failed during the upgrade");
  expect(appends.count > 0, "the writer recorded no append");
  expect(Object.keys(appends.kinds).some((k) => INDEXED_KINDS.includes(k)), "the timed writer inserted no indexed kind");

  const m13 = await db.unsafe("SELECT success, (extract(epoch from installed_on) * 1000)::float8 AS start_ms, (execution_time::float8 / 1000000)::float8 AS exec_ms FROM _sqlx_migrations WHERE version = 13");
  expect(m13.length === 1 && m13[0].success === true, "migration 13 not applied");
  // installed_on is now() of the migration transaction, so the transaction runs for exec_ms from it.
  const m13row = m13[0] ?? { start_ms: 0, exec_ms: 0 };
  const windowStart = m13row.start_ms as number;
  const execMs = m13row.exec_ms as number;
  const windowEnd = windowStart + execMs;
  const overlapping = appends.spans.filter((s) => s.startMs < windowEnd && s.endMs > windowStart).length;
  report.migration13 = { transactionMs: Math.round(execMs), overlappingAppends: overlapping };
  expect(execMs < STALL_BUDGET_MS, `migration 13 transaction ${Math.round(execMs)} ms, not under ${STALL_BUDGET_MS} ms`);
  expect(overlapping > 0, "no timed append overlaps the migration window");

  const indexes = (await db.unsafe("SELECT indexname FROM pg_indexes WHERE tablename = 'log_entries' ORDER BY indexname")).map((r) => r.indexname);
  report.indexes = indexes;
  expect(indexes.includes("log_entries_commitment") && indexes.includes("log_entries_manifest"), "both indexes must exist after the upgrade");
  await db.unsafe("ANALYZE log_entries");
  const after = await explain();
  report.explainAfter = after;
  expect(after.some((l) => l.includes("log_entries_commitment")) && after.some((l) => l.includes("log_entries_manifest")), "mine must use both partial indexes");
  expect(!after.some((l) => l.includes("Seq Scan on log_entries")), "mine must not scan log_entries");

  // 5. The mine check through the real client: enrol, approve, then check (the client mines its entries).
  const witnessLog = join(work, "witness.log");
  const witness = start([join(newDir, "open-pact-witness")], {
    WITNESS_NAME: "witness.example.org/demo",
    WITNESS_KEY_FILE: join(root, "deploy/compose/demo-witness.key"),
    WITNESS_LOG_KEY_URL: `${gatewayUrl}/v1/log/key`,
    WITNESS_STATE: join(work, "witness-state.json"),
    LISTEN_ADDR: `127.0.0.1:${witnessPort}`,
  }, witnessLog);
  await waitHttp(`http://127.0.0.1:${witnessPort}/healthz`, performance.now(), 60_000);
  const gwBin = join(newDir, "open-pact-gateway");
  const clientBin = join(newDir, "open-pact-client");
  const invite = await run([gwBin, "invite", "--url", gatewayUrl, "--ttl", "1h", "--note", "gate"], { env: gatewayEnv });
  expect(invite.code === 0 && invite.out.trim().startsWith("opi1:"), "invite");
  const join1 = await run([clientBin, "--home", home, "join", invite.out.trim(), "--yes", "--software-key", "--no-wait"]);
  const code = /Device code for IT: ([0-9a-f]{12})/.exec(join1.out)?.[1];
  expect(join1.code === 0 && !!code, `join: ${join1.err || join1.out.slice(-300)}`);
  const approve = await run([gwBin, "devices", "approve", code ?? "none"], { env: gatewayEnv });
  expect(approve.code === 0 && approve.out.includes("approved pseudonym:"), "approve");
  const check1 = await run([clientBin, "--home", home, "check"]);
  report.mineCheckNew = { exit: check1.code, inclusionProofs: /Inclusion proofs verified/.test(check1.out) };
  expect(/Inclusion proofs verified/.test(check1.out), `mine check on the new gateway: ${check1.out.slice(-400)}${check1.err.slice(-200)}`);

  // 6. The earlier gateway refuses the upgraded database.
  await stop(next);
  const refused = start([join(previousDir, "open-pact-gateway")], gatewayEnv, join(work, "previous-refused.log"));
  const exited = await Promise.race([refused.exited.then((code) => code), Bun.sleep(30_000).then(() => "running")]);
  if (exited === "running") await stop(refused);
  const refusedText = readFileSync(join(work, "previous-refused.log"), "utf8");
  const refusedLog = refusedText.trim().split("\n").slice(-2).join(" | ");
  report.previousRefusesUpgraded = { exit: exited, lastLines: refusedLog };
  expect(exited !== "running" && exited !== 0 && refusedText.includes("migration 13 was previously applied but is missing"), `the earlier gateway must refuse the upgraded database with the migration 13 error: ${refusedLog}`);

  // 7. The rollback block from docs/gateway.md, run with every gateway stopped.
  const doc = readFileSync(join(root, "docs/gateway.md"), "utf8");
  const section = doc.indexOf("### Migration 0013 and its rollback");
  const open = doc.indexOf("\`\`\`sql", section);
  const close = doc.indexOf("\`\`\`", open + 7);
  expect(section >= 0 && open > section && close > open, "rollback block not found in docs/gateway.md");
  const rollbackSql = doc.slice(open + 7, close).trim() + "\n";
  const rb = await run(["docker", "exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gate"], { input: rollbackSql });
  report.rollbackExit = rb.code;
  expect(rb.code === 0, `rollback: ${rb.err}${rb.out}`);
  const gone = (await db.unsafe("SELECT indexname FROM pg_indexes WHERE tablename = 'log_entries' AND indexname IN ('log_entries_commitment', 'log_entries_manifest')")).length;
  const version13 = (await db.unsafe("SELECT count(*)::int AS n FROM _sqlx_migrations WHERE version = 13"))[0].n;
  expect(gone === 0 && version13 === 0, "rollback left an index or migration 13 behind");

  // 8. The earlier gateway starts on the rolled-back database and its mine check passes.
  t = performance.now();
  const previous = start([join(previousDir, "open-pact-gateway")], gatewayEnv, join(work, "previous-after-rollback.log"));
  const previousMs = await waitHttp(`${gatewayUrl}/healthz`, t, 60_000);
  report.previousStartupMs = Math.round(previousMs);
  const check2 = await run([join(previousDir, "open-pact-client"), "--home", home, "check"]);
  report.mineCheckPrevious = { exit: check2.code, inclusionProofs: /Inclusion proofs verified/.test(check2.out) };
  expect(/Inclusion proofs verified/.test(check2.out), `mine check on the previous gateway: ${check2.out.slice(-400)}${check2.err.slice(-200)}`);
  const scansAfterRollback = (await minePlan(db!, FIXTURE_ROWS, "fixture-manifest", COMMITMENT)).some((l) => l.includes("Seq Scan on log_entries"));
  report.previousPlanScans = scansAfterRollback;
  await stop(previous);
} catch (error) {
  failures.push(`aborted: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  for (const p of procs) {
    if (p.exitCode === null) p.kill();
    await p.exited.catch(() => undefined);
  }
  await db?.close();
  await admin?.close();
  await run(["docker", "rm", "-f", container]);
}

report.passed = failures.length === 0;
report.failures = failures;
console.log(JSON.stringify(report, null, 2));
process.exit(failures.length === 0 ? 0 : 1);
