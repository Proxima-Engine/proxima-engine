#!/usr/bin/env node
import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const required = [
  "AGATA_API_BASE_URL",
  "AGATA_API_KEY",
  "AGATA_WEBHOOK_SIGNING_SECRET",
  "PROXIMA_DEPLOYMENT_EXECUTOR_ID",
];
for (const key of required) {
  if (!process.env[key]?.trim()) throw new Error(`Missing required environment variable: ${key}`);
}

const apiBase = process.env.AGATA_API_BASE_URL.replace(/\/+$/, "");
const apiKey = process.env.AGATA_API_KEY;
const webhookSecret = process.env.AGATA_WEBHOOK_SIGNING_SECRET;
const executorId = process.env.PROXIMA_DEPLOYMENT_EXECUTOR_ID;
const port = Number(process.env.PORT || 8789);
const maxBody = 1024 * 1024;
const inFlight = new Set();
const defaultStateDir = path.resolve(process.env.PROXIMA_DEPLOYMENT_STATE_DIR || path.join(process.cwd(), ".agata-deployments"));
const targets = new Map();

if (process.env.PROXIMA_DEPLOYMENT_TARGETS_FILE?.trim()) {
  const targetFile = path.resolve(process.env.PROXIMA_DEPLOYMENT_TARGETS_FILE);
  const config = JSON.parse(await readFile(targetFile, "utf8"));
  for (const [nodeId, value] of Object.entries(config)) {
    if (!/^[0-9a-f-]{36}$/i.test(nodeId)) throw new Error(`Invalid node UUID in deployment target file: ${nodeId}`);
    const projectDir = path.resolve(String(value.project_dir || ""));
    const composePath = path.resolve(projectDir, String(value.compose_file || "compose.customer.yaml"));
    const stateDir = path.resolve(String(value.state_dir || path.join(defaultStateDir, nodeId)));
    const allowedVersions = new Set(Array.isArray(value.allowed_versions) ? value.allowed_versions.map(v => String(v).trim()).filter(Boolean) : []);
    if (!value.project_dir || allowedVersions.size === 0 || [...allowedVersions].some(v => !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(v))) {
      throw new Error(`Target ${nodeId} requires project_dir and an explicit allowed_versions array.`);
    }
    targets.set(nodeId, { projectDir, composeFile: composePath, stateDir, stateFile: path.join(stateDir, "completed.json"), allowedVersions });
  }
} else {
  const nodeId = process.env.PROXIMA_NODE_ID;
  const versions = (process.env.PROXIMA_ENGINE_ALLOWLIST || "").split(",").map(v => v.trim()).filter(Boolean);
  if (!nodeId || !/^[0-9a-f-]{36}$/i.test(nodeId) || !versions.length) {
    throw new Error("Set PROXIMA_DEPLOYMENT_TARGETS_FILE or configure PROXIMA_NODE_ID and PROXIMA_ENGINE_ALLOWLIST for a single-node executor.");
  }
  const projectDir = path.resolve(process.env.PROXIMA_DEPLOYMENT_PROJECT_DIR || process.cwd());
  const composeFile = path.resolve(projectDir, process.env.PROXIMA_DEPLOYMENT_COMPOSE_FILE || "compose.customer.yaml");
  const stateDir = path.resolve(process.env.PROXIMA_DEPLOYMENT_STATE_DIR || path.join(projectDir, ".agata-deployments"));
  const allowedVersions = new Set(versions);
  if ([...allowedVersions].some(v => !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(v))) throw new Error("PROXIMA_ENGINE_ALLOWLIST contains an invalid Engine release version.");
  targets.set(nodeId, { projectDir, composeFile, stateDir, stateFile: path.join(stateDir, "completed.json"), allowedVersions });
}
if (targets.size === 0) throw new Error("At least one deployment target must be configured.");
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a valid TCP port.");
if (new URL(apiBase).protocol !== "https:" && !["localhost", "127.0.0.1"].includes(new URL(apiBase).hostname)) {
  throw new Error("AGATA_API_BASE_URL must use HTTPS outside local development.");
}

function verifySignature(rawBody, header) {
  const values = Object.fromEntries(String(header || "").split(",").map((part) => {
    const index = part.indexOf("=");
    return index > 0 ? [part.slice(0, index).trim(), part.slice(index + 1).trim()] : ["", ""];
  }).filter(([key]) => key));
  const timestamp = Number(values.t);
  const signature = values.v1 || "";
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > 300) return false;
  if (!/^[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = createHmac("sha256", webhookSecret).update(`${timestamp}.`).update(rawBody).digest();
  const actual = Buffer.from(signature, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function readState(stateFile) {
  try { return JSON.parse(await readFile(stateFile, "utf8")); }
  catch (error) { if (error.code === "ENOENT") return { completed: {} }; throw error; }
}

async function saveState(stateFile, state) {
  await mkdir(path.dirname(stateFile), { recursive: true, mode: 0o700 });
  const temporary = `${stateFile}.tmp`;
  await writeFile(temporary, JSON.stringify(state, null, 2), { mode: 0o600 });
  await rename(temporary, stateFile);
}

function docker(target, args, version) {
  const result = spawnSync("docker", ["compose", "-f", target.composeFile, ...args], {
    cwd: target.projectDir,
    env: { ...process.env, PROXIMA_ENGINE_VERSION: version },
    encoding: "utf8",
    timeout: 240_000,
    maxBuffer: 1024 * 1024,
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "Docker Compose command failed").slice(-3000);
    throw new Error(detail);
  }
  return result.stdout.trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForEngineHealth(target, version) {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      docker(target, ["exec", "-T", "engine", "curl", "-fsS", "http://127.0.0.1:9090/healthz"], version);
      return true;
    } catch {
      await sleep(5000);
    }
  }
  return false;
}

async function getDeployment(deploymentId) {
  const response = await fetch(`${apiBase}/api/v1/deployments`, {
    headers: { authorization: `Bearer ${apiKey}`, accept: "application/json" },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Could not inspect deployment state (${response.status}).`);
  const rows = await response.json();
  if (!Array.isArray(rows)) throw new Error("Control Plane returned an invalid deployment list.");
  return rows.find((row) => String(row.id) === deploymentId) || null;
}

async function reportResult(deploymentId, body) {
  const response = await fetch(`${apiBase}/api/v1/deployments/${encodeURIComponent(deploymentId)}/result`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 2000);
    throw new Error(`Control Plane rejected deployment result (${response.status}): ${detail}`);
  }
  return response.json();
}

async function executeDeployment(event, deliveryId) {
  const deploymentId = String(event?.resource?.id || "");
  const data = event?.data || {};
  const targetNode = String(data.node_id || "");
  const version = String(data.version || "");
  const desiredState = String(data.desired_state || "");

  if (!/^[0-9a-f-]{36}$/i.test(deploymentId)) throw new Error("Deployment event has an invalid resource ID.");
  const target = targets.get(targetNode);
  if (!target) throw new Error("No customer deployment target is configured for this node ID.");

  const stateFile = target.stateFile;
  const state = await readState(stateFile);
  if (state.completed[deploymentId]) return { accepted: true, duplicate: true };
  if (inFlight.has(deploymentId)) throw new Error("This deployment is already executing; retry the webhook delivery.");
  inFlight.add(deploymentId);

  const executionId = `agata-${deploymentId}`;
  const baseEvidence = { executor: executorId, execution_id: executionId };

  try {
    const remote = await getDeployment(deploymentId);
    if (!remote) throw new Error("Deployment record was not found in the active organization.");
    if (["healthy", "failed", "rolled_back"].includes(String(remote.status))) {
      const evidence = remote.result_evidence || {};
      if (evidence.executor !== executorId || evidence.execution_id !== executionId) {
        throw new Error("Deployment already has a terminal result from a different executor.");
      }
      await saveState(stateFile, {
        ...state,
        last_known_good_version: remote.observed_state === "running" ? remote.applied_version || state.last_known_good_version : state.last_known_good_version,
        completed: {
          ...(state.completed || {}),
          [deploymentId]: {
            version: remote.result_version || remote.version,
            desired_state: remote.observed_state,
            status: remote.status,
            completed_at: remote.completed_at || new Date().toISOString(),
          },
        },
      });
      return { accepted: true, duplicate: true, recovered_from_control_plane: true };
    }
    await reportResult(deploymentId, {
      status: "applying",
      observed_state: "unknown",
      version,
      evidence: baseEvidence,
    });

    const rejection = !target.allowedVersions.has(version)
      ? "Requested Engine version is not in this node target allowlist."
      : !["running", "stopped"].includes(desiredState)
        ? "This reference executor supports running and stopped states; draining requires a configured drain controller."
        : null;
    if (rejection) {
      await reportResult(deploymentId, {
        status: "failed",
        observed_state: "unknown",
        version,
        message: rejection,
        evidence: { ...baseEvidence, health_check: false },
      });
      await saveState(stateFile, {
        ...state,
        completed: {
          ...(state.completed || {}),
          [deploymentId]: { version, desired_state: desiredState, status: "failed", completed_at: new Date().toISOString() },
        },
      });
      return { accepted: true, failed: true, reason: rejection };
    }

    const previousVersion = state.last_known_good_version && target.allowedVersions.has(state.last_known_good_version)
      ? state.last_known_good_version
      : null;

    try {
      docker(target, ["pull", "engine"], version);
      if (desiredState === "running") {
        docker(target, ["up", "-d", "engine"], version);
        const healthy = await waitForEngineHealth(target, version);
        if (!healthy) throw new Error("Engine did not pass its local /healthz check after rollout.");
      } else {
        docker(target, ["stop", "engine"], version);
        const runningServices = docker(target, ["ps", "--status", "running", "--services"], version)
          .split(/\r?\n/).filter(Boolean);
        if (runningServices.includes("engine")) throw new Error("Engine container is still running after the stop request.");
      }

      await reportResult(deploymentId, {
        status: "healthy",
        observed_state: desiredState,
        version,
        evidence: { ...baseEvidence, health_check: true, check: desiredState === "running" ? "engine-healthz" : "container-stopped" },
      });
      await saveState(stateFile, {
        ...state,
        last_known_good_version: desiredState === "running" ? version : state.last_known_good_version,
        completed: {
          ...(state.completed || {}),
          [deploymentId]: { version, desired_state: desiredState, status: "healthy", completed_at: new Date().toISOString() },
        },
      });
      return { accepted: true, duplicate: false };
    } catch (rolloutError) {
      if (previousVersion && desiredState === "running") {
        try {
          docker(target, ["pull", "engine"], previousVersion);
          docker(target, ["up", "-d", "engine"], previousVersion);
          const restored = await waitForEngineHealth(target, previousVersion);
          if (restored) {
            await reportResult(deploymentId, {
              status: "rolled_back",
              observed_state: "running",
              version: previousVersion,
              evidence: { ...baseEvidence, rollback_version: previousVersion, rollback_health_check: true, health_check: true },
              message: "The requested release failed its health check; the previous known-good release was restored.",
            });
            await saveState(stateFile, {
              ...state,
              last_known_good_version: previousVersion,
              completed: {
                ...(state.completed || {}),
                [deploymentId]: { version: previousVersion, desired_state: "running", status: "rolled_back", completed_at: new Date().toISOString() },
              },
            });
            return { accepted: true, rolled_back: true };
          }
        } catch {
          // Fall through to a failed result; do not claim rollback without a passing health check.
        }
      }
      await reportResult(deploymentId, {
        status: "failed",
        observed_state: "unknown",
        version,
        message: String(rolloutError.message || rolloutError).slice(0, 900),
        evidence: { ...baseEvidence, health_check: false, rollback_attempted: Boolean(previousVersion) },
      });
      await saveState(stateFile, {
        ...state,
        completed: {
          ...(state.completed || {}),
          [deploymentId]: { version, desired_state: desiredState, status: "failed", completed_at: new Date().toISOString() },
        },
      });
      return { accepted: true, failed: true };
    }
  } finally {
    inFlight.delete(deploymentId);
  }
}

const server = createServer((req, res) => {
  const respond = (status, body) => {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  };
  if (req.method !== "POST" || req.url !== "/webhooks/agata/deployments") {
    respond(404, { error: "not_found" });
    return;
  }
  if (!String(req.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
    respond(415, { error: "application_json_required" });
    return;
  }
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > maxBody) { tooLarge = true; chunks.length = 0; }
    else if (!tooLarge) chunks.push(chunk);
  });
  req.on("end", async () => {
    if (tooLarge) return respond(413, { error: "payload_too_large" });
    const rawBody = Buffer.concat(chunks);
    if (!verifySignature(rawBody, req.headers["x-agata-signature"])) {
      return respond(401, { error: "invalid_signature" });
    }
    const deliveryId = String(req.headers["x-agata-delivery-id"] || "");
    if (!deliveryId || deliveryId.length > 200) return respond(400, { error: "invalid_delivery_id" });
    let event;
    try { event = JSON.parse(rawBody.toString("utf8")); }
    catch { return respond(400, { error: "invalid_json" }); }
    if (event.type !== "deployment.created") return respond(204, {});
    try {
      const result = await executeDeployment(event, deliveryId);
      return respond(202, result);
    } catch (error) {
      console.error(JSON.stringify({ error: String(error.message || error).slice(0, 1000), deliveryId }));
      return respond(503, { error: "deployment_execution_deferred" });
    }
  });
  req.on("error", () => { if (!res.headersSent) respond(400, { error: "request_read_failed" }); });
});

server.requestTimeout = 360_000;
server.headersTimeout = 365_000;
server.listen(port, "127.0.0.1", () => console.log(`Agata Proxima deployment executor listening on 127.0.0.1:${port}`));
