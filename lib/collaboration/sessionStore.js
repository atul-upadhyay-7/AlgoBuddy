import crypto from "crypto";
import { Redis } from "@upstash/redis";
import { sanitizeSessionText } from "./sessionTrace.js";

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const PUBLIC_VISIBILITY = new Set(["public", "unlisted", "private"]);

const memorySessions = new Map();

const redis =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? Redis.fromEnv()
    : null;

function createId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function normalizeVisibility(value) {
  return PUBLIC_VISIBILITY.has(value) ? value : "public";
}

function normalizeJoinCode(value) {
  return String(value || "").replace(/[^a-z0-9]/gi, "").toUpperCase();
}

function createJoinCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function hashPassword(password) {
  if (!password) return null;
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

function sessionKey(sessionId) {
  return `collab:session:${sessionId}`;
}

function discoverableSessionView(session, { includeJoinCode = true } = {}) {
  if (!session) return null;
  const view = {
    id: session.id,
    title: session.title,
    visibility: session.visibility,
    module: session.module,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    participantCount: session.participantCount || 0,
  };

  if (includeJoinCode) {
    view.joinCode = session.joinCode;
  }

  return view;
}

async function readSession(sessionId) {
  if (!sessionId) return null;

  if (redis) {
    const value = await redis.get(sessionKey(sessionId));
    return value ? value : null;
  }

  return memorySessions.get(sessionId) || null;
}

async function findSessionByJoinCode(joinCode) {
  const normalizedJoinCode = normalizeJoinCode(joinCode);
  if (!normalizedJoinCode) return null;

  if (redis) {
    const keys = await redis.keys("collab:session:*");
    for (const key of keys) {
      const session = await redis.get(key);
      if (normalizeJoinCode(session?.joinCode) === normalizedJoinCode) {
        return session;
      }
    }
    return null;
  }

  return [...memorySessions.values()].find(
    (session) => normalizeJoinCode(session.joinCode) === normalizedJoinCode,
  ) || null;
}

async function readSessionByIdentifier(identifier) {
  const directSession = await readSession(identifier);
  if (directSession) return directSession;
  return findSessionByJoinCode(identifier);
}

async function writeSession(session) {
  const nextSession = {
    ...session,
    updatedAt: new Date().toISOString(),
  };

  if (redis) {
    await redis.set(sessionKey(nextSession.id), nextSession, {
      ex: SESSION_TTL_SECONDS,
    });
  } else {
    memorySessions.set(nextSession.id, nextSession);
  }

  return nextSession;
}

export async function createCollaborationSession(input = {}) {
  const title = sanitizeSessionText(input.title || "Untitled session", 80);
  const visibility = normalizeVisibility(input.visibility || "public");
  const passwordHash = visibility === "private" ? hashPassword(input.password) : null;
  const id = createId("session");
  let joinCode = null;
  for (let attempts = 0; attempts < 5; attempts += 1) {
    const candidate = createJoinCode();
    if (!(await findSessionByJoinCode(candidate))) {
      joinCode = candidate;
      break;
    }
  }
  if (!joinCode) {
    throw new Error("Failed to create a unique collaboration join code.");
  }
  const sessionSecret = crypto.randomBytes(24).toString("base64url");
  const now = new Date().toISOString();

  const session = await writeSession({
    id,
    joinCode,
    title,
    visibility,
    module: sanitizeSessionText(input.module || "dry-run", 40),
    presenterId: null,
    createdAt: now,
    updatedAt: now,
    createdBy: sanitizeSessionText(input.createdBy || "", 80),
    passwordHash,
    sessionSecret,
    participantCount: 0,
    annotations: [],
    events: [],
  });

  return {
    session: discoverableSessionView(session),
    sessionSecret,
  };
}

export async function listCollaborationSessions() {
  if (redis) {
    const keys = await redis.keys("collab:session:*");
    const sessions = [];

    for (const key of keys) {
      const session = await redis.get(key);
      if (session && session.visibility === "public") {
        sessions.push(discoverableSessionView(session, { includeJoinCode: false }));
      }
    }

    return sessions.filter(Boolean).sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  return [...memorySessions.values()]
    .filter((session) => session.visibility === "public")
    .map((session) => discoverableSessionView(session, { includeJoinCode: false }))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}

export async function getCollaborationSession(sessionId) {
  return readSession(sessionId);
}

/**
 * Public-safe session lookup for use in HTTP GET handlers.
 * Returns only the discoverable view — never sessionSecret or passwordHash.
 * Returns null when the session does not exist.
 */
export async function getPublicCollaborationSession(sessionId) {
  const session = await readSession(sessionId);
  return discoverableSessionView(session, { includeJoinCode: false });
}

export async function joinCollaborationSession(sessionIdentifier, { password } = {}) {
  const session = await readSessionByIdentifier(sessionIdentifier);
  if (!session) {
    return { error: "Session not found", status: 404 };
  }

  if (session.visibility === "private") {
    const providedHash = hashPassword(password);
    if (!providedHash || providedHash !== session.passwordHash) {
      return { error: "Invalid session password", status: 403 };
    }
  }

  return {
    session: discoverableSessionView(session),
    sessionSecret: session.sessionSecret,
  };
}

export async function updateCollaborationSession(sessionId, patch = {}) {
  const current = await readSession(sessionId);
  if (!current) return null;

  const next = await writeSession({
    ...current,
    ...patch,
  });

  return discoverableSessionView(next);
}
