'use strict';

// Configuration and state files are the daemon's memory. A file that exists
// but cannot be trusted (damaged JSON, wrong types, unreadable) must never be
// silently replaced by defaults: the documented default bind is the wildcard,
// so a silent fallback would silently widen the network exposure. Everything
// here fails closed with a concrete repair message and never writes to, moves
// or "fixes" the file that failed validation.

const fs = require('fs');
const path = require('path');

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

const KNOWN_BIND_MODES = new Set(['wildcard', 'loopback']);

function jsonTypeName(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  return typeof value;
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Reads a JSON state file that must contain a top-level object.
// Returns null when the file does not exist (safe first start). Any other
// read or parse problem throws ConfigError — the caller must not fall back to
// defaults and must not touch the file.
function readJsonObject(file, validate) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new ConfigError(
      `${file} exists but cannot be read (${err.code}). ` +
        `Restore access (chmod 600 "${file}") and start again — portname refuses to run on unreadable state instead of guessing.`
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ConfigError(
      `${file} is damaged — not valid JSON (${err.message}). ` +
        `Fix or remove the file by hand and start again. Nothing was written, moved or defaulted.`
    );
  }
  if (!isPlainObject(parsed)) {
    throw new ConfigError(
      `${file} must contain a JSON object, found ${jsonTypeName(parsed)}. ` +
        `Fix the file by hand; it was not modified.`
    );
  }
  validate(parsed, file);
  return parsed;
}

// Known fields are type-checked explicitly; unknown fields are additive and
// never validated or removed. Problems are collected so one message names
// every bad field instead of failing one at a time.
function validateConfig(cfg, file = 'config.json') {
  const problems = [];

  if (cfg.bind !== undefined && !KNOWN_BIND_MODES.has(cfg.bind)) {
    problems.push(`bind must be "wildcard" or "loopback" (found ${JSON.stringify(cfg.bind)})`);
  }
  for (const key of ['port', 'fallbackPort', 'loopbackPort']) {
    const v = cfg[key];
    if (v !== undefined && (!Number.isInteger(v) || v < 0 || v > 65535)) {
      problems.push(`${key} must be an integer 0-65535 (found ${JSON.stringify(v)})`);
    }
  }
  if (cfg.control !== undefined && typeof cfg.control !== 'boolean') {
    problems.push(`control must be a boolean (found ${JSON.stringify(cfg.control)})`);
  }
  if (cfg.cloudflaredBin !== undefined && (typeof cfg.cloudflaredBin !== 'string' || cfg.cloudflaredBin.trim() === '')) {
    problems.push(`cloudflaredBin must be a non-empty string (found ${JSON.stringify(cfg.cloudflaredBin)})`);
  }
  if (
    cfg.ignoreCommands !== undefined &&
    (!Array.isArray(cfg.ignoreCommands) || cfg.ignoreCommands.some((c) => typeof c !== 'string'))
  ) {
    problems.push('ignoreCommands must be an array of strings');
  }

  const nameMapProblems = (map, label) => {
    if (map === undefined) return [];
    if (!isPlainObject(map)) return [`${label} must map names to names (found ${jsonTypeName(map)})`];
    const bad = Object.entries(map).filter(([, v]) => typeof v !== 'string' || v === '');
    return bad.length ? [`${label} must map names to non-empty strings (bad: ${bad.map(([k]) => k).join(', ')})`] : [];
  };
  problems.push(...nameMapProblems(cfg.renames, 'renames'));
  problems.push(...nameMapProblems(cfg.names, 'names'));

  const portMapProblems = (map, label, keyDesc) => {
    if (map === undefined) return [];
    if (!isPlainObject(map)) return [`${label} must map ${keyDesc} to ports (found ${jsonTypeName(map)})`];
    const bad = Object.entries(map).filter(([, v]) => !Number.isInteger(v) || v < 1 || v > 65535);
    return bad.length
      ? [`${label} must map ${keyDesc} to ports 1-65535 (bad: ${bad.map(([k]) => k).join(', ')})`]
      : [];
  };
  problems.push(...portMapProblems(cfg.manual, 'manual', 'names'));
  problems.push(...portMapProblems(cfg.primaryPorts, 'primaryPorts', 'roots'));

  // root -> day (days since 1970-01-01, UTC) the project was last live;
  // written by the daemon to expire unused name reservations.
  if (cfg.namesSeen !== undefined) {
    if (!isPlainObject(cfg.namesSeen)) {
      problems.push(`namesSeen must map roots to day numbers (found ${jsonTypeName(cfg.namesSeen)})`);
    } else {
      const bad = Object.entries(cfg.namesSeen).filter(([, v]) => !Number.isInteger(v) || v < 0);
      if (bad.length) {
        problems.push(`namesSeen must map roots to day numbers (bad: ${bad.map(([k]) => k).join(', ')})`);
      }
    }
  }

  if (cfg.exposed !== undefined) {
    if (!isPlainObject(cfg.exposed)) {
      problems.push(`exposed must map identities to booleans (found ${jsonTypeName(cfg.exposed)})`);
    } else {
      const bad = Object.entries(cfg.exposed).filter(([, v]) => typeof v !== 'boolean');
      if (bad.length) {
        problems.push(`exposed must map identities to booleans (bad: ${bad.map(([k]) => k).join(', ')})`);
      }
    }
  }

  if (cfg.exposedTargets !== undefined) {
    if (!isPlainObject(cfg.exposedTargets)) {
      problems.push(`exposedTargets must map identities to {port, command} (found ${jsonTypeName(cfg.exposedTargets)})`);
    } else {
      const bad = Object.entries(cfg.exposedTargets).filter(([, v]) =>
        !isPlainObject(v) ||
        !Number.isInteger(v.port) || v.port < 1 || v.port > 65535 ||
        (v.command !== null && typeof v.command !== 'string') ||
        (v.network !== undefined && v.network !== null && typeof v.network !== 'string') ||
        (v.gateway !== undefined && v.gateway !== null && typeof v.gateway !== 'string'));
      if (bad.length) {
        problems.push(`exposedTargets must map identities to {port, command} (bad: ${bad.map(([k]) => k).join(', ')})`);
      }
    }
  }

  if (problems.length) {
    throw new ConfigError(
      `${file} has invalid settings and was NOT modified — fix it by hand and start again: ${problems.join('; ')}`
    );
  }
}

// state.json is the listener-birth map: string keys, numeric timestamps.
function validateStateMap(state, file = 'state.json') {
  const bad = Object.entries(state).filter(([, v]) => typeof v !== 'number' || !Number.isFinite(v));
  if (bad.length) {
    throw new ConfigError(
      `${file} has invalid settings and was NOT modified — fix it by hand and start again: ` +
        bad.map(([k, v]) => `entry "${k}" must be a timestamp number (found ${JSON.stringify(v)})`).join('; ')
    );
  }
}

// Local file protection for the state directory: 0700, owned by the current
// user, never reached through a symlink. Only the directory itself is
// tightened (never a recursive chmod), and only when it belongs to us —
// foreign files are never modified.
function ensurePrivateDir(dir, { lstat = fs.lstatSync } = {}) {
  let st;
  try {
    st = lstat(dir);
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw new ConfigError(`cannot inspect state directory ${dir} (${err.code}); refusing to touch it`);
    }
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    st = lstat(dir);
  }
  if (st.isSymbolicLink()) {
    throw new ConfigError(`state directory ${dir} is a symlink; refusing to follow it. Point PORTNAME_DIR at a real directory.`);
  }
  if (!st.isDirectory()) {
    throw new ConfigError(`state path ${dir} is not a directory; refusing to use it`);
  }
  if (typeof st.uid === 'number' && typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new ConfigError(`state directory ${dir} is owned by uid ${st.uid}, not by you; refusing to modify it`);
  }
  if ((st.mode & 0o077) !== 0) {
    fs.chmodSync(dir, 0o700);
  }
}

// Darwin's sockaddr_un.sun_path holds 104 bytes including the terminating
// NUL; libuv silently truncates a longer path and binds a DIFFERENT file.
// The control socket path is measured exactly as it is passed to listen()
// (relative or absolute), so a too-long PORTNAME_DIR fails up front with a
// concrete message instead of crashing the daemon after it took its lock.
const MAX_SOCKET_PATH_BYTES = 103;

function socketPathProblem(sockFile) {
  const bytes = Buffer.byteLength(String(sockFile));
  if (bytes <= MAX_SOCKET_PATH_BYTES) return null;
  return `the control socket path ${sockFile} is ${bytes} bytes; Unix socket paths are limited to ` +
    `${MAX_SOCKET_PATH_BYTES} bytes on macOS — set PORTNAME_DIR to a shorter directory`;
}

module.exports = {
  ConfigError,
  MAX_SOCKET_PATH_BYTES,
  socketPathProblem,
  readJsonObject,
  validateConfig,
  validateStateMap,
  ensurePrivateDir,
  isPlainObject,
};
