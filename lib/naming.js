'use strict';

// Unified DNS label validation according to RFC 1035:
// - 1 to 63 characters
// - Lowercase alphanumeric and hyphens only: [a-z0-9-]
// - Must begin with an alphanumeric character: [a-z0-9]
// - Must end with an alphanumeric character: [a-z0-9]
function validateName(raw) {
  if (typeof raw !== 'string') {
    return { ok: false, reason: 'name must be a string' };
  }
  const name = raw.toLowerCase().trim();
  if (name.length < 1 || name.length > 63) {
    return { ok: false, reason: 'name must be between 1 and 63 characters' };
  }
  if (!/^[a-z0-9]/.test(name)) {
    return { ok: false, reason: 'name must start with an alphanumeric character (a-z, 0-9)' };
  }
  if (!/[a-z0-9]$/.test(name)) {
    return { ok: false, reason: 'name must end with an alphanumeric character (a-z, 0-9)' };
  }
  if (!/^[a-z0-9-]+$/.test(name)) {
    return { ok: false, reason: 'name may only contain lowercase letters, numbers, and hyphens' };
  }
  return { ok: true, name };
}

// Sanitize a folder or raw name into a valid DNS label.
function sanitizeName(raw) {
  const name = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-')
    .slice(0, 63)
    .replace(/-+$/, '');
  return name || 'project';
}

module.exports = { validateName, sanitizeName };
