'use strict';

// Release gate: the respawn policy of the LaunchAgent plist `portname
// install` writes (bin/portname.js). launchd keeps the daemon alive
// unconditionally, but restarts a daemon that died right after starting at
// most once per ThrottleInterval seconds, so a permanent start failure is a
// slow retry instead of a tight loop. Static, no plutil: release-check.sh
// runs it against the installed plist on macOS, the test suite against the
// generated one anywhere.
//
// CLI: launch-agent-check.js PLIST
//   exit 0  KeepAlive true and ThrottleInterval >= MIN_THROTTLE_SECONDS
//   exit 1  a problem (printed), including a plist this reader cannot parse
// Node stdlib only.

const fs = require('fs');

const MIN_THROTTLE_SECONDS = 30;

const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

function tokenize(xml) {
  const re = /<\?[^]*?\?>|<!DOCTYPE[^>]*>|<!--[^]*?-->|<(\/?)([A-Za-z]+)(?:\s[^>]*)?(\/?)>|([^<]+)/y;
  const tokens = [];
  while (re.lastIndex < xml.length) {
    const at = re.lastIndex;
    const m = re.exec(xml);
    if (!m) throw new Error(`malformed plist at offset ${at}`);
    if (m[2]) tokens.push({ name: m[2], close: m[1] === '/', empty: m[3] === '/' });
    else if (m[4] !== undefined && m[4].trim()) {
      tokens.push({ text: m[4].replace(/&(lt|gt|amp|quot|apos);/g, (_, e) => ENTITIES[e]) });
    }
  }
  return tokens;
}

function leaf(tokens, i, name) {
  const open = tokens[i];
  if (!open || open.name !== name || open.close || open.empty) throw new Error(`malformed plist: expected <${name}>`);
  let j = i + 1;
  let text = '';
  if (tokens[j] && tokens[j].text !== undefined) text = tokens[j++].text;
  if (!tokens[j] || !tokens[j].close || tokens[j].name !== name) throw new Error(`malformed plist: unclosed <${name}>`);
  return [text, j + 1];
}

// The element subset a LaunchAgent uses; anything else fails closed rather
// than being guessed at.
function value(tokens, i) {
  const t = tokens[i];
  if (!t || t.text !== undefined || t.close) throw new Error('malformed plist: expected a value');
  if (t.empty) {
    if (t.name === 'true' || t.name === 'false') return [t.name === 'true', i + 1];
    throw new Error(`unsupported plist element <${t.name}/>`);
  }
  if (t.name === 'dict') {
    const dict = Object.create(null);
    let j = i + 1;
    while (!(tokens[j] && tokens[j].close && tokens[j].name === 'dict')) {
      const [key, next] = leaf(tokens, j, 'key');
      if (key in dict) throw new Error(`duplicate plist key ${key}`);
      [dict[key], j] = value(tokens, next);
    }
    return [dict, j + 1];
  }
  if (t.name === 'array') {
    const list = [];
    let j = i + 1;
    while (!(tokens[j] && tokens[j].close && tokens[j].name === 'array')) {
      let item;
      [item, j] = value(tokens, j);
      list.push(item);
    }
    return [list, j + 1];
  }
  if (t.name === 'string') return leaf(tokens, i, 'string');
  if (t.name === 'integer') {
    const [text, next] = leaf(tokens, i, 'integer');
    if (!/^\s*[+-]?\d+\s*$/.test(text)) throw new Error(`malformed plist integer ${JSON.stringify(text)}`);
    return [Number(text), next];
  }
  throw new Error(`unsupported plist element <${t.name}>`);
}

function parsePlist(xml) {
  const tokens = tokenize(String(xml));
  if (!tokens[0] || tokens[0].name !== 'plist' || tokens[0].close) throw new Error('not a plist document');
  const [root, next] = value(tokens, 1);
  if (!tokens[next] || tokens[next].name !== 'plist' || !tokens[next].close || next + 1 !== tokens.length) {
    throw new Error('malformed plist: trailing content');
  }
  return root;
}

function respawnPolicyProblems(xml) {
  let agent;
  try {
    agent = parsePlist(xml);
  } catch (err) {
    return [err.message];
  }
  if (!agent || typeof agent !== 'object' || Array.isArray(agent)) return ['plist root is not a dict'];
  const problems = [];
  if (agent.KeepAlive !== true) {
    problems.push(`KeepAlive must be true (got ${JSON.stringify(agent.KeepAlive)})`);
  }
  const throttle = agent.ThrottleInterval;
  if (!Number.isSafeInteger(throttle) || throttle < MIN_THROTTLE_SECONDS) {
    problems.push(`ThrottleInterval must be an integer >= ${MIN_THROTTLE_SECONDS} seconds (got ${JSON.stringify(throttle)})`);
  }
  return problems;
}

if (require.main === module) {
  const file = process.argv[2];
  if (!file) {
    process.stderr.write('usage: launch-agent-check.js PLIST\n');
    process.exit(2);
  }
  const problems = respawnPolicyProblems(fs.readFileSync(file, 'utf8'));
  for (const p of problems) process.stderr.write(`${file}: ${p}\n`);
  process.exit(problems.length ? 1 : 0);
}

module.exports = { parsePlist, respawnPolicyProblems, MIN_THROTTLE_SECONDS };
