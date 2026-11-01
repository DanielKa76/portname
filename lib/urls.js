'use strict';

// Browser-facing URL construction, shared by the CLI and the daemon so the
// displayed gateway port always matches what the daemon actually bound.
// The upstream (dev server) port never appears in these URLs; only the
// gateway port does (omitted when it is 80).
function browserHost(name, suffix, proxyPort) {
  const host = `${name}${suffix}`;
  const port = Number(proxyPort);
  return !port || port === 80 ? host : `${host}:${port}`;
}

function localBrowserUrl(name, proxyPort) {
  return `http://${browserHost(name, '.localhost', proxyPort)}/`;
}

function lanBrowserUrl(name, proxyPort) {
  return `http://${browserHost(name, '.local', proxyPort)}/`;
}

module.exports = { browserHost, localBrowserUrl, lanBrowserUrl };
