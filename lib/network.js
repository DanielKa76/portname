'use strict';

const os = require('os');
const net = require('net');

// Interfaces to ignore when detecting physical LAN/Wi-Fi
const IGNORE_PREFIXES = [
  'lo',
  'utun',
  'tun',
  'tap',
  'tailscale',
  'bridge',
  'docker',
  'vbox',
  'vmnet',
  'p2p',
  'awdl',
  'llw',
  'anpi',
];

function isIgnoredInterface(name) {
  const lower = name.toLowerCase();
  return IGNORE_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

// Selects the active physical LAN/Wi-Fi interface on macOS.
// Prefers en0 (the standard Wi-Fi / primary interface on Apple Silicon / macOS),
// falling back to other physical en* interfaces with a non-internal IPv4 address.
function getLanInterface(interfaces = os.networkInterfaces()) {
  let fallback = null;

  for (const [name, list] of Object.entries(interfaces)) {
    if (isIgnoredInterface(name)) continue;

    for (const info of list || []) {
      if (info.internal || info.family !== 'IPv4') continue;

      const candidate = {
        name,
        address: info.address,
        netmask: info.netmask,
        family: 'IPv4',
      };

      if (name.toLowerCase() === 'en0') {
        return candidate;
      }

      if (!fallback && name.toLowerCase().startsWith('en')) {
        fallback = candidate;
      }
    }
  }

  return fallback;
}

function cleanIpv4(ip) {
  if (!ip) return null;
  let s = String(ip).trim();
  if (s.startsWith('::ffff:')) s = s.slice('::ffff:'.length);
  return net.isIPv4(s) ? s : null;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function isIpInSubnet(ip, subnetIp, netmask) {
  const cleanTarget = cleanIpv4(ip);
  const cleanSubnet = cleanIpv4(subnetIp);
  const cleanMask = cleanIpv4(netmask);

  if (!cleanTarget || !cleanSubnet || !cleanMask) return false;

  const targetInt = ipv4ToInt(cleanTarget);
  const subnetInt = ipv4ToInt(cleanSubnet);
  const maskInt = ipv4ToInt(cleanMask);

  return (targetInt & maskInt) === (subnetInt & maskInt);
}

// Verifies that a connection arrived on the designated LAN interface
// and originated from a client within that same LAN subnet.
function isAuthorizedLanClient({ localAddress, remoteAddress, lanInfo } = {}) {
  if (!lanInfo || !lanInfo.address || !lanInfo.netmask) return false;

  const cleanLocal = cleanIpv4(localAddress);
  const cleanRemote = cleanIpv4(remoteAddress);

  if (!cleanLocal || !cleanRemote) return false;

  // Connection must have been accepted on this Mac's LAN interface address
  if (cleanLocal !== cleanIpv4(lanInfo.address)) {
    return false;
  }

  // Client must be within the same subnet
  return isIpInSubnet(cleanRemote, lanInfo.address, lanInfo.netmask);
}

module.exports = {
  getLanInterface,
  isIpInSubnet,
  isAuthorizedLanClient,
  cleanIpv4,
};
