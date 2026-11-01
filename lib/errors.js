'use strict';

// Control-protocol errors carry a stable machine-readable code next to the
// legacy human-readable message. Old clients keep reading `error`; newer
// clients (the macOS app) branch on `code`.
class ControlError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ControlError';
    this.code = code;
  }
}

module.exports = { ControlError };
