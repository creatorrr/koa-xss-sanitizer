"use strict";

const get = require("lodash.get");
const set = require("lodash.set");

const sanitize = require("./lib/sanitize");

function middleware(options = {}) {
  return async (ctx, next) => {
    ["body", "headers", "query", "request.body"].forEach((path) => {
      const data = get(ctx, path, null);
      if (data) {
        set(ctx, path, sanitize(data, options));
      }
    });

    await next();
  };
}

module.exports = {
  xss: middleware,
  sanitize,
};
