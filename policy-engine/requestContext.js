'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');

const store = new AsyncLocalStorage();

function middleware() {
  return (req, res, next) => {
    const id = req.id || req.headers['x-request-id'];
    store.run({ requestId: id }, () => next());
  };
}

function getRequestId() {
  return store.getStore()?.requestId;
}

module.exports = { middleware, getRequestId };
