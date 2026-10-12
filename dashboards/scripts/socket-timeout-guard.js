// /usr/local/lib/socket-timeout-guard.js
process.on('uncaughtException', (err) => {
  if (err && err.code === 'ERR_SOCKET_TIMEOUT') {
    console.error(`[socket-timeout-guard] ignoring agentkeepalive socket timeout (${err.timeout}ms)`);
    return;
  }
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
