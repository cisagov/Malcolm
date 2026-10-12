// /usr/local/lib/keepalive-finish-fix.js
//
// The legacy elasticsearch client (elasticsearch@16, used by OpenSearch Dashboards) calls
// request.removeAllListeners() as soon as a response ends. If that response ends before
// the request has emitted 'finish', this also removes Node's internal 'finish' listener
// (requestOnFinish), which is what returns a keepalive socket to the agent's pool. The
// socket then stays "in use" forever, until agentkeepalive's working-socket timeout destroys
// it with an error that nothing is listening for, and the process exits.
//
// This preserves Node's own 'finish' listener across a no-argument removeAllListeners().
const { ClientRequest } = require('http');

const origRemoveAll = ClientRequest.prototype.removeAllListeners;
let warned = false;

ClientRequest.prototype.removeAllListeners = function (...args) {
  if (args.length === 0 && !this.writableFinished) {
    const finishListeners = this.listeners('finish');
    const keep = finishListeners.filter((f) => f.name === 'requestOnFinish');
    if (keep.length === 0 && finishListeners.length > 0 && !warned) {
      warned = true;
      console.error('[keepalive-finish-fix] no requestOnFinish listener found; this Node version may need a different fix');
    }
    const result = origRemoveAll.call(this);
    for (const f of keep) this.on('finish', f);
    return result;
  }
  return origRemoveAll.apply(this, args);
};
