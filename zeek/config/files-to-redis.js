import { createClient } from 'redis';

let client;
let ready = false;

client = createClient({
  socket: {
    host: process.env.REDIS_CACHE_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_CACHE_PORT || '6379', 10),
    reconnectStrategy: (retries) => {
      // Exponential backoff: 1s, 2s, 4s, 8s...
      const delay = Math.min(1000 * Math.pow(2, retries), 30000);
      console.error(`Redis reconnect attempt ${retries} (waiting ${delay}ms)`);
      return delay;
    }
  },
  database: parseInt(process.env.REDIS_FILESCAN_CACHE_DATABASE || '0', 10),
  password: process.env.REDIS_PASSWORD || undefined,
});

// Error handler so Zeek doesn't crash
client.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

// Track readiness
client.on('ready', () => {
  ready = true;
  console.log('Redis: connected and ready');
});

// Track disconnects
client.on('end', () => {
  ready = false;
  console.error('Redis: connection lost');
});

// Connect, safely
(async () => {
  try {
    await client.connect();
  } catch (err) {
    console.error('Redis initial connection failed:', err);
  }
})();

zeek.hook('Files::log_policy', (rec, id, filter) => {
  if (!ready) {
    console.error('Redis not ready; skipping LPUSH');
    return;
  }

  if (rec?.extracted) {
    const data = {
      conn: rec.id,
      uid: rec.uid,
      fuid: rec.fuid,
      source: rec.source,
      filename: rec.filename,
    };

    client.lPush(rec.fuid, JSON.stringify(data))
      .catch(err => console.error('Redis LPUSH failed:', err));
  }
});
