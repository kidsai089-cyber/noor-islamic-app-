const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
    "access-control-allow-headers": "content-type, authorization"
  }
});

const fromB64url = (s) => {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
};
const toB64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const concat = (...arrays) => {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
};
const utf8 = (s) => new TextEncoder().encode(s);

async function hkdf(secret, salt, info, length) {
  const key = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: (typeof info === "string" ? utf8(info) : info) }, key, length * 8
  ));
}

async function vapidToken(endpoint, env) {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) {
    throw new Error("VAPID_PUBLIC_KEY or VAPID_PRIVATE_KEY is missing");
  }
  const pub = fromB64url(env.VAPID_PUBLIC_KEY);
  const priv = fromB64url(env.VAPID_PRIVATE_KEY);
  if (pub.length !== 65 || priv.length !== 32) throw new Error("Invalid VAPID key length");
  const x = toB64url(pub.slice(1, 33));
  const y = toB64url(pub.slice(33, 65));
  const d = toB64url(priv);
  const key = await crypto.subtle.importKey(
    "jwk", { kty: "EC", crv: "P-256", x, y, d, ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const aud = new URL(endpoint).origin;
  const now = Math.floor(Date.now() / 1000);
  const header = toB64url(utf8(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = toB64url(utf8(JSON.stringify({
    aud, exp: now + 12 * 60 * 60,
    sub: env.VAPID_SUBJECT || "mailto:admin@noor.app"
  })));
  const input = header + "." + payload;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, key, utf8(input)
  );
  return input + "." + toB64url(signature);
}

async function encryptPush(subscription, message) {
  const uaPublic = fromB64url(subscription.p256dh);
  const auth = fromB64url(subscription.auth);
  if (uaPublic.length !== 65 || auth.length !== 16) throw new Error("Invalid subscription keys");

  const serverKeys = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const serverPublic = new Uint8Array(await crypto.subtle.exportKey("raw", serverKeys.publicKey));
  const clientPublicKey = await crypto.subtle.importKey(
    "raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: clientPublicKey }, serverKeys.privateKey, 256
  ));

  const authInfo = concat(utf8("WebPush: info\0"), uaPublic, serverPublic);
  const ikm = await hkdf(shared, auth, authInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(ikm, salt, "Content-Encoding: aes128gcm\\0", 16);
  const nonce = await hkdf(ikm, salt, "Content-Encoding: nonce\\0", 12);

  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const padded = concat(utf8(message), new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 }, aesKey, padded
  ));
  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);
  header[20] = serverPublic.length;
  return concat(header, serverPublic, ciphertext);
}

async function deliver(subscription, payload, env) {
  const endpoint = subscription.endpoint;
  const token = await vapidToken(endpoint, env);
  const body = await encryptPush(subscription, JSON.stringify(payload));
  return fetch(endpoint, {
    method: "POST",
    headers: {
      "Authorization": "vapid t=" + token + ", k=" + env.VAPID_PUBLIC_KEY,
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "TTL": "86400",
      "Urgency": "high"
    },
    body
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type, authorization"
    }});
    if (url.pathname === "/health") return json({ ok: true, service: "noor-prayer-push" });
    if (!env.DB) return json({ error: "D1 binding DB is not configured" }, 503);

    if (url.pathname === "/api/subscribe" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      if (!body?.endpoint || !body?.keys?.p256dh || !body?.keys?.auth) {
        return json({ error: "A valid PushSubscription is required" }, 400);
      }
      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO push_subscriptions (id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth, updated_at=CURRENT_TIMESTAMP"
      ).bind(id, body.endpoint, body.keys.p256dh, body.keys.auth).run();
      return json({ ok: true, message: "Subscription saved" });
    }

    if (url.pathname === "/api/unsubscribe" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      if (!body?.endpoint) return json({ error: "endpoint is required" }, 400);
      await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint = ?").bind(body.endpoint).run();
      return json({ ok: true });
    }

    if (url.pathname === "/api/schedule" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      if (!body?.endpoint || !Array.isArray(body.schedules) || !body.schedules.length) {
        return json({ error: "endpoint and a non-empty schedules array are required" }, 400);
      }
      const sub = await env.DB.prepare(
        "SELECT id FROM push_subscriptions WHERE endpoint = ?"
      ).bind(body.endpoint).first();
      if (!sub) return json({ error: "Subscribe this device before adding schedules" }, 404);
      const insert = env.DB.prepare(
        "INSERT INTO prayer_schedules (id, subscription_id, prayer_name, prayer_at, timezone) VALUES (?, ?, ?, ?, ?)"
      );
      const statements = [];
      for (const item of body.schedules) {
        if (!item?.prayer_name || !item?.prayer_at || !item?.timezone ||
            !Number.isFinite(Date.parse(item.prayer_at))) {
          return json({ error: "Each schedule needs prayer_name, valid prayer_at, and timezone" }, 400);
        }
        statements.push(insert.bind(crypto.randomUUID(), sub.id, String(item.prayer_name),
          new Date(item.prayer_at).toISOString(), String(item.timezone)));
      }
      await env.DB.batch(statements);
      return json({ ok: true, saved: statements.length });
    }

    return json({ error: "Not found" }, 404);
  },

  async scheduled(controller, env, ctx) {
    if (!env.DB || !env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) {
      console.error("Noor cron skipped: DB or VAPID secrets are missing");
      return;
    }
    const now = new Date().toISOString();
    const due = await env.DB.prepare(
      "SELECT s.id AS schedule_id, s.prayer_name, s.prayer_at, p.endpoint, p.p256dh, p.auth " +
      "FROM prayer_schedules s JOIN push_subscriptions p ON p.id = s.subscription_id " +
      "WHERE s.sent_at IS NULL AND s.prayer_at <= ? ORDER BY s.prayer_at LIMIT 100"
    ).bind(now).all();

    for (const item of due.results || []) {
      try {
        const response = await deliver(item, {
          title: "Noor — " + item.prayer_name,
          body: "নামাজের সময় হয়েছে।",
          tag: "prayer-" + item.schedule_id,
          url: "/"
        }, env);
        if (response.ok) {
          await env.DB.prepare("UPDATE prayer_schedules SET sent_at = ? WHERE id = ?")
            .bind(new Date().toISOString(), item.schedule_id).run();
        } else if (response.status === 404 || response.status === 410) {
          await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint = ?")
            .bind(item.endpoint).run();
        } else {
          console.error("Push provider rejected notification:", response.status);
        }
      } catch (error) {
        console.error("Noor push delivery failed:", String(error));
      }
    }
  }
};
