const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" }
});

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
        "access-control-allow-headers": "content-type, authorization"
      }});
    }
    if (url.pathname === "/health") return json({ ok: true, service: "noor-prayer-push" });

    if (url.pathname === "/api/subscribe" && request.method === "POST") {
      if (!env.DB) return json({ error: "D1 binding DB is not configured" }, 503);
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
      if (!env.DB) return json({ error: "D1 binding DB is not configured" }, 503);
      const body = await request.json().catch(() => null);
      if (!body?.endpoint) return json({ error: "endpoint is required" }, 400);
      await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint = ?").bind(body.endpoint).run();
      return json({ ok: true });
    }

    return json({ error: "Not found" }, 404);
  },

  async scheduled(controller, env, ctx) {
    // The cron trigger is registered, but Web Push delivery is intentionally
    // not activated until VAPID signing/sending is configured and tested.
    // Never silently report a notification as delivered.
    if (!env.DB) return;
    const due = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM prayer_schedules WHERE sent_at IS NULL AND prayer_at <= ?"
    ).bind(new Date().toISOString()).first();
    console.log("Noor due prayer notifications awaiting configured Web Push sender:", due?.total ?? 0);
  }
};
