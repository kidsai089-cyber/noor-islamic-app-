CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS prayer_schedules (
  id TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL,
  prayer_name TEXT NOT NULL,
  prayer_at TEXT NOT NULL,
  timezone TEXT NOT NULL,
  sent_at TEXT,
  FOREIGN KEY (subscription_id) REFERENCES push_subscriptions(id)
);

CREATE INDEX IF NOT EXISTS idx_prayer_schedules_due
  ON prayer_schedules(prayer_at, sent_at);
