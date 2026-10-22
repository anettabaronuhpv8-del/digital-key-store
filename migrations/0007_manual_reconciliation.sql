-- Additive, preserving all existing orders, receipts and inventory.
CREATE TABLE IF NOT EXISTS manual_refunds (
 order_id TEXT PRIMARY KEY REFERENCES orders(id),
 amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
 currency TEXT NOT NULL DEFAULT 'USD',
 method TEXT NOT NULL CHECK(method IN ('bank_transfer','cash','other')),
 refunded_on TEXT NOT NULL,
 reference TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'owner_reported' CHECK(status IN ('owner_reported','provider_confirmed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS manual_deliveries (
 order_id TEXT PRIMARY KEY REFERENCES orders(id),
 delivery_id TEXT NOT NULL UNIQUE REFERENCES deliveries(id),
 owner_note TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
