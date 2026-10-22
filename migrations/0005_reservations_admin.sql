-- Additive migration for EXISTING digital-key-store-db. No databases recreated.
CREATE TABLE IF NOT EXISTS inventory_reservations (
 inventory_id TEXT PRIMARY KEY REFERENCES inventory(id),
 order_id TEXT NOT NULL UNIQUE REFERENCES orders(id),
 state TEXT NOT NULL CHECK(state IN ('reserved','consumed','released')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_reservations_state ON inventory_reservations(state);
CREATE TABLE IF NOT EXISTS admin_login_attempts (
 ip_hash TEXT PRIMARY KEY,
 failures INTEGER NOT NULL DEFAULT 0,
 started_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_orders_access ON orders(access_token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_order ON payments(order_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_deliveries_order ON deliveries(order_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_sold_order_item ON inventory(order_item_id) WHERE order_item_id IS NOT NULL;