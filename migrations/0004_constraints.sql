-- Applied to existing Cloudflare D1 on 2026-10-22.
CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_order_provider ON payments(order_id,provider);
CREATE UNIQUE INDEX IF NOT EXISTS ux_deliveries_item ON deliveries(order_item_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_product_id ON inventory(product_id,id);
CREATE INDEX IF NOT EXISTS idx_attempts_order_status ON payment_attempts(order_id,status);
