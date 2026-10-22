-- Snapshot billable credits at order creation to avoid changing pricing on an existing order.
ALTER TABLE payment_attempts ADD COLUMN credits_requested INTEGER;
UPDATE payment_attempts SET credits_requested=COALESCE((SELECT credits_per_purchase FROM product_payment_plans WHERE product_payment_plans.product_id=payment_attempts.product_id),0) WHERE credits_requested IS NULL;
CREATE INDEX IF NOT EXISTS idx_attempt_credits ON payment_attempts(plan_id,credits_requested);