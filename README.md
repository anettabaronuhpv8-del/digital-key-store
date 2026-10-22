# Digital Key Store

English-only digital key storefront on Cloudflare Workers + D1. **The public store defaults to checkout disabled and must not be used for Live payments before Nevermined sandbox and Live tests are approved.**

- Store URL: https://digital-key-store.anettabaronuhpv8.workers.dev
- Owner login: https://digital-key-store.anettabaronuhpv8.workers.dev/admin
- Cloudflare D1: `digital-key-store-db` / `1296d184-6168-49a1-9311-7df37499818e`
- Default packages: Package 1 ($1 / Key Type A), Package 2 ($2 / Key Type B), Package 3 ($3 / Key Type C), Package 5 ($5 / Key Type D).

## Security / operations

The owner receives a high-entropy bootstrap password, configured as an encrypted Cloudflare Worker secret `ADMIN_BOOTSTRAP_PASSWORD`. Administration uses a signed, HttpOnly, Secure, SameSite=Strict cookie, Origin checks and a 6-attempt/15-minute IP throttle. Protect the password: never commit it to GitHub. Session verification requires `SESSION_SECRET`. Inventory is encrypted with AES-256-GCM and HMAC-deduplicated using `INVENTORY_SECRET`, and seller API keys entered in admin are encrypted in D1 with `CONFIG_SECRET`, all configured as Cloudflare Worker secrets. Keep all secrets out of code and repository. Never rotate encryption secrets without migrating and backing up ciphertext first.

The admin supports editable product names, descriptions, prices, activation flags, creation/soft deletion, isolated TXT inventory imports, stock/sold counts, revenue, payment plan IDs, credit units, agent ID, payment network and Nevermined environment. API key entry in Admin replaces the saved encrypted seller credential; the current API key is never reflected to the browser.

## Official x402 API contract

`POST https://api.[sandbox|live].nevermined.app/api/v1/x402/verify` with `{accessToken,agentId,creditsRequested}` and `POST .../settle` with `{accessToken,agentId,creditsUsed,requestMetadata:{orderId}}`, authenticated with `Authorization: Bearer <seller-key>`. Sources: https://nevermined.ai/docs/api-reference/x402/verify-permission and https://nevermined.ai/docs/api-reference/x402/settle-permission . These endpoints are implemented without a local fake fallback. The store blocks delivery until the settle receipt confirms `success:true`, the exact configured credits, a `txHash`, and a permission hash. Credits and USD price are separately configured; their equivalence requires provider-side verification before activation. Tokens must advertise the correct per-product Plan, Agent, scheme and network and are independently verified at the facilitator.

An order is single-use and purchases always have quantity 1. A new purchase produces a new order ID and can reuse the token only if the facilitator genuinely allows it. A duplicate request for one order never retries payment. An ambiguous settlement/error, including `BCK.X402.0049`, leaves the attempt uncertain and inventory reserved; the owner must reconcile it. Paid orders can retry D1 delivery without a new settlement. No customer login is required, only a per-order secret used for recovery.

**Important limitations before Live:** Cross-plan token use is not guaranteed. Card-delegation receipt fields and credit-to-USD equivalence must be verified with a real, explicit, approved transaction. The current `CHECKOUT_ENABLED` binding is `false`. Never run Live purchases without owner approval. The public website uses no simulated payment provider.

## Tests

`npm test` executes the 25 Node-based tests, including full Worker request flows with an in-memory SQLite D1-compatible harness and mocked Nevermined HTTP responses. Test doubles are supplied by the test runner, not shipped in the Worker code. These are not proof of Nevermined Live settlement.

## Cloudflare deployment

The Worker and D1 database already exist; **do not recreate them**. `wrangler.toml` references the existing D1 ID. Apply the additive `migrations/0005_reservations_admin.sql` once (already applied to the existing remote D1 on 2026-10-22). In a fresh local database, apply `0001_current_schema.sql` then indexes and `0005`.

Never put seller API keys, real inventory TXT files or owner login credentials in source control. `CHECKOUT_ENABLED` must remain `false` until an independently reviewed sandbox test and owner-approved Live test succeed. The owner may add their seller API key and plan IDs through the protected Admin; changing checkout activation requires an explicit Cloudflare configuration update after verification.