# QC Agent → Digital Key Store x402 v2 migration audit

Date: 2026-10-22. Source reference (read-only):
`phamgialong1199-create/qc-agent-nevermined` on `main`, especially
`node-backend/server.mjs`, `node-backend/payment-ledger.mjs`,
`node-backend/buyer-verify.mjs`, and `src/index.js`.

## What the old implementation actually did

- Node SDK: `@nevermined-io/payments@1.13.0`.
- Seller: `Payments.getInstance({nvmApiKey:NVM_API_KEY, environment:NVM_ENV})`.
- Buyer sent a signed token in the `payment-signature` request header.
- Seller built an x402 v2 `paymentRequired` using plan, agent, POST endpoint,
  `nvm:card-delegation` and `stripe`.
- Verification: `facilitator.verifyPermissions({paymentRequired,
  x402AccessToken:token, maxAmount:1n})`.
- Verification result was checked via `verification.isValid === true`.
- Settlement: `facilitator.settlePermissions({paymentRequired,
  x402AccessToken:token, maxAmount:1n,
  agentRequestId:verification.agentRequest?.agentRequestId})`.
- PAYG was treated as successful only if `settlement.success===true`
  and `settlement.orderTx || settlement.transaction` was present.
- The old backend claimed a SHA-256 hash of the **token** in Postgres with
  a primary-key uniqueness rule. That prevents a subsequent independent order
  with the same reusable v2 authorization token and was **not copied**.
- A previous $1 success was reported, but it cannot be independently validated
  from source code alone. Subsequent failures included
  `PAYMENT_ALREADY_SETTLED`, `PAYMENT_UNCERTAIN_CHECK_NEVERMINED_BEFORE_RETRY`,
  and `BCK.X402.0049`. Never automatically retry an uncertain charge.

## Digital Key Store changes

- Uses the same SDK-compatible request shape in the seller-side REST adapter:
  `paymentRequired`, `x402AccessToken`, stringified `maxAmount`, and optional
  verified `agentRequestId`.
- Checks `isValid` rather than the earlier incorrect `valid` property.
- Uses PAYG `orderTx || transaction` evidence rather than treating
  `creditsSettled` as a USD payment.
- D1 payment attempt is bound to an independently generated order ID. The
  authorization token is not a unique per-order payment ID.
- Duplicate attempts on the **same order** remain blocked by an atomic state
  transition; different orders with the same v2 token may proceed only if the
  facilitator verifies and settles each independently.
- A distinct provider transaction ID is required for recorded settlement.
  Existing D1 unique constraints block reuse of that transaction ID.
- Pricing is fail-closed: PAYG provider evidence without a trustworthy fiat
  amount does **not** authorize key delivery. Such attempts require independent
  provider reconciliation; status remains uncertain and retry is forbidden.
- All public checkout remains off (`CHECKOUT_ENABLED=false`).

## $1 owner-controlled Live test readiness

Target: Package 1, 100 cents USD configured, one PAYG redemption unit, one
new order, one x402 v2 card-delegation token scoped to Package 1, and one
settlement attempt after separate explicit approval.

**Not yet ready for charge:** Payment plan's exact Stripe `Price.unit_amount`
is not independently readable with the current Nevermined Seller API Key.
Also the live settlement response's fiat amount fields have not been observed.
A token signed for the old QC Agent plan cannot be assumed valid for the new
Package 1 plan. No token should be pasted into CI, GitHub, or logs.

Before authorizing a $1 charge, confirm the official Nevermined Dashboard
$1 PAYG price / Stripe Price object; verify a new buyer token for the correct
plan without settlement; require a single-use owner-approved charge path
(not unrestricted public `CHECKOUT_ENABLED=true`); and ensure transaction
reconciliation can establish actual USD charged before releasing a key.

After any uncertain settlement, do not create a replacement order or repeat
settlement until Nevermined/Stripe payment records are reconciled.
