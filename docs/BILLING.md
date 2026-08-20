# Stripe billing

## Setup

```bash
export STRIPE_SECRET_KEY=sk_test_...
export STRIPE_WEBHOOK_SECRET=whsec_...
export STRIPE_PRICE_TEAM=price_...
export STRIPE_PRICE_BUSINESS=price_...
export STRIPE_PRICE_ENTERPRISE=price_...
export BILLING_SUCCESS_URL=http://localhost:3000/admin-console/billing?success=1
export BILLING_CANCEL_URL=http://localhost:3000/admin-console/billing?canceled=1
export BILLING_PORTAL_RETURN_URL=http://localhost:3000/admin-console/billing
```

Stripe CLI webhook forwarding:

```bash
stripe listen --forward-to localhost:4000/v1/billing/webhooks/stripe
```

## APIs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/billing/catalog` | Public plan catalog |
| GET | `/v1/admin/billing/:tenantId` | Usage + subscription summary |
| POST | `/v1/admin/billing/:tenantId/checkout` | `{ plan }` → Checkout URL |
| POST | `/v1/admin/billing/:tenantId/portal` | Customer portal URL |
| GET | `/v1/admin/billing/:tenantId/invoices` | Invoice list |
| POST | `/v1/billing/webhooks/stripe` | Stripe webhooks |

## Admin UI

`/admin-console/billing` — plan cards, usage meter, invoices, portal.

## Webhook events handled

- `checkout.session.completed`
- `customer.subscription.created|updated|deleted`
- `invoice.paid|payment_failed`
