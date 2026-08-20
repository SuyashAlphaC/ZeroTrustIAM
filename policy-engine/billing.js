'use strict';

/**
 * Stripe-grade billing: Checkout, Customer Portal, subscriptions, invoices, webhooks.
 *
 * Env:
 *   STRIPE_SECRET_KEY          sk_live_... / sk_test_...
 *   STRIPE_WEBHOOK_SECRET      whsec_...
 *   STRIPE_PRICE_FREE          optional (usually $0 / no subscription)
 *   STRIPE_PRICE_TEAM          price_...
 *   STRIPE_PRICE_BUSINESS      price_...
 *   STRIPE_PRICE_ENTERPRISE    price_...
 *   BILLING_SUCCESS_URL        https://app/admin-console/billing?success=1
 *   BILLING_CANCEL_URL         https://app/admin-console/billing?canceled=1
 *   BILLING_PORTAL_RETURN_URL  https://app/admin-console/billing
 */

const crypto = require('crypto');
const db = require('./database');
const tenancy = require('./tenancy');
const { logger } = require('./logger');

const STRIPE_API = 'https://api.stripe.com/v1';

function isConfigured() {
  return !!(process.env.STRIPE_SECRET_KEY);
}

function priceMap() {
  return {
    free: process.env.STRIPE_PRICE_FREE || null,
    team: process.env.STRIPE_PRICE_TEAM || null,
    business: process.env.STRIPE_PRICE_BUSINESS || null,
    enterprise: process.env.STRIPE_PRICE_ENTERPRISE || null,
  };
}

function planFromPriceId(priceId) {
  const map = priceMap();
  for (const [plan, id] of Object.entries(map)) {
    if (id && id === priceId) return plan;
  }
  return null;
}

/**
 * Stripe REST helper (form-encoded).
 */
async function stripeRequest(method, path, params = {}, { rawBody, headers: extraHeaders } = {}) {
  if (!isConfigured()) {
    const err = new Error('Stripe is not configured (STRIPE_SECRET_KEY)');
    err.code = 'STRIPE_NOT_CONFIGURED';
    throw err;
  }
  const url = path.startsWith('http') ? path : `${STRIPE_API}${path}`;
  const headers = {
    Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
    ...(extraHeaders || {}),
  };
  let body;
  if (method !== 'GET' && method !== 'DELETE') {
    if (rawBody !== undefined) {
      body = rawBody;
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams();
      const flatten = (obj, prefix = '') => {
        for (const [k, v] of Object.entries(obj)) {
          const key = prefix ? `${prefix}[${k}]` : k;
          if (v === undefined || v === null) continue;
          if (typeof v === 'object' && !Array.isArray(v)) flatten(v, key);
          else if (Array.isArray(v)) v.forEach((item, i) => {
            if (typeof item === 'object') flatten(item, `${key}[${i}]`);
            else body.append(`${key}[${i}]`, String(item));
          });
          else body.append(key, String(v));
        }
      };
      flatten(params);
      body = body.toString();
    }
  }
  const res = await fetch(url + (method === 'GET' && Object.keys(params).length
    ? `?${new URLSearchParams(params)}` : ''), {
    method,
    headers,
    body: method === 'GET' || method === 'DELETE' ? undefined : body,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(json?.error?.message || `Stripe HTTP ${res.status}`);
    err.code = json?.error?.code || 'STRIPE_ERROR';
    err.status = res.status;
    err.raw = json;
    throw err;
  }
  return json;
}

/**
 * Ensure tenant has a Stripe customer; create if missing.
 */
async function ensureCustomer(tenantId, { email, name } = {}) {
  const t = await db.getTenant(tenantId);
  if (!t) {
    const err = new Error('Tenant not found');
    err.code = 'TENANT_NOT_FOUND';
    throw err;
  }
  if (t.stripe_customer_id) {
    return { customerId: t.stripe_customer_id, tenant: t };
  }
  const customer = await stripeRequest('POST', '/customers', {
    email: email || t.billing_email || undefined,
    name: name || t.name,
    metadata: { tenant_id: tenantId, slug: t.slug },
  });
  await db.updateTenant(tenantId, {
    // store via raw SQL helper fields
  });
  await db.setTenantStripeCustomer(tenantId, customer.id);
  return { customerId: customer.id, tenant: await db.getTenant(tenantId) };
}

/**
 * Create Checkout Session for plan upgrade.
 */
async function createCheckoutSession(tenantId, plan, { successUrl, cancelUrl, email } = {}) {
  const prices = priceMap();
  const priceId = prices[plan];
  if (!priceId && plan !== 'free') {
    const err = new Error(`No Stripe price configured for plan "${plan}"`);
    err.code = 'PRICE_NOT_CONFIGURED';
    throw err;
  }
  if (plan === 'free') {
    await db.updateTenant(tenantId, { plan: 'free' });
    await db.setTenantSubscription(tenantId, {
      status: 'active',
      plan: 'free',
      stripeSubscriptionId: null,
    });
    return { mode: 'free', url: successUrl || process.env.BILLING_SUCCESS_URL };
  }

  const { customerId } = await ensureCustomer(tenantId, { email });
  const session = await stripeRequest('POST', '/checkout/sessions', {
    mode: 'subscription',
    customer: customerId,
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': 1,
    success_url: successUrl || process.env.BILLING_SUCCESS_URL
      || 'http://localhost:3000/admin-console/billing?success=1',
    cancel_url: cancelUrl || process.env.BILLING_CANCEL_URL
      || 'http://localhost:3000/admin-console/billing?canceled=1',
    client_reference_id: tenantId,
    'metadata[tenant_id]': tenantId,
    'metadata[plan]': plan,
    'subscription_data[metadata][tenant_id]': tenantId,
    'subscription_data[metadata][plan]': plan,
    allow_promotion_codes: 'true',
    billing_address_collection: 'auto',
  });

  await db.recordBillingEvent(tenantId, 'checkout.session.created', null, {
    sessionId: session.id,
    plan,
  });

  return {
    mode: 'checkout',
    sessionId: session.id,
    url: session.url,
  };
}

/**
 * Customer billing portal (update payment method, cancel, invoices).
 */
async function createPortalSession(tenantId, { returnUrl } = {}) {
  const t = await db.getTenant(tenantId);
  if (!t?.stripe_customer_id) {
    const err = new Error('No Stripe customer for tenant — start a subscription first');
    err.code = 'NO_CUSTOMER';
    throw err;
  }
  const session = await stripeRequest('POST', '/billing_portal/sessions', {
    customer: t.stripe_customer_id,
    return_url: returnUrl || process.env.BILLING_PORTAL_RETURN_URL
      || 'http://localhost:3000/admin-console/billing',
  });
  return { url: session.url };
}

/**
 * List invoices for tenant's Stripe customer.
 */
async function listInvoices(tenantId, { limit = 12 } = {}) {
  const t = await db.getTenant(tenantId);
  if (!t?.stripe_customer_id) return { invoices: [] };
  const data = await stripeRequest('GET', '/invoices', {
    customer: t.stripe_customer_id,
    limit: String(limit),
  });
  return {
    invoices: (data.data || []).map((inv) => ({
      id: inv.id,
      number: inv.number,
      status: inv.status,
      currency: inv.currency,
      amountDue: inv.amount_due,
      amountPaid: inv.amount_paid,
      created: inv.created,
      hostedInvoiceUrl: inv.hosted_invoice_url,
      invoicePdf: inv.invoice_pdf,
      periodStart: inv.period_start,
      periodEnd: inv.period_end,
    })),
  };
}

/**
 * Subscription + usage summary for UI.
 */
async function getBillingSummary(tenantId) {
  const t = await db.getTenant(tenantId);
  if (!t) return null;
  const users = await db.listUsersByTenant(tenantId);
  const limits = tenancy.getPlanLimits(t.plan || 'free');
  const events = await db.listBillingEvents(tenantId, 20);
  let stripeSub = null;
  if (t.stripe_subscription_id && isConfigured()) {
    try {
      stripeSub = await stripeRequest('GET', `/subscriptions/${t.stripe_subscription_id}`);
    } catch (err) {
      logger.warn({ err: err.message, tenantId }, 'Failed to fetch Stripe subscription');
    }
  }
  return {
    tenantId,
    plan: t.plan || 'free',
    status: t.subscription_status || (t.plan === 'free' ? 'active' : 'unknown'),
    stripeCustomerId: t.stripe_customer_id || null,
    stripeSubscriptionId: t.stripe_subscription_id || null,
    currentPeriodEnd: t.subscription_period_end || null,
    cancelAtPeriodEnd: t.cancel_at_period_end || false,
    limits,
    usage: {
      users: users.length,
      usersLimit: limits.users,
      usersPct: Math.min(100, Math.round((users.length / Math.max(limits.users, 1)) * 100)),
    },
    features: {
      scim: !!limits.scim,
      saml: !!limits.saml,
      cmk: !!limits.cmk,
      mfaRequired: !!limits.mfaRequired,
    },
    prices: Object.fromEntries(
      Object.entries(priceMap()).map(([k, v]) => [k, { configured: !!v, priceId: v }])
    ),
    stripeConfigured: isConfigured(),
    subscription: stripeSub ? {
      id: stripeSub.id,
      status: stripeSub.status,
      cancelAtPeriodEnd: stripeSub.cancel_at_period_end,
      currentPeriodEnd: stripeSub.current_period_end
        ? new Date(stripeSub.current_period_end * 1000).toISOString()
        : null,
    } : null,
    recentEvents: events,
  };
}

/**
 * Verify Stripe webhook signature (v1).
 * @param {string|Buffer} rawBody
 * @param {string} signatureHeader
 */
function verifyWebhookSignature(rawBody, signatureHeader) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      throw Object.assign(new Error('STRIPE_WEBHOOK_SECRET required'), { code: 'WEBHOOK_SECRET' });
    }
    logger.warn('Stripe webhook secret missing — skipping verify (non-production)');
    return true;
  }
  const parts = Object.fromEntries(
    String(signatureHeader || '').split(',').map((p) => {
      const [k, ...rest] = p.split('=');
      return [k.trim(), rest.join('=')];
    })
  );
  const timestamp = parts.t;
  const sig = parts.v1;
  if (!timestamp || !sig) return false;
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > 300) return false; // 5 min tolerance
  const payload = `${timestamp}.${typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8')}`;
  const expected = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch {
    return false;
  }
}

/**
 * Process Stripe webhook event.
 */
async function handleWebhookEvent(event) {
  const type = event.type;
  const obj = event.data?.object || {};
  logger.info({ type, id: event.id }, 'Stripe webhook');

  switch (type) {
    case 'checkout.session.completed': {
      const tenantId = obj.client_reference_id || obj.metadata?.tenant_id;
      if (!tenantId) break;
      const plan = obj.metadata?.plan || 'team';
      if (obj.customer) await db.setTenantStripeCustomer(tenantId, obj.customer);
      if (obj.subscription) {
        await db.setTenantSubscription(tenantId, {
          stripeSubscriptionId: obj.subscription,
          plan,
          status: 'active',
        });
      } else {
        await db.updateTenant(tenantId, { plan });
      }
      await db.recordBillingEvent(tenantId, type, obj.amount_total, {
        sessionId: obj.id,
        plan,
      });
      break;
    }
    case 'customer.subscription.updated':
    case 'customer.subscription.created': {
      const tenantId = obj.metadata?.tenant_id
        || (await db.findTenantByStripeCustomer(obj.customer))?.tenant_id;
      if (!tenantId) break;
      const priceId = obj.items?.data?.[0]?.price?.id;
      const plan = obj.metadata?.plan || planFromPriceId(priceId) || undefined;
      await db.setTenantSubscription(tenantId, {
        stripeSubscriptionId: obj.id,
        plan,
        status: obj.status,
        periodEnd: obj.current_period_end
          ? new Date(obj.current_period_end * 1000).toISOString()
          : null,
        cancelAtPeriodEnd: !!obj.cancel_at_period_end,
      });
      if (plan) await db.updateTenant(tenantId, { plan });
      await db.recordBillingEvent(tenantId, type, null, {
        subscriptionId: obj.id,
        status: obj.status,
        plan,
      });
      break;
    }
    case 'customer.subscription.deleted': {
      const tenantId = obj.metadata?.tenant_id
        || (await db.findTenantByStripeCustomer(obj.customer))?.tenant_id;
      if (!tenantId) break;
      await db.setTenantSubscription(tenantId, {
        stripeSubscriptionId: null,
        plan: 'free',
        status: 'canceled',
        periodEnd: null,
        cancelAtPeriodEnd: false,
      });
      await db.updateTenant(tenantId, { plan: 'free' });
      await db.recordBillingEvent(tenantId, type, null, { subscriptionId: obj.id });
      break;
    }
    case 'invoice.paid':
    case 'invoice.payment_failed': {
      const tenantId = (await db.findTenantByStripeCustomer(obj.customer))?.tenant_id;
      if (!tenantId) break;
      await db.recordBillingEvent(tenantId, type, obj.amount_paid ?? obj.amount_due, {
        invoiceId: obj.id,
        status: obj.status,
      });
      if (type === 'invoice.payment_failed') {
        await db.setTenantSubscription(tenantId, { status: 'past_due' });
      }
      break;
    }
    default:
      break;
  }
  return { received: true };
}

/**
 * Catalog for pricing page (static amounts for UI; Stripe is source of truth).
 */
function getCatalog() {
  return {
    currency: 'usd',
    plans: [
      {
        id: 'free',
        name: 'Free',
        priceMonthly: 0,
        description: 'Pilot & internal labs',
        features: ['25 users', 'Core MFA & risk scoring', 'Community support'],
      },
      {
        id: 'team',
        name: 'Team',
        priceMonthly: 99,
        description: 'Growing product teams',
        features: ['250 users', 'SCIM provisioning', 'Email support', 'MFA enforced'],
        highlighted: false,
      },
      {
        id: 'business',
        name: 'Business',
        priceMonthly: 499,
        description: 'Security-conscious orgs',
        features: ['5,000 users', 'SAML SSO', 'SCIM', 'CMK', 'Priority support'],
        highlighted: true,
      },
      {
        id: 'enterprise',
        name: 'Enterprise',
        priceMonthly: null,
        description: 'Global / regulated',
        features: ['Unlimited users', 'SAML + OIDC federation', 'CMK / HSM', 'Dedicated support', 'Custom DPA'],
        contactSales: true,
      },
    ],
    stripeConfigured: isConfigured(),
  };
}

module.exports = {
  isConfigured,
  priceMap,
  ensureCustomer,
  createCheckoutSession,
  createPortalSession,
  listInvoices,
  getBillingSummary,
  verifyWebhookSignature,
  handleWebhookEvent,
  getCatalog,
  stripeRequest,
};
