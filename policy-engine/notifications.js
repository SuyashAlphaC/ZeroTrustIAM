'use strict';

/**
 * User lifecycle notifications (email + SMS).
 *
 * Modes (NOTIFICATION_MODE):
 *  - log   (default) — structured logs + DB outbox; no external network
 *  - smtp  — send email via SMTP (nodemailer); SMS still Twilio or log
 *  - full  — SMTP email + Twilio SMS when configured
 *
 * Credentials are never required for the service to start. Missing providers
 * fall back to log so onboarding keeps working in local/dev.
 */

const config = require('./config');
const { logger } = require('./logger');

const TEMPLATES = {
  USER_ONBOARDED: {
    subject: (p) => `Your ${p.orgName} account is ready`,
    email: (p) => [
      `Hello ${p.userId},`,
      '',
      `An administrator (${p.actor}) created your ZeroTrust IAM account.`,
      '',
      `Username: ${p.userId}`,
      `Role: ${p.role || 'viewer'}`,
      `Sign-in: ${p.loginUrl}`,
      p.tempPassword
        ? `\nTemporary password: ${p.tempPassword}\nPlease change it after your first sign-in.`
        : '\nYour temporary password was shared separately by your administrator.',
      '',
      'Your browser will be bound automatically as a trusted device after sign-in.',
      '',
      '— ZeroTrust IAM',
    ].join('\n'),
    sms: (p) => p.tempPassword
      ? `${p.orgName}: account ${p.userId} ready. Sign in at ${p.loginUrl}. Temp password sent via email/admin.`
      : `${p.orgName}: account ${p.userId} created by admin. Sign in: ${p.loginUrl}`,
  },
  USER_SUSPENDED: {
    subject: (p) => `Your ${p.orgName} account was suspended`,
    email: (p) => [
      `Hello ${p.userId},`,
      '',
      `Your account was suspended by administrator ${p.actor}.`,
      'You cannot sign in until an admin re-activates the account.',
      'All active sessions have been revoked.',
      '',
      'If you did not expect this, contact your security team.',
      '',
      '— ZeroTrust IAM',
    ].join('\n'),
    sms: (p) => `${p.orgName}: account ${p.userId} suspended by admin. Sessions revoked.`,
  },
  USER_ACTIVATED: {
    subject: (p) => `Your ${p.orgName} account was re-activated`,
    email: (p) => [
      `Hello ${p.userId},`,
      '',
      `Your account was re-activated by administrator ${p.actor}.`,
      `You can sign in again at ${p.loginUrl}.`,
      '',
      '— ZeroTrust IAM',
    ].join('\n'),
    sms: (p) => `${p.orgName}: account ${p.userId} re-activated. Sign in: ${p.loginUrl}`,
  },
  SESSIONS_REVOKED: {
    subject: (p) => `Your ${p.orgName} sessions were revoked`,
    email: (p) => [
      `Hello ${p.userId},`,
      '',
      `All of your active sessions were revoked by administrator ${p.actor}.`,
      'You will need to sign in again on every device.',
      '',
      'If you did not request this, change your password and contact security.',
      '',
      '— ZeroTrust IAM',
    ].join('\n'),
    sms: (p) => `${p.orgName}: all sessions for ${p.userId} were revoked by admin.`,
  },
  PASSWORD_RESET_ADMIN: {
    subject: (p) => `Your ${p.orgName} password was reset`,
    email: (p) => [
      `Hello ${p.userId},`,
      '',
      `An administrator (${p.actor}) reset your password.`,
      'All sessions were revoked.',
      p.tempPassword
        ? `\nTemporary password: ${p.tempPassword}\nChange it after you sign in.`
        : '\nYour temporary password was shared separately by your administrator.',
      '',
      `Sign-in: ${p.loginUrl}`,
      '',
      '— ZeroTrust IAM',
    ].join('\n'),
    sms: (p) => `${p.orgName}: password for ${p.userId} was reset by admin. Check email for details.`,
  },
  USER_EVICTED: {
    subject: (p) => `Your ${p.orgName} account was removed`,
    email: (p) => [
      `Hello ${p.userId},`,
      '',
      `Your account was permanently removed/redacted by administrator ${p.actor}.`,
      'You can no longer sign in. Contact your organization if this was unexpected.',
      '',
      '— ZeroTrust IAM',
    ].join('\n'),
    sms: (p) => `${p.orgName}: account ${p.userId} was removed by admin.`,
  },
};

function buildPayload(event, ctx) {
  const tpl = TEMPLATES[event];
  if (!tpl) throw new Error(`Unknown notification event: ${event}`);
  const p = {
    orgName: config.notifyOrgName,
    loginUrl: config.notifyLoginUrl,
    userId: ctx.userId,
    actor: ctx.actor || 'admin',
    role: ctx.role,
    tempPassword: ctx.tempPassword && config.notifyIncludeTempPassword ? ctx.tempPassword : null,
  };
  return {
    subject: tpl.subject(p),
    emailBody: tpl.email(p),
    smsBody: tpl.sms(p),
  };
}

async function sendEmail({ to, subject, text }) {
  if (!to) return { channel: 'email', status: 'skipped', reason: 'no_email' };
  if (!config.notifyEmailEnabled) {
    logger.info({ to, subject, preview: text.slice(0, 120) }, 'notify email (log mode)');
    return { channel: 'email', status: 'logged', to, subject };
  }

  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch {
    logger.warn('nodemailer not installed — logging email instead');
    logger.info({ to, subject }, 'notify email fallback log');
    return { channel: 'email', status: 'logged_no_transport', to, subject };
  }

  const transport = nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpSecure,
    auth: config.smtpUser ? { user: config.smtpUser, pass: config.smtpPass } : undefined,
  });

  const info = await transport.sendMail({
    from: config.smtpFrom,
    to,
    subject,
    text,
  });
  return { channel: 'email', status: 'sent', to, subject, messageId: info.messageId };
}

async function sendSms({ to, body }) {
  if (!to) return { channel: 'sms', status: 'skipped', reason: 'no_phone' };
  if (!config.notifySmsEnabled) {
    logger.info({ to, preview: body.slice(0, 120) }, 'notify sms (log mode)');
    return { channel: 'sms', status: 'logged', to };
  }

  const url = `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.twilioAccountSid)}/Messages.json`;
  const auth = Buffer.from(`${config.twilioAccountSid}:${config.twilioAuthToken}`).toString('base64');
  const form = new URLSearchParams({
    To: to,
    From: config.twilioFrom,
    Body: body,
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: form.toString(),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Twilio SMS failed HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  let sid = null;
  try { sid = JSON.parse(text).sid; } catch { /* ignore */ }
  return { channel: 'sms', status: 'sent', to, sid };
}

/**
 * Notify a user about a lifecycle event. Never throws to callers — returns result.
 *
 * @param {string} event  TEMPLATE key
 * @param {{ userId, email?, phone?, actor?, role?, tempPassword? }} ctx
 */
async function notifyUser(event, ctx = {}) {
  if (!config.notifyEnabled) {
    return { skipped: true, reason: 'disabled' };
  }

  const userId = ctx.userId;
  if (!userId) return { skipped: true, reason: 'no_user' };

  let email = ctx.email || null;
  let phone = ctx.phone || null;
  if ((!email || !phone) && userId) {
    try {
      const db = require('./database');
      const u = await db.getUser(userId);
      if (u) {
        email = email || u.email || null;
        phone = phone || u.phone || null;
      }
    } catch { /* best-effort */ }
  }

  let content;
  try {
    content = buildPayload(event, { ...ctx, userId });
  } catch (err) {
    logger.error({ err: err.message, event }, 'notify template failed');
    return { ok: false, error: err.message };
  }

  const results = [];
  try {
    results.push(await sendEmail({ to: email, subject: content.subject, text: content.emailBody }));
  } catch (err) {
    logger.error({ err: err.message, userId, event }, 'notify email failed');
    results.push({ channel: 'email', status: 'error', error: err.message });
  }
  try {
    results.push(await sendSms({ to: phone, body: content.smsBody }));
  } catch (err) {
    logger.error({ err: err.message, userId, event }, 'notify sms failed');
    results.push({ channel: 'sms', status: 'error', error: err.message });
  }

  try {
    const db = require('./database');
    await db.recordNotification({
      userId,
      event,
      channels: results,
      actor: ctx.actor || null,
      subject: content.subject,
    });
  } catch (err) {
    logger.debug({ err: err.message }, 'notify outbox write failed');
  }

  const ok = results.some((r) => r.status === 'sent' || r.status === 'logged' || r.status === 'logged_no_transport');
  logger.info({ userId, event, results }, 'lifecycle notification dispatched');
  return { ok, event, userId, results };
}

/** Fire-and-forget wrapper for request handlers. */
function notifyUserAsync(event, ctx) {
  setImmediate(() => {
    notifyUser(event, ctx).catch((err) => {
      logger.warn({ err: err.message, event }, 'async notify failed');
    });
  });
}

module.exports = {
  TEMPLATES,
  notifyUser,
  notifyUserAsync,
  buildPayload,
};
