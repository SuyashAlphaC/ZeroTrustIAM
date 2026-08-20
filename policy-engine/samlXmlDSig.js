'use strict';

/**
 * Full SAML XMLDSig verification with exclusive C14N.
 *
 * Handles IdP edge cases:
 *  - Response-level and/or Assertion-level signatures
 *  - Enveloped-signature transform
 *  - Exclusive C14N with InclusiveNamespaces PrefixList
 *  - Multiple certs in KeyInfo / configured IdP cert pins
 *  - RSA-SHA1 / RSA-SHA256 / RSA-SHA512
 *  - Assertion Conditions (NotBefore / NotOnOrAfter) with clock skew
 *  - AudienceRestriction vs SP entity ID
 *  - Destination vs ACS URL
 *  - InResponseTo correlation (optional)
 */

const crypto = require('crypto');
const {
  exclusiveCanonicalize,
  parseXml,
  findByLocalName,
  findAllByLocalName,
  getInclusivePrefixList,
} = require('./samlExclusiveC14n');
const { logger } = require('./logger');

const ALG_MAP = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'RSA-SHA1',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'RSA-SHA256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'RSA-SHA512',
  'http://www.w3.org/2000/09/xmldsig#sha1': 'sha1',
  'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256',
  'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
};

function pemFromBase64Cert(b64) {
  const clean = String(b64).replace(/\s+/g, '');
  const lines = clean.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function normalizePem(cert) {
  if (!cert) return '';
  let c = cert.replace(/\\n/g, '\n').trim();
  if (!c.includes('BEGIN CERTIFICATE')) {
    c = pemFromBase64Cert(c);
  }
  return c;
}

/**
 * Remove Signature element(s) that are descendants of node (enveloped transform).
 * Operates on a clone.
 */
function stripEnvelopedSignatures(element) {
  const sigs = findAllByLocalName(element, 'Signature');
  for (const s of sigs) {
    if (s.parentNode) s.parentNode.removeChild(s);
  }
  return element;
}

/**
 * Clone via re-serialize + parse of subtree (xmldom has limited importNode).
 */
function cloneElement(el) {
  const xml = el.toString ? el.toString() : serializeFallback(el);
  const doc = parseXml(xml);
  return doc.documentElement;
}

function serializeFallback(el) {
  // last resort — exclusiveCanonicalize itself can re-serialize structure
  return exclusiveCanonicalize(el);
}

/**
 * Apply transforms listed in Reference and return canonical bytes string.
 */
function applyTransforms(referencedElement, transformsEl) {
  let node = cloneElement(referencedElement);
  const transforms = transformsEl ? findAllByLocalName(transformsEl, 'Transform') : [];
  let inclusiveList = '';

  for (const t of transforms) {
    const alg = t.getAttribute('Algorithm') || '';
    if (alg.includes('enveloped-signature')) {
      stripEnvelopedSignatures(node);
    } else if (alg.includes('xml-exc-c14n')) {
      inclusiveList = getInclusivePrefixList(t) || inclusiveList;
    } else if (alg.includes('xml-c14n') && !alg.includes('exc')) {
      // inclusive C14N — treat as exclusive with empty inclusive list for SAML (most IdPs use exclusive)
      inclusiveList = getInclusivePrefixList(t) || inclusiveList;
    }
  }

  // If no C14N transform listed, SAML still requires exclusive C14N for SignedInfo/refs commonly
  return exclusiveCanonicalize(node, { inclusiveNamespacesPrefixList: inclusiveList });
}

/**
 * Verify one ds:Signature element against pinned certs.
 * @returns {{ ok: boolean, reason?: string, signedInfoC14n?: string }}
 */
function verifySignatureElement(signatureEl, documentRoot, trustedCerts) {
  const signedInfo = findByLocalName(signatureEl, 'SignedInfo');
  const sigValueEl = findByLocalName(signatureEl, 'SignatureValue');
  const keyInfo = findByLocalName(signatureEl, 'KeyInfo');
  if (!signedInfo || !sigValueEl) {
    return { ok: false, reason: 'Signature missing SignedInfo or SignatureValue' };
  }

  // C14N method for SignedInfo
  const c14nMethod = findByLocalName(signedInfo, 'CanonicalizationMethod');
  const c14nAlg = c14nMethod?.getAttribute('Algorithm') || 'http://www.w3.org/2001/10/xml-exc-c14n#';
  let siInclusive = '';
  if (c14nMethod) {
    siInclusive = getInclusivePrefixList(c14nMethod);
    // InclusiveNamespaces may be child of CanonicalizationMethod
    const inc = findByLocalName(c14nMethod, 'InclusiveNamespaces');
    if (inc) siInclusive = inc.getAttribute('PrefixList') || siInclusive;
  }

  // SignedInfo must be exclusive-canonicalized (with xmlns:ds in scope for many IdPs)
  // Ensure Signature's namespace is on SignedInfo by cloning Signature and c14n SignedInfo
  const sigClone = cloneElement(signatureEl);
  const siClone = findByLocalName(sigClone, 'SignedInfo');
  const signedInfoC14n = exclusiveCanonicalize(siClone, {
    inclusiveNamespacesPrefixList: siInclusive,
  });

  const sigMethod = findByLocalName(signedInfo, 'SignatureMethod');
  const sigAlgUri = sigMethod?.getAttribute('Algorithm') || '';
  const nodeAlg = ALG_MAP[sigAlgUri] || 'RSA-SHA256';

  // Collect certs: KeyInfo + trusted pins
  const certs = [...trustedCerts];
  if (keyInfo) {
    for (const x509 of findAllByLocalName(keyInfo, 'X509Certificate')) {
      const b64 = (x509.textContent || '').replace(/\s+/g, '');
      if (b64) certs.push(normalizePem(b64));
    }
  }
  if (!certs.length) return { ok: false, reason: 'No certificates available for verification' };

  const sigB64 = (sigValueEl.textContent || '').replace(/\s+/g, '');
  const sigBuf = Buffer.from(sigB64, 'base64');

  let sigOk = false;
  for (const pem of certs) {
    try {
      const verifier = crypto.createVerify(nodeAlg);
      verifier.update(signedInfoC14n);
      verifier.end();
      if (verifier.verify(pem, sigBuf)) {
        sigOk = true;
        break;
      }
    } catch (err) {
      logger.debug({ err: err.message }, 'cert verify attempt failed');
    }
  }
  if (!sigOk) return { ok: false, reason: 'SignatureValue cryptographic verification failed' };

  // Verify each Reference digest
  const references = findAllByLocalName(signedInfo, 'Reference');
  if (!references.length) return { ok: false, reason: 'SignedInfo has no Reference' };

  for (const ref of references) {
    const uri = ref.getAttribute('URI') || '';
    let target = null;
    if (!uri || uri === '') {
      target = documentRoot;
    } else if (uri.startsWith('#')) {
      const id = uri.slice(1);
      // Search by Id / ID / wsu:Id
      const all = documentRoot.ownerDocument
        ? documentRoot.ownerDocument.getElementsByTagName('*')
        : documentRoot.getElementsByTagName('*');
      for (let i = 0; i < all.length; i++) {
        const el = all.item(i);
        const cand = el.getAttribute('ID') || el.getAttribute('Id') || el.getAttribute('id')
          || el.getAttributeNS?.('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd', 'Id');
        if (cand === id) {
          target = el;
          break;
        }
      }
    }
    if (!target) return { ok: false, reason: `Reference URI not found: ${uri}` };

    const transforms = findByLocalName(ref, 'Transforms');
    const c14n = applyTransforms(target, transforms);
    const digestMethod = findByLocalName(ref, 'DigestMethod');
    const digestUri = digestMethod?.getAttribute('Algorithm') || '';
    const hashName = ALG_MAP[digestUri] || 'sha256';
    const digestValue = (findByLocalName(ref, 'DigestValue')?.textContent || '').replace(/\s+/g, '');
    const actual = crypto.createHash(hashName).update(c14n, 'utf8').digest('base64');
    if (actual !== digestValue) {
      return {
        ok: false,
        reason: `Digest mismatch for ${uri}: expected ${digestValue}, got ${actual}`,
      };
    }
  }

  return { ok: true, signedInfoC14n };
}

/**
 * High-level: verify SAML Response XML.
 *
 * @param {string} xml
 * @param {{
 *   idpCerts: string[],
 *   spEntityId: string,
 *   acsUrl: string,
 *   wantAssertionsSigned?: boolean,
 *   wantResponseSigned?: boolean,
 *   clockSkewSeconds?: number,
 *   expectedInResponseTo?: string|null,
 * }} opts
 */
function verifySamlResponse(xml, opts) {
  const doc = parseXml(xml);
  const response = findByLocalName(doc, 'Response');
  if (!response) {
    return { ok: false, reason: 'No samlp:Response root' };
  }

  const trusted = (opts.idpCerts || []).map(normalizePem).filter(Boolean);
  const skew = (opts.clockSkewSeconds ?? 120) * 1000;
  const now = Date.now();

  // Destination
  const destination = response.getAttribute('Destination');
  if (destination && opts.acsUrl && destination !== opts.acsUrl) {
    return { ok: false, reason: `Destination mismatch: ${destination}` };
  }

  // Status
  const statusCode = findByLocalName(response, 'StatusCode');
  const statusVal = statusCode?.getAttribute('Value') || '';
  if (statusVal && !statusVal.endsWith('Success')) {
    return { ok: false, reason: `SAML status not Success: ${statusVal}` };
  }

  // InResponseTo
  if (opts.expectedInResponseTo) {
    const irt = response.getAttribute('InResponseTo');
    if (irt && irt !== opts.expectedInResponseTo) {
      return { ok: false, reason: 'InResponseTo mismatch' };
    }
  }

  const responseSigs = [];
  const assertionSigs = [];
  for (const sig of findAllByLocalName(response, 'Signature')) {
    // classify by parent
    let p = sig.parentNode;
    const local = p?.localName || p?.nodeName || '';
    if (local === 'Response' || local.endsWith(':Response')) responseSigs.push(sig);
    else if (local === 'Assertion' || local.endsWith(':Assertion')) assertionSigs.push(sig);
    else {
      // nested — walk up
      let cur = p;
      while (cur) {
        const ln = cur.localName || cur.nodeName || '';
        if (ln === 'Assertion' || ln.endsWith(':Assertion')) {
          assertionSigs.push(sig);
          break;
        }
        if (ln === 'Response' || ln.endsWith(':Response')) {
          responseSigs.push(sig);
          break;
        }
        cur = cur.parentNode;
      }
    }
  }

  const wantAssertion = opts.wantAssertionsSigned !== false;
  const wantResponse = opts.wantResponseSigned === true;

  if (wantResponse && !responseSigs.length) {
    return { ok: false, reason: 'Response signature required but missing' };
  }
  if (wantAssertion && !assertionSigs.length && !responseSigs.length) {
    return { ok: false, reason: 'Assertion signature required but missing' };
  }

  for (const sig of responseSigs) {
    const r = verifySignatureElement(sig, response, trusted);
    if (!r.ok) return { ok: false, reason: `Response signature: ${r.reason}` };
  }
  for (const sig of assertionSigs) {
    const assertion = sig.parentNode;
    const r = verifySignatureElement(sig, assertion, trusted);
    if (!r.ok) return { ok: false, reason: `Assertion signature: ${r.reason}` };
  }

  // Assertions content checks
  const assertions = findAllByLocalName(response, 'Assertion');
  if (!assertions.length) {
    return { ok: false, reason: 'No Assertion in Response' };
  }

  const assertion = assertions[0];
  const conditions = findByLocalName(assertion, 'Conditions');
  if (conditions) {
    const notBefore = conditions.getAttribute('NotBefore');
    const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
    if (notBefore) {
      const t = Date.parse(notBefore);
      if (!Number.isNaN(t) && now + skew < t) {
        return { ok: false, reason: `Assertion not yet valid (NotBefore=${notBefore})` };
      }
    }
    if (notOnOrAfter) {
      const t = Date.parse(notOnOrAfter);
      if (!Number.isNaN(t) && now - skew >= t) {
        return { ok: false, reason: `Assertion expired (NotOnOrAfter=${notOnOrAfter})` };
      }
    }
    // Audience
    if (opts.spEntityId) {
      const audiences = findAllByLocalName(conditions, 'Audience').map(
        (a) => (a.textContent || '').trim()
      ).filter(Boolean);
      if (audiences.length && !audiences.includes(opts.spEntityId)) {
        return {
          ok: false,
          reason: `AudienceRestriction mismatch: got ${audiences.join(',')}, want ${opts.spEntityId}`,
        };
      }
    }
  }

  // Issuer
  const issuer = findByLocalName(assertion, 'Issuer')?.textContent?.trim()
    || findByLocalName(response, 'Issuer')?.textContent?.trim();

  // NameID
  const nameIdEl = findByLocalName(assertion, 'NameID');
  const nameId = nameIdEl?.textContent?.trim() || null;

  // Attributes
  const attributes = {};
  for (const attr of findAllByLocalName(assertion, 'Attribute')) {
    const name = attr.getAttribute('Name') || attr.getAttribute('FriendlyName');
    if (!name) continue;
    const vals = findAllByLocalName(attr, 'AttributeValue').map((v) => (v.textContent || '').trim());
    attributes[name] = vals.length === 1 ? vals[0] : vals;
  }

  // Email heuristics
  const email = attributes['email']
    || attributes['emailAddress']
    || attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
    || attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']
    || nameId;

  return {
    ok: true,
    issuer,
    nameId,
    email,
    attributes,
    assertionId: assertion.getAttribute('ID') || assertion.getAttribute('Id'),
    responseId: response.getAttribute('ID') || response.getAttribute('Id'),
    signatures: {
      response: responseSigs.length,
      assertion: assertionSigs.length,
    },
  };
}

module.exports = {
  verifySamlResponse,
  verifySignatureElement,
  normalizePem,
  ALG_MAP,
};
