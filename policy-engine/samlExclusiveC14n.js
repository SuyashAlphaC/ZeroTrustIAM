'use strict';

/**
 * Exclusive XML Canonicalization 1.0 (with comments omitted)
 * http://www.w3.org/2001/10/xml-exc-c14n#
 *
 * Used for SAML / XMLDSig verification across Entra, Okta, ADFS, Ping, etc.
 * Handles:
 *  - exclusive namespace rendering (visibly utilized only)
 *  - attribute & namespace sorting
 *  - default attribute normalization
 *  - inclusive namespace prefix list (PrefixList from InclusiveNamespaces)
 */

const { DOMParser } = require('@xmldom/xmldom');

const XMLNS = 'http://www.w3.org/2000/xmlns/';
const XML_NS = 'http://www.w3.org/XML/1998/namespace';

function isElement(n) {
  return n && n.nodeType === 1;
}

function isText(n) {
  return n && (n.nodeType === 3 || n.nodeType === 4); // text or CDATA
}

function isComment(n) {
  return n && n.nodeType === 8;
}

/**
 * Parse InclusiveNamespaces PrefixList attribute ("ds ds dig" etc.)
 * @param {string} prefixList
 * @returns {Set<string>}
 */
function parsePrefixList(prefixList) {
  const set = new Set();
  if (!prefixList) return set;
  for (const p of prefixList.trim().split(/\s+/)) {
    if (p === '#default') set.add('');
    else if (p) set.add(p);
  }
  return set;
}

/**
 * Collect namespace nodes in scope for an element (including inherited).
 */
function getNamespaceAxis(element) {
  const map = new Map(); // prefix -> uri
  let cur = element;
  while (cur && cur.nodeType === 1) {
    if (cur.attributes) {
      for (let i = 0; i < cur.attributes.length; i++) {
        const a = cur.attributes.item(i);
        if (a.prefix === 'xmlns') {
          if (!map.has(a.localName)) map.set(a.localName, a.value);
        } else if (a.name === 'xmlns' || a.nodeName === 'xmlns') {
          if (!map.has('')) map.set('', a.value);
        }
      }
    }
    cur = cur.parentNode;
  }
  return map;
}

/**
 * Namespace prefixes "visibly utilized" by element (its own name + attributes).
 */
function visiblyUtilizedPrefixes(element) {
  const used = new Set();
  if (element.prefix) used.add(element.prefix);
  else used.add(''); // default may be used by unprefixed element name
  if (element.attributes) {
    for (let i = 0; i < element.attributes.length; i++) {
      const a = element.attributes.item(i);
      if (a.prefix === 'xmlns' || a.name === 'xmlns' || a.nodeName === 'xmlns') continue;
      if (a.prefix) used.add(a.prefix);
    }
  }
  return used;
}

/**
 * Compare attributes for C14N order: namespaces first (by prefix), then attrs by ns URI then name.
 */
function attrSortKey(a) {
  const isNs = a.prefix === 'xmlns' || a.name === 'xmlns' || a.nodeName === 'xmlns';
  if (isNs) {
    const p = a.prefix === 'xmlns' ? a.localName : '';
    return `0\0${p}`;
  }
  const ns = a.namespaceURI || '';
  const name = a.localName || a.name;
  return `1\0${ns}\0${name}`;
}

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/\r/g, '&#xD;')
    .replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;');
}

function escapeText(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r/g, '&#xD;');
}

/**
 * Exclusive C14N of a node-set rooted at `node`.
 *
 * @param {Node} node
 * @param {{ inclusiveNamespacesPrefixList?: string, withComments?: boolean }} [opts]
 * @returns {string}
 */
function exclusiveCanonicalize(node, opts = {}) {
  const inclusive = parsePrefixList(opts.inclusiveNamespacesPrefixList || '');
  const withComments = !!opts.withComments;
  // Track rendered ns on ancestor path for exclusive omission
  const nsStack = [];

  function renderedNs() {
    const m = new Map();
    for (const frame of nsStack) {
      for (const [p, u] of frame) m.set(p, u);
    }
    return m;
  }

  function processElement(el) {
    const nsInScope = getNamespaceAxis(el);
    const used = visiblyUtilizedPrefixes(el);
    // Inclusive prefixes always considered utilized
    for (const p of inclusive) used.add(p);

    const toRender = [];
    const already = renderedNs();

    for (const prefix of used) {
      const uri = nsInScope.has(prefix)
        ? nsInScope.get(prefix)
        : (prefix === '' ? null : null);
      // unprefixed element in no default ns — don't emit xmlns=""
      if (uri === null || uri === undefined) {
        if (prefix === '' && !nsInScope.has('')) continue;
        if (!nsInScope.has(prefix)) continue;
      }
      const actualUri = nsInScope.get(prefix);
      if (actualUri === undefined) continue;
      // omit if already rendered with same URI
      if (already.get(prefix) === actualUri) continue;
      // omit empty default ns if not needed — exclusive C14N still may need xmlns=""
      toRender.push({ prefix, uri: actualUri });
    }

    // Also: if inclusive list has prefixes declared in scope, render if not already
    for (const prefix of inclusive) {
      if (!nsInScope.has(prefix)) continue;
      const uri = nsInScope.get(prefix);
      if (already.get(prefix) === uri) continue;
      if (!toRender.find((x) => x.prefix === prefix)) {
        toRender.push({ prefix, uri });
      }
    }

    toRender.sort((a, b) => (a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0));

    const frame = new Map();
    for (const { prefix, uri } of toRender) frame.set(prefix, uri);
    nsStack.push(frame);

    const localName = el.localName || el.nodeName.replace(/^.*:/, '');
    const qName = el.prefix ? `${el.prefix}:${localName}` : localName;
    let out = `<${qName}`;

    // namespace nodes
    for (const { prefix, uri } of toRender) {
      if (prefix === '') out += ` xmlns="${escapeAttr(uri)}"`;
      else out += ` xmlns:${prefix}="${escapeAttr(uri)}"`;
    }

    // attributes (non-namespace)
    const attrs = [];
    if (el.attributes) {
      for (let i = 0; i < el.attributes.length; i++) {
        const a = el.attributes.item(i);
        if (a.prefix === 'xmlns' || a.name === 'xmlns' || a.nodeName === 'xmlns') continue;
        attrs.push(a);
      }
    }
    attrs.sort((a, b) => {
      const ka = attrSortKey(a);
      const kb = attrSortKey(b);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    for (const a of attrs) {
      const an = a.prefix ? `${a.prefix}:${a.localName || a.name}` : (a.localName || a.name);
      out += ` ${an}="${escapeAttr(a.value)}"`;
    }
    out += '>';

    for (let c = el.firstChild; c; c = c.nextSibling) {
      out += processNode(c);
    }
    out += `</${qName}>`;
    nsStack.pop();
    return out;
  }

  function processNode(n) {
    if (isElement(n)) return processElement(n);
    if (isText(n)) return escapeText(n.nodeValue || '');
    if (isComment(n) && withComments) {
      return `<!--${n.nodeValue || ''}-->`;
    }
    // processing instructions
    if (n && n.nodeType === 7) {
      return `<?${n.target} ${n.data}?>`;
    }
    // document node — process children
    if (n && n.nodeType === 9) {
      let o = '';
      for (let c = n.firstChild; c; c = c.nextSibling) o += processNode(c);
      return o;
    }
    return '';
  }

  return processNode(node);
}

/**
 * Parse XML string to Document.
 */
function parseXml(xml) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const err = doc.getElementsByTagName('parsererror')[0];
  if (err) throw new Error(`XML parse error: ${err.textContent}`);
  return doc;
}

/**
 * Find first element by local name (namespace-agnostic).
 */
function findByLocalName(root, localName) {
  if (!root) return null;
  if (isElement(root) && (root.localName === localName || root.nodeName === localName
    || root.nodeName.endsWith(`:${localName}`))) {
    return root;
  }
  const all = root.getElementsByTagName ? root.getElementsByTagName('*') : [];
  for (let i = 0; i < all.length; i++) {
    const el = all.item(i);
    if (el.localName === localName || el.nodeName === localName
      || (el.nodeName && el.nodeName.endsWith(`:${localName}`))) {
      return el;
    }
  }
  return null;
}

function findAllByLocalName(root, localName) {
  const out = [];
  const all = root.getElementsByTagName ? root.getElementsByTagName('*') : [];
  for (let i = 0; i < all.length; i++) {
    const el = all.item(i);
    if (el.localName === localName || el.nodeName === localName
      || (el.nodeName && el.nodeName.endsWith(`:${localName}`))) {
      out.push(el);
    }
  }
  return out;
}

/**
 * Get InclusiveNamespaces PrefixList from a Transform if present.
 */
function getInclusivePrefixList(transformsEl) {
  if (!transformsEl) return '';
  const all = transformsEl.getElementsByTagName('*');
  for (let i = 0; i < all.length; i++) {
    const el = all.item(i);
    if (el.localName === 'InclusiveNamespaces' || el.nodeName.endsWith(':InclusiveNamespaces')) {
      return el.getAttribute('PrefixList') || el.getAttributeNS?.(null, 'PrefixList') || '';
    }
  }
  return '';
}

module.exports = {
  exclusiveCanonicalize,
  parseXml,
  findByLocalName,
  findAllByLocalName,
  getInclusivePrefixList,
  parsePrefixList,
};
