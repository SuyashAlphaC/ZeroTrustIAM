'use strict';

const {
  exclusiveCanonicalize,
  parseXml,
  findByLocalName,
} = require('../../samlExclusiveC14n');

describe('exclusive C14N', () => {
  it('canonicalizes a simple element deterministically', () => {
    const doc = parseXml('<root xmlns="urn:test"><child a="1" b="2">x</child></root>');
    const child = findByLocalName(doc, 'child');
    const c1 = exclusiveCanonicalize(child);
    const c2 = exclusiveCanonicalize(child);
    expect(c1).toBe(c2);
    expect(c1).toContain('<child');
    expect(c1).toContain('a="1"');
    expect(c1).toContain('>x</child>');
  });

  it('sorts attributes', () => {
    const doc = parseXml('<e z="1" a="2" m="3"/>');
    const c = exclusiveCanonicalize(doc.documentElement);
    const aPos = c.indexOf('a="2"');
    const mPos = c.indexOf('m="3"');
    const zPos = c.indexOf('z="1"');
    expect(aPos).toBeLessThan(mPos);
    expect(mPos).toBeLessThan(zPos);
  });

  it('escapes special characters in text and attributes', () => {
    const doc = parseXml('<e a="&quot;x&quot;">a&amp;b&lt;c</e>');
    const c = exclusiveCanonicalize(doc.documentElement);
    expect(c).toContain('&amp;');
    expect(c).toContain('&lt;');
  });

  it('emits utilized namespace prefixes', () => {
    const doc = parseXml(
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="x">'
      + '<saml:Issuer>https://idp</saml:Issuer></saml:Assertion>'
    );
    const c = exclusiveCanonicalize(doc.documentElement);
    expect(c).toContain('xmlns:saml=');
    expect(c).toContain('saml:Assertion');
  });
});
