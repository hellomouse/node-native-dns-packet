// Copyright 2011 Timothy J Fontaine <tjfontaine@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

'use strict';

/**
 * Reverse a map
 * @param {Object} src
 * @return {object}
 */
function reverseMap(src) {
  const dst = {};

  for (const k of src) {
    dst[src[k]] = k;
  }
  return dst;
}

/* http://www.iana.org/assignments/dns-parameters */
const NAME_TO_QTYPE = {
  'A': 1,
  'NS': 2,
  'MD': 3,
  'MF': 4,
  'CNAME': 5,
  'SOA': 6,
  'MB': 7,
  'MG': 8,
  'MR': 9,
  'NULL': 10,
  'WKS': 11,
  'PTR': 12,
  'HINFO': 13,
  'MINFO': 14,
  'MX': 15,
  'TXT': 16,
  'RP': 17,
  'AFSDB': 18,
  'X25': 19,
  'ISDN': 20,
  'RT': 21,
  'NSAP': 22,
  'NSAP-PTR': 23,
  'SIG': 24,
  'KEY': 25,
  'PX': 26,
  'GPOS': 27,
  'AAAA': 28,
  'LOC': 29,
  'NXT': 30,
  'EID': 31,
  'NIMLOC': 32,
  'SRV': 33,
  'ATMA': 34,
  'NAPTR': 35,
  'KX': 36,
  'CERT': 37,
  'A6': 38,
  'DNAME': 39,
  'SINK': 40,
  'OPT': 41,
  'APL': 42,
  'DS': 43,
  'SSHFP': 44,
  'IPSECKEY': 45,
  'RRSIG': 46,
  'NSEC': 47,
  'DNSKEY': 48,
  'DHCID': 49,
  'NSEC3': 50,
  'NSEC3PARAM': 51,
  'TLSA': 52,
  'HIP': 55,
  'NINFO': 56,
  'RKEY': 57,
  'TALINK': 58,
  'CDS': 59,
  'SPF': 99,
  'UINFO': 100,
  'UID': 101,
  'GID': 102,
  'UNSPEC': 103,
  'TKEY': 249,
  'TSIG': 250,
  'IXFR': 251,
  'AXFR': 252,
  'MAILB': 253,
  'MAILA': 254,
  'ANY': 255,
  'URI': 256,
  'CAA': 257,
  'TA': 32768,
  'DLV': 32769
};

const QTYPE_TO_NAME = reverseMap(NAME_TO_QTYPE);

const NAME_TO_QCLASS = {
  IN: 1
};

const NAME_TO_RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NOTFOUND: 3,
  NOTIMP: 4,
  REFUSED: 5,
  YXDOMAIN: 6, // Name Exists when it should not
  YXRRSET: 7, // RR Set Exists when it should not
  NXRRSET: 8, // RR Set that should exist does not
  NOTAUTH: 9,
  NOTZONE: 10,
  BADVERS: 16,
  BADSIG: 16, // really?
  BADKEY: 17,
  BADTIME: 18,
  BADMODE: 19,
  BADNAME: 20,
  BADALG: 21,
  BADTRUNC: 22
};

/**
 * Get name of qtype
 * @param {Number} t
 * @return {String}
 */
function qtypeToName(t) {
  return QTYPE_TO_NAME[t];
}

/**
 * Get qtype from name
 * @param {String} n
 * @return {Number}
 */
function nameToQtype(n) {
  return NAME_TO_QTYPE[n.toUpperCase()];
}

module.exports = {
  NAME_TO_QTYPE,
  QTYPE_TO_NAME,
  nameToQtype,
  qtypeToName,
  NAME_TO_QCLASS,
  QCLASS_TO_NAME: reverseMap(NAME_TO_QCLASS),
  FAMILY_TO_QTYPE: {
    4: NAME_TO_QTYPE.A,
    6: NAME_TO_QTYPE.AAAA
  },
  QTYPE_TO_FAMILY: {
    [NAME_TO_QTYPE.A]: 4,
    [NAME_TO_QTYPE.AAAA]: 6
  },
  NAME_TO_RCODE,
  RCODE_TO_NAME: reverseMap(NAME_TO_RCODE),
  BADNAME: 'EBADNAME',
  BADRESP: 'EBADRESP',
  CONNREFUSED: 'ECONNREFUSED',
  DESTRUCTION: 'EDESTRUCTION',
  REFUSED: 'EREFUSED',
  FORMERR: 'EFORMERR',
  NODATA: 'ENODATA',
  NOMEM: 'ENOMEM',
  NOTFOUND: 'ENOTFOUND',
  NOTIMP: 'ENOTIMP',
  SERVFAIL: 'ESERVFAIL',
  TIMEOUT: 'ETIMEOUT'
};
