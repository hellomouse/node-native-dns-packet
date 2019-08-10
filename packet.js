// Copyright 2011 Timothy J Fontaine <tjfontaine@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

// TODO: change the default UDP packet size that node-dns sends
//       from 4096 to conform to these:
//       - [requestor's payload size](https://tools.ietf.org/html/rfc6891#section-6.2.3)
//       - [responders's payload size](https://tools.ietf.org/html/rfc6891#section-6.2.4)

'use strict';

// TODO: actually do the TODOs and FIXMEs
// TODO: update history in README with actual changelog
// TODO: more classes!
// TODO: turn off assertions when NODE_ENV is production
// TODO: add tests for added resource types

// TODO: jsdoc descriptions for functions
/* eslint-disable require-jsdoc */

let consts = require('./consts');
let BufferCursor = require('buffercursor');
let BufferCursorOverflow = BufferCursor.BufferCursorOverflow;
let ipaddr = require('ipaddr.js');
let assert = require('assert');

/**
 * Assert a value is not undefined
 * @param {*} val
 * @param {String} msg Message to include in error
 */
function assertUndefined(val, msg) {
  assert(typeof val !== 'undefined', msg);
}

// TODO: use something less convoluted?
// parse states
const PARSE_HEADER = 100000;
const PARSE_QUESTION = 100001;
const PARSE_RESOURCE_RECORD = 100002;
const PARSE_RR_UNPACK = 100003;
const PARSE_RESOURCE_DONE = 100004;
const PARSE_END = 100005;
const PARSE_A = consts.NAME_TO_QTYPE.A;
const PARSE_NS = consts.NAME_TO_QTYPE.NS;
const PARSE_CNAME = consts.NAME_TO_QTYPE.CNAME;
const PARSE_SOA = consts.NAME_TO_QTYPE.SOA;
const PARSE_PTR = consts.NAME_TO_QTYPE.PTR;
const PARSE_MX = consts.NAME_TO_QTYPE.MX;
const PARSE_TXT = consts.NAME_TO_QTYPE.TXT;
const PARSE_AAAA = consts.NAME_TO_QTYPE.AAAA;
const PARSE_SRV = consts.NAME_TO_QTYPE.SRV;
const PARSE_NAPTR = consts.NAME_TO_QTYPE.NAPTR;
const PARSE_OPT = consts.NAME_TO_QTYPE.OPT;
const PARSE_SPF = consts.NAME_TO_QTYPE.SPF;
const PARSE_TLSA = consts.NAME_TO_QTYPE.TLSA;

// write states
const WRITE_HEADER = 100001;
const WRITE_TRUNCATE = 100002;
const WRITE_QUESTION = 100003;
const WRITE_RESOURCE_RECORD = 100004;
const WRITE_RESOURCE_WRITE = 100005;
const WRITE_RESOURCE_DONE = 100006;
/* eslint-disable no-unused-vars */
const WRITE_RESOURCE_END = 100007;
const WRITE_EDNS = 100008;
/** eslint-enable no-unused-vars */
const WRITE_END = 100009;
const WRITE_A = consts.NAME_TO_QTYPE.A;
const WRITE_AAAA = consts.NAME_TO_QTYPE.AAAA;
const WRITE_NS = consts.NAME_TO_QTYPE.NS;
const WRITE_CNAME = consts.NAME_TO_QTYPE.CNAME;
const WRITE_PTR = consts.NAME_TO_QTYPE.PTR;
const WRITE_SPF = consts.NAME_TO_QTYPE.SPF;
const WRITE_MX = consts.NAME_TO_QTYPE.MX;
const WRITE_SRV = consts.NAME_TO_QTYPE.SRV;
const WRITE_TXT = consts.NAME_TO_QTYPE.TXT;
const WRITE_SOA = consts.NAME_TO_QTYPE.SOA;
const WRITE_OPT = consts.NAME_TO_QTYPE.OPT;
const WRITE_NAPTR = consts.NAME_TO_QTYPE.NAPTR;
const WRITE_TLSA = consts.NAME_TO_QTYPE.TLSA;
const WRITE_DNSKEY = consts.NAME_TO_QTYPE.DNSKEY;
const WRITE_SSHFP = consts.NAME_TO_QTYPE.SSHFP;
const WRITE_CAA = consts.NAME_TO_QTYPE.CAA;
const WRITE_DS = consts.NAME_TO_QTYPE.DS;
const WRITE_URI = consts.NAME_TO_QTYPE.URI;

/** Represents a DNS packet */
class Packet {
  /** The constructor */
  constructor() {
    this.header = {
      id: 0,
      qr: 0,
      opcode: 0,
      aa: 0,
      tc: 0,
      rd: 1,
      ra: 0,
      res1: 0,
      res2: 0,
      res3: 0,
      rcode: 0
    };
    this.question = [];
    this.answer = [];
    this.authority = [];
    this.additional = [];
    this.edns_options = []; // TODO: DEPRECATED! Use `.edns.options` instead!
    this.payload = null; // TODO: DEPRECATED! Use `.edns.payload` instead!
  }

  write(buff, packet) {
    let state = WRITE_HEADER;
    let val;
    let section;
    let count;
    let rdata;
    let lastResource;
    let labelIndex = {};

    buff = new BufferCursor(buff);

    // the existence of 'edns' in a packet indicates that a proper OPT record exists
    // in 'additional' and that all of the other fields in packet (that are parsed by
    // 'parseOpt') are properly set. If it does not exist, we assume that the user
    // is requesting that we create one for them.
    if (
      typeof packet.edns_version !== 'undefined' &&
      typeof packet.edns === 'undefined'
    ) state = makeEdns(packet);

    // TODO: this is unnecessarily inefficient. rewrite this using a
    //       function table instead. (same for Packet.parse too).
    while (true) {
      try {
        switch (state) {
          case WRITE_HEADER:
            state = writeHeader(buff, packet);
            break;
          case WRITE_TRUNCATE:
            state = writeTruncate(buff, packet, section, lastResource);
            break;
          case WRITE_QUESTION:
            state = writeQuestion(buff, packet.question[0], labelIndex);
            section = 'answer';
            count = 0;
            break;
          case WRITE_RESOURCE_RECORD:
            lastResource = buff.tell();
            if (packet[section].length === count) {
              switch (section) {
                case 'answer':
                  section = 'authority';
                  state = WRITE_RESOURCE_RECORD;
                  break;
                case 'authority':
                  section = 'additional';
                  state = WRITE_RESOURCE_RECORD;
                  break;
                case 'additional':
                  state = WRITE_END;
                  break;
              }
              count = 0;
            } else {
              state = WRITE_RESOURCE_WRITE;
            }
            break;
          case WRITE_RESOURCE_WRITE:
            rdata = {};
            val = packet[section][count];
            state = writeResource(buff, val, labelIndex, rdata);
            break;
          case WRITE_RESOURCE_DONE:
            count += 1;
            state = writeResourceDone(buff, rdata);
            break;
          case WRITE_A:
          case WRITE_AAAA:
            state = writeIp(buff, val);
            break;
          case WRITE_NS:
          case WRITE_CNAME:
          case WRITE_PTR:
            state = writeCname(buff, val, labelIndex);
            break;
          case WRITE_SPF:
          case WRITE_TXT:
            state = writeTxt(buff, val);
            break;
          case WRITE_MX:
            state = writeMx(buff, val, labelIndex);
            break;
          case WRITE_SRV:
            state = writeSrv(buff, val, labelIndex);
            break;
          case WRITE_SOA:
            state = writeSoa(buff, val, labelIndex);
            break;
          case WRITE_OPT:
            state = writeOpt(buff, val);
            break;
          case WRITE_NAPTR:
            state = writeNaptr(buff, val, labelIndex);
            break;
          case WRITE_TLSA:
            state = writeTlsa(buff, val);
            break;
          case WRITE_DNSKEY:
            state = writeDnskey(buff, val, labelIndex);
            break;
          case WRITE_SSHFP:
            state = writeSshfp(buff, val, labelIndex);
            break;
          case WRITE_CAA:
            state = writeCaa(buff, val, labelIndex);
            break;
          case WRITE_DS:
            state = writeDs(buff, val, labelIndex);
            break;
          case WRITE_URI:
            state = writeUri(buff, val, labelIndex);
            break;
          case WRITE_END:
            return buff.tell();
          default:
            if (typeof val.data !== 'object') {
              throw new Error(`Packet.write Unknown State: ${state}`);
            }
            // write unhandled RR type
            buff.copy(val.data);
            state = WRITE_RESOURCE_DONE;
        }
      } catch (e) {
        if (e instanceof BufferCursorOverflow) {
          state = WRITE_TRUNCATE;
        } else {
          throw e;
        }
      }
    }
  }

  static parse(msg) {
    let state = PARSE_HEADER;
    let pos = 0;
    let val;
    let rdata;
    let section;
    let count;

    let packet = new Packet();

    msg = new BufferCursor(msg);

    while (true) {
      switch (state) {
        case PARSE_HEADER:
          state = parseHeader(msg, packet);
          break;
        case PARSE_QUESTION:
          state = parseQuestion(msg, packet);
          section = 'answer';
          count = 0;
          break;
        case PARSE_RESOURCE_RECORD:
          // console.log('PARSE_RESOURCE_RECORD: count = %d, %s.len = %d', count, section, packet[section].length);
          if (count === packet[section].length) {
            switch (section) {
              case 'answer':
                section = 'authority';
                count = 0;
                break;
              case 'authority':
                section = 'additional';
                count = 0;
                break;
              case 'additional':
                state = PARSE_END;
                break;
            }
          } else {
            state = PARSE_RR_UNPACK;
          }
          break;
        case PARSE_RR_UNPACK:
          val = {};
          rdata = {};
          state = parseRR(msg, val, rdata);
          break;
        case PARSE_RESOURCE_DONE:
          packet[section][count++] = val;
          state = PARSE_RESOURCE_RECORD;
          break;
        case PARSE_A:
          state = parseA(val, msg);
          break;
        case PARSE_AAAA:
          state = parseAAAA(val, msg);
          break;
        case PARSE_NS:
        case PARSE_CNAME:
        case PARSE_PTR:
          state = parseCname(val, msg);
          break;
        case PARSE_SPF:
        case PARSE_TXT:
          state = parseTxt(val, msg, rdata);
          break;
        case PARSE_MX:
          state = parseMx(val, msg);
          break;
        case PARSE_SRV:
          state = parseSrv(val, msg);
          break;
        case PARSE_SOA:
          state = parseSoa(val, msg);
          break;
        case PARSE_OPT:
          state = parseOpt(val, msg, rdata, packet);
          break;
        case PARSE_NAPTR:
          state = parseNaptr(val, msg);
          break;
        case PARSE_TLSA:
          state = parseTlsa(val, msg, rdata);
          break;
        case PARSE_END:
          return packet;
        default:
          // console.log(state, val);
          val.data = msg.slice(rdata.len);
          state = PARSE_RESOURCE_DONE;
          break;
      }
    }
  }
}
module.exports = Packet;

const LABEL_POINTER = 0xc0;

/**
 * @param {Number} len
 * @return {Boolean}
 */
function isPointer(len) {
  return (len & LABEL_POINTER) === LABEL_POINTER;
}

/**
 * @param {BufferCursor} buff Source buffer
 * @return {String} Unpacked name
 */
function nameUnpack(buff) {
  let len = buff.readUInt8();
  let comp = false;
  let end = buff.tell();
  let pos = 0;
  let part = '';
  let combine = '';

  while (len !== 0) {
    if (isPointer(len)) {
      len -= LABEL_POINTER;
      len = len << 8;
      pos = len + buff.readUInt8();
      if (!comp) end = buff.tell();
      buff.seek(pos);
      len = buff.readUInt8();
      comp = true;
      continue;
    }

    part = buff.toString('ascii', len);

    if (combine.length) combine.concat(`.${part}`);
    else combine = part;

    len = buff.readUInt8();

    if (!comp) end = buff.tell();
  }

  buff.seek(end);
  return combine;
}

/**
 * @param {String} str Domain name
 * @param {BufferCursor} buff Destination of buffer
 * @param {Object} index ???
 */
function namePack(str, buff, index) {
  let offset = 0;
  let dot = 0;
  let part = '';

  while (str) {
    if (index[str]) {
      offset = (LABEL_POINTER << 8) + index[str];
      buff.writeUInt16BE(offset);
      break;
    } else {
      index[str] = buff.tell();
      dot = str.indexOf('.');
      if (dot > -1) {
        part = str.slice(0, dot);
        str = str.slice(dot + 1);
      } else {
        part = str;
        str = undefined;
      }
      buff.writeUInt8(part.length);
      buff.write(part, part.length, 'ascii');
    }
  }

  if (!str) buff.writeUInt8(0);
}

/**
 * Serialize packet header into buffer
 * @param {BufferCursor} buff Destination buffer
 * @param {Packet} packet Source
 * @return {Number} Next state
 */
function writeHeader(buff, packet) {
  assert(packet.header, 'Packet requires "header"');
  buff.writeUInt16BE(packet.header.id & 0xffff);
  let val = 0;
  val += (packet.header.qr << 15) & 0x8000;
  val += (packet.header.opcode << 11) & 0x7800;
  val += (packet.header.aa << 10) & 0x400;
  val += (packet.header.tc << 9) & 0x200;
  val += (packet.header.rd << 8) & 0x100;
  val += (packet.header.ra << 7) & 0x80;
  val += (packet.header.res1 << 6) & 0x40;
  val += (packet.header.res2 << 5) & 0x20;
  val += (packet.header.res3 << 4) & 0x10;
  val += packet.header.rcode & 0xf;
  buff.writeUInt16BE(val & 0xffff);
  assert(packet.question.length === 1, 'DNS requires one question');
  // aren't used
  buff.writeUInt16BE(1);
  // answer offset 6
  buff.writeUInt16BE(packet.answer.length & 0xffff);
  // authority offset 8
  buff.writeUInt16BE(packet.authority.length & 0xffff);
  // additional offset 10
  buff.writeUInt16BE(packet.additional.length & 0xffff);
  return WRITE_QUESTION;
}

let count = 0;
let lastResource = 0;
/**
 * @param {BufferCursor} buff Destination buffer
 * @param {Packet} _packet Source packet object
 * @param {String} section Section to write
 * @param {Number} val
 * @return {Number} Next state
 */
function writeTruncate(buff, _packet, section, val) {
  // FIXME: truncation is currently done wrong.
  // Quote rfc2181 section 9
  // The TC bit should not be set merely because some extra information
  // could have been included, but there was insufficient room.  This
  // includes the results of additional section processing.  In such cases
  // the entire RRSet that will not fit in the response should be omitted,
  // and the reply sent as is, with the TC bit clear.  If the recipient of
  // the reply needs the omitted data, it can construct a query for that
  // data and send that separately.
  //
  // TODO: IOW only set TC if we hit it in ANSWERS otherwise make sure an
  // entire RRSet is removed during a truncation.
  let pos = 0;

  buff.seek(2);
  val = buff.readUInt16BE();
  val |= (1 << 9) & 0x200;
  buff.seek(2);
  buff.writeUInt16BE(val);
  switch (section) {
    case 'answer':
      pos = 6;
      // seek to authority and clear it and additional out
      buff.seek(8);
      buff.writeUInt16BE(0);
      buff.writeUInt16BE(0);
      break;
    case 'authority':
      pos = 8;
      // seek to additional and clear it out
      buff.seek(10);
      buff.writeUInt16BE(0);
      break;
    case 'additional':
      pos = 10;
      break;
  }
  buff.seek(pos);
  buff.writeUInt16BE(count - 1); // TODO: count not defined!
  buff.seek(lastResource); // TODO: last_resource not defined!
  return WRITE_END;
}

/**
 * @param {BufferCursor} buff Destination buffer
 * @param {Object} val Question object
 * @param {Object} labelIndex
 * @return {Number} Next state
 */
function writeQuestion(buff, val, labelIndex) {
  assert(val, 'Packet requires a question');
  assertUndefined(val.name, 'Question requires a "name"');
  assertUndefined(val.type, 'Question requires a "type"');
  assertUndefined(val.class, 'Questionn requires a "class"');
  namePack(val.name, buff, labelIndex);
  buff.writeUInt16BE(val.type & 0xffff);
  buff.writeUInt16BE(val.class & 0xffff);
  return WRITE_RESOURCE_RECORD;
}

/**
 * @param {BufferCursor} buff Destination buffer
 * @param {Obejct} val
 * @param {Object} labelIndex
 * @param {Object} rdata
 * @return {Number} Next state
 */
function writeResource(buff, val, labelIndex, rdata) {
  assert(val, 'Resource must be defined');
  assertUndefined(val.name, 'Resource record requires "name"');
  assertUndefined(val.type, 'Resource record requires "type"');
  assertUndefined(val.class, 'Resource record requires "class"');
  assertUndefined(val.ttl, 'Resource record requires "ttl"');
  namePack(val.name, buff, labelIndex);
  buff.writeUInt16BE(val.type & 0xffff);
  buff.writeUInt16BE(val.class & 0xffff);
  buff.writeUInt32BE(val.ttl & 0xffffffff);
  rdata.pos = buff.tell();
  buff.writeUInt16BE(0); // if there is rdata, then this value will be updated
  // to the correct value by 'writeResourceDone'
  return val.type;
}

/**
 * @param {BufferCursor} buff Destination buffer
 * @param {Object} rdata
 * @return {Number} Next state
 */
function writeResourceDone(buff, rdata) {
  let pos = buff.tell();
  buff.seek(rdata.pos);
  // seems like it's supposed to write size?
  buff.writeUInt16BE(pos - rdata.pos - 2);
  buff.seek(pos);
  return WRITE_RESOURCE_RECORD;
}

/**
 * Write an IP address to a destination buffer
 * @param {BufferCursor} buff Destination buffer
 * @param {Object} val
 * @param {String} val.address IP address to write
 * @return {Number} Next state
 */
function writeIp(buff, val) {
  // FIXME: assert that address is of proper type
  assertUndefined(val.address, 'A/AAAA record requires "address"');
  val = ipaddr.parse(val.address).toByteArray();
  val.forEach(b => buff.writeUInt8(b));
  return WRITE_RESOURCE_DONE;
}

function writeCname(buff, val, labelIndex) {
  assertUndefined(val.data, 'NS/CNAME/PTR record requires "data"');
  namePack(val.data, buff, labelIndex);
  return WRITE_RESOURCE_DONE;
}

// For <character-string> see: http://tools.ietf.org/html/rfc1035#section-3.3
// For TXT: http://tools.ietf.org/html/rfc1035#section-3.3.14
function writeTxt(buff, val) {
  // TODO XXX FIXME -- split on max char string and loop
  assertUndefined(val.data, 'TXT record requires "data"');
  for (let i = 0, len = val.data.length; i < len; i++) {
    let dataLen = Buffer.byteLength(val.data[i], 'utf8');
    buff.writeUInt8(dataLen);
    buff.write(val.data[i], dataLen, 'utf8');
  }
  return WRITE_RESOURCE_DONE;
}

function writeMx(buff, val, labelIndex) {
  assertUndefined(val.priority, 'MX record requires "priority"');
  assertUndefined(val.exchange, 'MX record requires "exchange"');
  buff.writeUInt16BE(val.priority & 0xffff);
  namePack(val.exchange, buff, labelIndex);
  return WRITE_RESOURCE_DONE;
}

function writeDnskey(buff, val, labelIndex) {
  assertUndefined(val.algorithm, 'DNSKEY record requires "algorithm"');
  assertUndefined(val.key, 'DNSKEY record requires "key"');
  assertUndefined(val.flags, 'DNSKEY record requires "flags"');
  assertUndefined(val.protocol, 'DNSKEY record requires "protocol"');
  buff.writeUInt16BE(val.flags);
  buff.writeUInt8(val.protocol);
  buff.writeUInt8(val.algorithm);
  namePack(val.key, buff, labelIndex);
  return WRITE_RESOURCE_DONE;
}

function writeSshfp(buff, val, _labelIndex) {
  assertUndefined(val.algorithm, 'SSHFP record requires "algorithm"');
  assertUndefined(val.hash, 'SSHFP record requires "hash"');
  assertUndefined(val.fingerprint, 'SSHFP record requires "fingerprint"');
  buff.writeUInt8(val.algorithm);
  buff.writeUInt8(val.hash);
  buff.write(Buffer.from(val.fingerprint, 'hex').toString('binary'), 'binary');
  return WRITE_RESOURCE_DONE;
}

function writeDs(buff, val, _labelIndex) {
  assertUndefined(val.tag, 'DS record requires "tag"');
  assertUndefined(val.algorithm, 'DS record requires "algorithm"');
  assertUndefined(val.digestAlgorithm, 'DS record requires "digestAlgorithm"');
  assertUndefined(val.digest, 'DS record requires "digest"');
  buff.writeUint16BE(val.tag & 0xffff);
  buff.writeUint8(val.algorithm);
  buff.writeUint8(val.digestAlgorithm);
  buff.write(val.digest);
  return WRITE_RESOURCE_DONE;
}

// SRV: https://tools.ietf.org/html/rfc2782
// TODO: SRV fixture failing for '_xmpp-server._tcp.gmail.com.srv.js'
function writeSrv(buff, val, labelIndex) {
  assertUndefined(val.priority, 'SRV record requires "priority"');
  assertUndefined(val.weight, 'SRV record requires "weight"');
  assertUndefined(val.port, 'SRV record requires "port"');
  assertUndefined(val.target, 'SRV record requires "target"');
  buff.writeUInt16BE(val.priority & 0xffff);
  buff.writeUInt16BE(val.weight & 0xffff);
  buff.writeUInt16BE(val.port & 0xffff);
  namePack(val.target, buff, labelIndex);
  return WRITE_RESOURCE_DONE;
}

function writeSoa(buff, val, labelIndex) {
  assertUndefined(val.primary, 'SOA record requires "primary"');
  assertUndefined(val.admin, 'SOA record requires "admin"');
  assertUndefined(val.serial, 'SOA record requires "serial"');
  assertUndefined(val.refresh, 'SOA record requires "refresh"');
  assertUndefined(val.retry, 'SOA record requires "retry"');
  assertUndefined(val.expiration, 'SOA record requires "expiration"');
  assertUndefined(val.minimum, 'SOA record requires "minimum"');
  namePack(val.primary, buff, labelIndex);
  namePack(val.admin, buff, labelIndex);
  buff.writeUInt32BE(val.serial & 0xffffffff);
  buff.writeInt32BE(val.refresh & 0xffffffff);
  buff.writeInt32BE(val.retry & 0xffffffff);
  buff.writeInt32BE(val.expiration & 0xffffffff);
  buff.writeInt32BE(val.minimum & 0xffffffff);
  return WRITE_RESOURCE_DONE;
}

// http://tools.ietf.org/html/rfc3403#section-4.1
function writeNaptr(buff, val, labelIndex) {
  assertUndefined(val.order, 'NAPTR record requires "order"');
  assertUndefined(val.preference, 'NAPTR record requires "preference"');
  assertUndefined(val.flags, 'NAPTR record requires "flags"');
  assertUndefined(val.service, 'NAPTR record requires "service"');
  assertUndefined(val.regexp, 'NAPTR record requires "regexp"');
  assertUndefined(val.replacement, 'NAPTR record requires "replacement"');
  buff.writeUInt16BE(val.order & 0xffff);
  buff.writeUInt16BE(val.preference & 0xffff);
  buff.writeUInt8(val.flags.length);
  buff.write(val.flags, val.flags.length, 'ascii');
  buff.writeUInt8(val.service.length);
  buff.write(val.service, val.service.length, 'ascii');
  buff.writeUInt8(val.regexp.length);
  buff.write(val.regexp, val.regexp.length, 'ascii');
  namePack(val.replacement, buff, labelIndex);
  return WRITE_RESOURCE_DONE;
}

// https://tools.ietf.org/html/rfc6698
function writeTlsa(buff, val) {
  assertUndefined(val.usage, 'TLSA record requires "usage"');
  assertUndefined(val.selector, 'TLSA record requires "selector"');
  assertUndefined(val.matchingtype, 'TLSA record requires "matchingtype"');
  assertUndefined(val.buff, 'TLSA record requires "buff"');
  buff.writeUInt8(val.usage);
  buff.writeUInt8(val.selector);
  buff.writeUInt8(val.matchingtype);
  buff.copy(val.buff);
  return WRITE_RESOURCE_DONE;
}

function writeCaa(buff, val) {
  assertUndefined(val.flags, 'CAA record requires "flags"');
  assertUndefined(val.tag, 'CAA record requires "tag"');
  assertUndefined(val.value, 'CAA record requires "value"');
  buff.writeUInt8(val.flags);
  buff.writeUInt8(val.tag.length);
  buff.copy(Buffer.from(val.tag));
  buff.copy(Buffer.from(val.value));
  return WRITE_RESOURCE_DONE;
}

function writeUri(buff, val) {
  // TODO: split on max char string and loop
  assertUndefined(val.priority, 'URI record requires "priority"');
  assertUndefined(val.weight, 'URI record requires "weight"');
  assertUndefined(val.target, 'URI record requires "target"');
  buff.writeUInt16BE(val.priority & 0xffff);
  buff.writeUInt16BE(val.weight & 0xffff);
  //  for (var i=0,len=val.target.length; i<len; i++) {
  let dataLen = Buffer.byteLength(val.target, 'utf8');
  // buff.writeUInt8(dataLen);
  buff.write(val.target, dataLen, 'utf8');
  // }
  return WRITE_RESOURCE_DONE;
}

function makeEdns(packet) {
  packet.edns = {
    name: '',
    type: consts.NAME_TO_QTYPE.OPT,
    class: packet.payload,
    options: [],
    ttl: 0
  };
  packet.edns_options = packet.edns.options; // TODO: 'edns_options' is DEPRECATED!
  packet.additional.push(packet.edns);
  return WRITE_HEADER;
}

function writeOpt(buff, val) {
  let opt;
  for (let i = 0, len = val.options.length; i < len; i++) {
    opt = val.options[i];
    buff.writeUInt16BE(opt.code);
    buff.writeUInt16BE(opt.data.length);
    buff.copy(opt.data);
  }
  return WRITE_RESOURCE_DONE;
}

function parseHeader(msg, packet) {
  packet.header.id = msg.readUInt16BE();
  let val = msg.readUInt16BE();
  packet.header.qr = (val & 0x8000) >> 15;
  packet.header.opcode = (val & 0x7800) >> 11;
  packet.header.aa = (val & 0x400) >> 10;
  packet.header.tc = (val & 0x200) >> 9;
  packet.header.rd = (val & 0x100) >> 8;
  packet.header.ra = (val & 0x80) >> 7;
  packet.header.res1 = (val & 0x40) >> 6;
  packet.header.res2 = (val & 0x20) >> 5;
  packet.header.res3 = (val & 0x10) >> 4;
  packet.header.rcode = val & 0xf;
  packet.question = new Array(msg.readUInt16BE());
  packet.answer = new Array(msg.readUInt16BE());
  packet.authority = new Array(msg.readUInt16BE());
  packet.additional = new Array(msg.readUInt16BE());
  return PARSE_QUESTION;
}

function parseQuestion(msg, packet) {
  let val = {};
  val.name = nameUnpack(msg);
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  packet.question[0] = val;
  assert(packet.question.length === 1);
  // TODO handle qdcount > 1, in practice no one sends this
  return PARSE_RESOURCE_RECORD;
}

/**
 * @param {BufferCursor} msg
 * @param {*} val
 * @param {*} rdata
 * @return {number}
 */
function parseRR(msg, val, rdata) {
  val.name = nameUnpack(msg);
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  val.ttl = msg.readUInt32BE();
  rdata.len = msg.readUInt16BE();
  return val.type;
}

/**
 * @param {*} val
 * @param {BufferCursor} msg
 * @return {number}
 */
function parseA(val, msg) {
  val.address = [
    msg.readUInt8(),
    msg.readUInt8(),
    msg.readUInt8(),
    msg.readUInt8()
  ].join('.');
  return PARSE_RESOURCE_DONE;
}

/**
 * @param {*} val
 * @param {BufferCursor} msg
 * @return {number}
 */
function parseAAAA(val, msg) {
  let address = '';
  let compressed = false;

  for (let i = 0; i < 8; i++) {
    if (i > 0) address += ':';
    // TODO zero compression
    address += msg.readUInt16BE().toString(16);
  }
  val.address = address;
  return PARSE_RESOURCE_DONE;
}

function parseCname(val, msg) {
  val.data = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseTxt(val, msg, rdata) {
  val.data = [];
  let end = msg.tell() + rdata.len;
  while (msg.tell() !== end) {
    let len = msg.readUInt8();
    val.data.push(msg.toString('utf8', len));
  }
  return PARSE_RESOURCE_DONE;
}

function parseMx(val, msg, rdata) {
  val.priority = msg.readUInt16BE();
  val.exchange = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

// FIXME: SRV fixture failing for '_xmpp-server._tcp.gmail.com.srv.js'
//        https://tools.ietf.org/html/rfc2782
function parseSrv(val, msg) {
  val.priority = msg.readUInt16BE();
  val.weight = msg.readUInt16BE();
  val.port = msg.readUInt16BE();
  val.target = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseSoa(val, msg) {
  val.primary = nameUnpack(msg);
  val.admin = nameUnpack(msg);
  val.serial = msg.readUInt32BE();
  val.refresh = msg.readInt32BE();
  val.retry = msg.readInt32BE();
  val.expiration = msg.readInt32BE();
  val.minimum = msg.readInt32BE();
  return PARSE_RESOURCE_DONE;
}

// http://tools.ietf.org/html/rfc3403#section-4.1
function parseNaptr(val, msg) {
  val.order = msg.readUInt16BE();
  val.preference = msg.readUInt16BE();
  let len = msg.readUInt8();
  val.flags = msg.toString('ascii', len);
  len = msg.readUInt8();
  val.service = msg.toString('ascii', len);
  len = msg.readUInt8();
  val.regexp = msg.toString('ascii', len);
  val.replacement = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseTlsa(val, msg, rdata) {
  val.usage = msg.readUInt8();
  val.selector = msg.readUInt8();
  val.matchingtype = msg.readUInt8();
  val.buff = msg.slice(rdata.len - 3).buffer; // 3 because of the 3 UInt8s above.
  return PARSE_RESOURCE_DONE;
}

// https://tools.ietf.org/html/rfc6891#section-6.1.2
// https://tools.ietf.org/html/rfc2671#section-4.4
//       - [payload size selection](https://tools.ietf.org/html/rfc6891#section-6.2.5)
function parseOpt(val, msg, rdata, packet) {
  // assert first entry in additional
  rdata.buf = msg.slice(rdata.len);

  val.rcode = ((val.ttl & 0xff000000) >> 20) + packet.header.rcode;
  val.version = (val.ttl >> 16) & 0xff;
  val.do = (val.ttl >> 15) & 1;
  val.z = val.ttl & 0x7f;
  val.options = [];

  packet.edns = val;
  packet.edns_version = val.version; // TODO: return BADVERS for unsupported version! (Section 6.1.3)

  // !! BEGIN DEPRECATION NOTICE !!
  // THESE FIELDS MAY BE REMOVED IN THE FUTURE!
  packet.edns_options = val.options;
  packet.payload = val.class;
  // !! END DEPRECATION NOTICE !!

  while (!rdata.buf.eof()) {
    val.options.push({
      code: rdata.buf.readUInt16BE(),
      data: rdata.buf.slice(rdata.buf.readUInt16BE()).buffer
    });
  }
  return PARSE_RESOURCE_DONE;
}
