/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is IP.v4 Public Module.
 *
 * The Initial Developer of the Original Code is
 * James Harton, <james@mashd.cc>.
 * Portions created by the Initial Developer are Copyright (C) 2005-2009
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * ***** END LICENSE BLOCK ***** */

static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static int _version;
static int _ihl;
static int _tos;
static int _len;
static int _snaplen;
static int _identification;
static int _flags;
static int _frag_offset;
static int _ttl;
static IP.Protocol.Protocol _protocol;
static int _header_checksum;
static IP.v4.Address _src;
static IP.v4.Address _dst;
static string _data;
static int _dns;

void create(void|string payload, void|int _dns) {
  dns = _dns;
  if (stringp(payload))
    parse(payload);
}

void parse(string payload) {
  snaplen = sizeof(payload);
  if (snaplen < 20) {
    throw(Error.Generic("Packet too small - can't get complete IP header"));
  }
  int tmp;
  tmp = (int)payload[0];
  version = tmp >> 4;
  ihl = tmp << 4;
  tos = (int)payload[1];
  [len] = array_sscanf(payload[2..3], "%2c");
  [identification] = array_sscanf(payload[4..5], "%2c");
  [tmp] = array_sscanf(payload[6..7], "%2c");
  // FIXME: flags = 3 bits, frag_offset = 13 bits.
  flags = frag_offset = tmp;
  ttl = (int)payload[8];
  protocol = IP.Protocol.Protocol((int)payload[9]);
  [header_checksum] = array_sscanf(payload[10..11], "%2c");
  int _src, _dst;
  [_src] = array_sscanf(payload[12..15], "%4c");
  [_dst] = array_sscanf(payload[16..19], "%4c");
  src = IP.v4.Address(_src, dns);
  dst = IP.v4.Address(_dst, dns);
  data = payload[20..];
}

// getters and setters.

int `version() {
  return _version;
}

int `version=(int x) {
  LOCK;
  return _version = x;
}

int `ihl() {
  return _ihl;
}

int `ihl=(int x) {
  LOCK;
  return _ihl = x;
}

int `tos() {
  return _tos;
}

int `tos=(int x) {
  LOCK;
  return _tos = x;
}

int `len() {
  return _len;
}

int `len=(int x) {
  LOCK;
  return _len = x;
}

int `snaplen() {
  return _snaplen;
}

int `snaplen=(int x) {
  LOCK;
  return _snaplen = x;
}

int `identification() {
  return _identification;
}

int `identification=(int x) {
  LOCK;
  return _identification = x;
}

int `flags() {
  return _flags;
}

int `flags=(int x) {
  LOCK;
  return _flags = x;
}

int `frag_offset() {
  return _frag_offset;
}

int `frag_offset=(int x) {
  LOCK;
  return _frag_offset = x;
}

int `ttl() {
  return _ttl;
}

int `ttl=(int x) {
  LOCK;
  return _ttl = x;
}

IP.Protocol.Protocol `protocol() {
  return _protocol;
}

IP.Protocol.Protocol `protocol=(IP.Protocol.Protocol x) {
  LOCK;
  return _protocol = x;
}

int `header_checksum() {
  return _header_checksum;
}

int `header_checksum=(int x) {
  LOCK;
  return _header_checksum = x;
}

IP.v4.Address `src() {
  return _src;
}

IP.v4.Address `src=(IP.v4.Address x) {
  LOCK;
  return _src = x;
}

IP.v4.Address `dst() {
  return _dst;
}

IP.v4.Address `dst=(IP.v4.Address x) {
  LOCK;
  return _dst = x;
}

string `data() {
  return _data;
}

string `data=(string x) {
  LOCK;
  return _data = x;
}

static int `dns() {
  return _dns;
}

static int `dns=(int x) {
  LOCK;
  return _dns = x;
}
