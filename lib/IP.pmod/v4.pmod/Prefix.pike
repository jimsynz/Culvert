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
 *   Bill Welliver <hww3@riverweb.com>.
 *
 * ***** END LICENSE BLOCK ***** */

//! This module describes an IP prefix, ie a network/netmask pair.


static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static object _ip;
static object _mask;
static int _len;
static inherit "helpers";

//! Clone the IP.v4.Prefix module.
//!
//! @param prefix
//!    The IP prefix in the CIDR format (ie x.x.x.x/m)
//!
void create(string prefix) {
  string _ip, _mask;
  _ip = (prefix / "/")[0];
  _mask = (prefix / "/")[1];
  ip = IP.v4.Address(_ip);
  if (sizeof(_mask / ".") == 1) {
    len = (int)_mask;
    mask = IP.v4.Address(lengthtoint((int)_mask));
  }
  else {
    mask = IP.v4.Address(_mask);
    len = masktolength(mask);
  }
}

string _sprintf() {
  return sprintf("IP.v4.Prefix(\"%s/%s\")", (string)network(), (string)mask);
}

void|string cast(string type) {
  switch(type) {
  case "string":
    return (string)ip + "/" + (string)mask;
  }
}

//! Get the network address of this prefix.
IP.v4.Address network() {
  return IP.v4.Address(::network((int)ip, (int)mask));
}

//! Get the broadcast address of this prefix.
IP.v4.Address broadcast() {
  return IP.v4.Address(::broadcast((int)ip, (int)mask));
}

//! Get the netmask of this prefix.
IP.v4.Address netmask() {
  return mask;
}

//! Get the length of this prefix (ie, number of "on" bits in the mask).
int(0..32) length() {
  return len;
}

//! Get the address space available within this prefix.
int space() {
  // like size() we need to add one.
  return ((int)broadcast() - (int)network()) + 1;
}

//! Return the reverse zones for this prefix.
array reverse() {
  // calculate all the reverse zones for a given network prefix.
  int boundary = length() % 8 == 0 && length() != 0 ? length() / 8 - 1 : length() / 8;
  int divisor = (boundary + 1) * 8;
  int count = ((int)broadcast() - (int)network()) / (1 << 32-divisor);
  array res = ({});
  for (int i = 0; i <= count; i++) {
    array octets = (((string)IP.v4.Address((int)network() + ((1<<32-divisor)*i)) / ".")[0..boundary]);
    res += ({ sprintf("%{%s.%}in-addr.arpa", predef::reverse(octets)) });
  }
  return res;
}

//! Test if an IP address is inside this prefix.
//! Returns 1 if true, 0 otherwise.
//!
//! @param test
//!    The IP address to test.
//!
int(0..1) contains(IP.v4.Address|IP.v4.Prefix test) {
  if (test->network)
    return (test->network() >= network() && test->broadcast() <= broadcast());
  else
    return (test >= network() && test <= broadcast());
}

int(0..1) `==(IP.v4.Prefix test) {
  return (test->network() == network() && test->broadcast() == broadcast());
}

int(0..1) `<(IP.v4.Prefix test) {
  return (test->network() > network() && test->broadcast() < broadcast());
}

int(0..1) `<=(IP.v4.Prefix test) {
  return (test->network() >= network() && test->broadcast() <= broadcast());
}

int(0..1) `>(IP.v4.Prefix test) {
  return (test->network() < network() && test->broadcast() > broadcast());
}

int(0..1) `>=(IP.v4.Prefix test) {
  return (test->network() <= network() && test->broadcast() >= broadcast());
}

static IP.v4.Address `ip() {
  return _ip;
}

static IP.v4.Address `ip=(IP.v4.Address x) {
  LOCK;
  return _ip = x;
}

static IP.v4.Address `mask() {
  return _mask;
}

static IP.v4.Address `mask=(IP.v4.Address x) {
  LOCK;
  return _mask = x;
}

static int `len() {
  return _len;
}

static int `len=(int x) {
  LOCK;
  return _len = x;
}

