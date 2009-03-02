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
 * The Original Code is DogStar SOFTWARE IP.v6 Public Module.
 *
 * The Initial Developer of the Original Code is
 * James Tyson, DogStar SOFTWARE <james@thedogstar.org>.
 * Portions created by the Initial Developer are Copyright (C) 2005
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Bill Welliver <hww3@riverweb.com>.
 *
 * ***** END LICENSE BLOCK ***** */

//! This module describes an IP prefix, ie a network/netmask pair.


static object ip;
static object mask;
static int len;
static inherit "helpers";

//! Clone the IP.v6.Prefix module.
//!
//! @param prefix
//!    The IP prefix in the CIDR format (ie x.x.x.x/m)
//!
void create(string prefix) {
  string _ip, _mask;
  _ip = (prefix / "/")[0];
  _mask = (prefix / "/")[1];
  ip = IP.v6.Address(_ip);
  if (sizeof(_mask / ".") == 1) {
    len = (int)_mask;
    mask = IP.v6.Address(lengthtoint((int)_mask));
  }
  else {
    mask = IP.v6.Address(_mask);
    len = masktolength(mask);
  }
}

string _sprintf() {
  return sprintf("IP.v6.Prefix(\"%s/%d\")", (string)network(), len);
}

void|string cast(string type) {
  switch(type) {
  case "string":
    return sprintf("%s/%d", (string)ip, len);
  }
}

//! Get the network address of this prefix.
IP.v6.Address network() {
  return IP.v6.Address(::network((int)ip, (int)mask));
}

//! Get the highest address of this prefix.
IP.v6.Address highest() {
  return IP.v6.Address(::highest((int)ip, (int)mask));
}

//! Get the length of this prefix (ie, number of "on" bits in the mask).
int(0..32) length() {
  return len;
}

//! Test if an IP address is inside this prefix.
//! Returns 1 if true, 0 otherwise.
//!
//! @param test
//!    The IP address to test.
//!
int(0..1) contains(IP.v6.Address|IP.v6.Prefix test) {
  if (test->network)
    return (test->network() >= network() && test->highest() <= highest());
  else
    return (test >= network() && test <= highest());
}

int(0..1) `==(IP.v6.Prefix test) {
  return (test->network() == network() && test->highest() == highest());
}

int(0..1) `<(IP.v6.Prefix test) {
  return (test->network() > network() && test->highest() < highest());
}

int(0..1) `<=(IP.v6.Prefix test) {
  return (test->network() >= network() && test->highest() <= highest());
}

int(0..1) `>(IP.v6.Prefix test) {
  return (test->network() < network() && test->highest() > highest());
}

int(0..1) `>=(IP.v6.Prefix test) {
  return (test->network() <= network() && test->highest() >= highest());
}
