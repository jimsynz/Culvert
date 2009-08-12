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

//! This module provides handy helpers to the IP.v4 modules.

#define MAX 4294967295

//! Convert an IP address to a 32 bit integer.
//!
//! @param _ip
//!   The IP address to convert.
int iptoint(string _ip) {
  array ip = _ip / ".";
  return ((int)ip[0] << 24) + ((int)ip[1] << 16) + ((int)ip[2] << 8) + (int)ip[3];
}

//! Convert a 32 bit integer to an IP address.
//!
//! @param _ip
//!   The IP address to convert.
string inttoip(int _ip) {
  if (_ip > MAX)
    throw(Error.Generic("IP address too large"));
  if (_ip < 0)
    throw(Error.Generic("Cannot have negative IP address"));
  array exp = allocate(4);
  for (int i = 0; i < 4; i++) {
    int x = (3 - i) * 8;
    int y = (4 - i) * 8;
    exp[i] = sprintf("%d", ((_ip >> x) - ((_ip >> y) * 256)));
  }
  return exp * ".";
}

//! Find the network address for the given address and mask.
//!
//! @param ip
//!   An IP address.
//!
//! @param mask
//!   A netmask.
int network(int ip, int mask) {
  return ip & mask;
}

//! Find the broadcast address for the given address and mask.
//!
//! @param ip
//!   An IP address.
//!
//! @param mask
//!   A netmask.
int broadcast(int ip, int mask) {
  int net = ip & mask;
  int _msk = mask ^ 4294967295;
  return net | _msk;
}

//! Convert a prefix length into an integer mask.
//!
//! @param length
//!   A prefix length.
int lengthtoint(int length) {
  if (length == 32)
    return 4294967295;
  else if (length < 32)
    return (int)((int)pow(2,32) - (int)pow(2,(32 -length)));
}

//! Convert a mask to a prefix length.
//!
//! @param mask
//!   The netmask.
int masktolength(int|object mask) {
  return sizeof(sprintf("%b", (int)mask) - "0");
}
