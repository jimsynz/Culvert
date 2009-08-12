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
 * The Original Code is IP.v6 Public Module.
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

//! This module provides handy helpers to the IP.v6 modules.

static mapping mscopes = 
([
  1 : "INTERFACE LOCAL MULTICAST",
  2 : "LINK LOCAL MULTICAST",
  4 : "ADMIN LOCAL MULTICAST",
  5 : "SITE LOCAL MULTICAST",
  8 : "ORGANISATION LOCAL MULTICAST",
  0xe : "GLOBAL MULTICAST"
 ]);

static mapping mdests =
([
  1 : "ALL NODES",
  2 : "ALL ROUTERS",
  3 : "ALL DHCP SERVERS",
  4 : "DVMRP ROUTERS",
  5 : "OSPFIGP",
  6 : "OSPFIGP DESIGNATED ROUTERS",
  7 : "ST ROUTERS",
  8 : "ST HOSTS",
  9 : "RIP ROUTERS",
  0xa : "EIGRP ROUTERS",
  0xb : "MOBILE-AGENTS",
  0xc : "SSDP",
  0xd : "ALL PIM ROUTERS",
  0xe : "RSVP ENCAPSULATION",
  0xf : "UPNP",
  0x16 : "ALL MLDV2 CAPABLE ROUTERS",
  0x6a : "ALL SNOOPERS",
  0x6b : "PTP-PDELAY",
  0x6c : "SARATOGA",
  0x6d : "LL MANET ROUTERS",
  0xfb : "MDNSV6",
  0x100 : "VMTP MANAGERS GROUP",
  0x101 : "NTP",
  0x102 : "SGI-DOGFIGHT",
  0x103 : "RWHOD",
  0x104 : "VNP",
  0x105 : "ARTIFICIAL HORIZONS",
  0x106 : "NSS",
  0x107 : "AUDIONEWS",
  0x108 : "SUN NIS+",
  0x109 : "MTP",
  0x10a : "IETF-1-LOW-AUDIO",
  0x10b : "IETF-1-AUDIO",
  0x10c : "IETF-1-VIDEO",
  0x10d : "IETF-2-LOW-AUDIO",
  0x10e : "IETF-2-AUDIO",
  0x10f : "IETF-2-VIDEO",
  0x110 : "MUSIC-SERVICE",
  0x111 : "SEANET-TELEMETRY",
  0x112 : "SEANET-IMAGE",
  0x113 : "MLOADD",
  0x114 : "ANY PRIVATE EXPERIMENT",
  0x115 : "DVMRP on MOSPF",
  0x116 : "SVRLOC",
  0x117 : "XINGTV",
  0x118 : "MICROSOFT-DS",
  0x119 : "NBC-PRO",
  0x11a : "NBC-PFN",
  0x10001 : "LINK NAME",
  0x10002 : "ALL DHCP AGENTS",
  0x10003 : "LINK LOCAL MULTICAST NAME",
  0x10004 : "DTCP ANNOUNCEMENT",

 ]);

#define MAX 340282366920938463463374607431768211455

//! Convert an IP address to a 128 bit integer.
//!
//! @param _ip
//!   The IP address to convert.
static int iptoint(string _ip) {
  if (_ip == "::") {
    return 0;
  }
  array parts = _ip / "::";
  if (sizeof(parts) == 1) {
    return parse_expanded_ip6(_ip);
  }
  else if (sizeof(parts) == 2) {
    array tmp = allocate(8, "0");
    array _tmp = parts[0] / ":";
    for (int i = 0; i < sizeof(_tmp); i++) {
      string octet = _tmp[i];
      tmp[i] = (octet==""?"0":octet);
    }
    _tmp = parts[1] / ":";
    for (int i = 0; i < sizeof(_tmp); i++) {
      string octet = _tmp[sizeof(_tmp)-(1+i)];
      tmp[7 - i] = octet==""?"0":octet;
    }
    return parse_expanded_ip6(tmp * ":");
  }
}

static int parse_expanded_ip6(string _ip) {
  array tmp = _ip / ":";
  int ip = 0;
  if (sizeof(tmp) == 8) {
    // full IPv6 address.
    for(int i = 0; i < 8; i++) {
      int __ip;
      [__ip] = array_sscanf(tmp[i], "%x");
      ip += (__ip << 16 * (7 - i));
    }
  }
  else {
    throw(Error.Generic("Not enough octets in address!"));
  }
  return ip;
}

//! Convert a 128 bit integer to an IP address.
//!
//! @param _ip
//!   The IP address to convert.
string inttoip(int _ip) {
  if (_ip > MAX)
    throw(Error.Generic("IP address too large"));
  if (_ip < 0)
    throw(Error.Generic("Cannot have negative IP address"));
  array exp = allocate(8);
  for (int i = 0; i < 8; i++) {
    int x = (7 - i) * 16;
    int y = (8 - i) * 16;
    exp[i] = sprintf("%x", (_ip >> x) - ((_ip >> y) * 65536));
  }
  int x,y,z;
  array out = ({});
  for (int i = 0; i < 8; i++) {
    if (exp[i] != "0") {
      if (x)
	z = 1;
      out += ({ exp[i] });
    }
    else if (exp[i] == "0") {
      if (i == 7) {
	out += ({ "" });
      }
      if (!z) {
	x++;
	if (!y) {
	  out += ({ "" });
	  y++;
        }
      }
      else
	out += ({ "0" });
    }
  }
  if (out == ({ "", "" }))
    return "::";
  return out * ":";
}

string inttoipex(int _ip) {
  if (_ip > MAX)
    throw(Error.Generic("IP address too large"));
  if (_ip < 0)
    throw(Error.Generic("Cannot have negative IP address"));
  array exp = allocate(8);
  for (int i = 0; i < 8; i++) {
    int x = (7 - i) * 16;
    int y = (8 - i) * 16;
    exp[i] = (_ip >> x) - ((_ip >> y) * 65536);
  }
  for (int i = 0; i < 8; i++) {
    exp[i] = sprintf("%04x", exp[i]);
  }
  return exp*":";
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

//! Find the highest address for the given address and mask.
//!
//! @param ip
//!   An IP address.
//!
//! @param mask
//!   A netmask.
int highest(int ip, int mask) {
  int net = ip & mask;
  int _msk = mask ^ MAX;
  return net | _msk;
}

//! Convert a prefix length into an integer mask.
//!
//! @param length
//!   A prefix length.
int lengthtoint(int length) {
  if (length == 128)
    return MAX;
  else if (length < 128) {
    return (int)(MAX - (int)(pow(2,(128 -length))-1));
  }
}

//! Convert a mask to a prefix length.
//!
//! @param mask
//!   The netmask.
int masktolength(int|object mask) {
  for(int i = 0; i <= 128; i++) {
    if (lengthtoint(i) == (int)mask)
      return i;
  }
}
