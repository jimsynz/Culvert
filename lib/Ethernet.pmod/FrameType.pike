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

static int _type;
static mapping types = ([
    0x0800 : "IPv4",
    0x0806 : "ARP",
    0x8035 : "RARP",
    0x809b : "Ethertalk",
    0x80f3 : "AARP",
    0x8100 : "802.1Q",
    0x8137 : "IPX",
    0x8138 : "IPX",
    0x86DD : "IPv6",
    0x8819 : "CobraNet",
    0x88a8 : "802.1ad",
    0x8847 : "MPLS_unicast",
    0x8848 : "MPLS_multicast",
    0x8863 : "PPPoE_discovery",
    0x8864 : "PPPoE_session",
    0x888E : "802.1X",
    0x889A : "HyperSCSI",
    0x88A2 : "ATAoE",
    0x88A4 : "EtherCAT",
    0x88CD : "SERCOS-III",
    0x88D8 : "MEF-8",
    0x88E5 : "802.1AE",
    0x8906 : "FCoE",
    0x8914 : "FCoE_init",
    0x9100 : "QinQ",
    0xCAFE : "LLT",
  ]);

void create(int|string type) {
  if (intp(type))
    _type = type;
  else if (stringp(type)) {
    mapping tmp = mkmapping(values(types), indices(types));
    if (tmp[type])
      _type = tmp[type];
  }
}

int numeric() {
  return _type;
}

string hex() {
  return sprintf("0x%0:4x", _type);
}

void|string name() {
  if (types[_type])
    return types[_type];
  else
    return "UNKNOWN";
}

string _sprintf() {
  return sprintf("Ethernet.FrameType(%O)", name());
}
