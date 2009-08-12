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

//! This module describes an IP.v6 address.
//! You can use this module by simply casting to an int or string.


static int _ip;
static inherit "helpers";
static string _hostname;
static object _mutex = Thread.Mutex();

#define LOCK object __key = _mutex->lock(1);
#define UNLOCK destruct(__key);

//! Clone the IP.v6.Address module.
//!
//! @param _ip
//!   An IP address.
//!
void create(int|string _ip, void|int dns) {
  if (intp(_ip))
    ip = _ip;
  else if (stringp(_ip)) {
    ip = iptoint(_ip);
  }
  if (dns)
    IP.Flow.DNSCache->lookup_ip(inttoip(ip), set_hostname);
}

int `ip() {
  return _ip;
}

int `ip=(int x) {
  LOCK;
  return _ip = x;
}

static void set_hostname(string __hostname) {
  _hostname = __hostname;
}

string hostname() {
  if (_hostname)
    return _hostname;
  else
    return _hostname = IP.Flow.DNSCache->lookup_ip(inttoip(ip));
}

string _sprintf() {
  return sprintf("IP.v6.Address(/* %s */ %O)", scope(), _hostname||inttoip(ip));
}

//!
void|int|string cast(string type) {
  switch(type) {
  case "int":
    return ip;
  case "string":
    return inttoip(ip);
  }
}

int numeric() {
  return ip;
}

string expanded() {
  return inttoipex(ip);
}

string reverse() {
  string s = inttoipex(ip);
  s = replace(s, ":", "");
  return (predef::reverse(s / "") * ".") + ".ip6.arpa";
}

string scope() {
  string s = "RESERVED";
  if (IP.v6.Prefix("2000::/3")->contains(this_object())) {
    s = "GLOBAL UNICAST";
    if (IP.v6.Prefix("2002::/16")->contains(this_object())) {
      // 6to4
      int a,b;
      sscanf(inttoipex(ip), "%*4x:%4x:%4x:%*s", a, b);
      s = sprintf("GLOBAL UNICAST (6to4: %s)", (string)IP.v4.Address((a<<16)+b));
    }
    else if (IP.v6.Prefix("2001::/32")->contains(this_object())) {
      // teredo
      int server_ip = ((ip >> 64) & ((1<<32)-1));
      int client_ip = (ip & ((1<<32)-1)) ^ ((1<<32)-1);
      int udp_port = ((ip >> 32) & ((1<<16)-1));
      s = sprintf("GLOBAL UNICAST (Teredo %s:%d -> %s:%d)", (string)IP.v4.Address(client_ip), udp_port, (string)IP.v4.Address(server_ip), udp_port);
    }
    else if (IP.v6.Prefix("2001:10::/28")->contains(this_object()))
      s = "ORCHID";
    else if (IP.v6.Prefix("2001:db8::/32")->contains(this_object()))
      s = "DOCUMENTATION";
  }
  else if (IP.v6.Prefix("::/128")->contains(this_object()))
    s = "UNSPECIFIED ADDRESS";
  else if (IP.v6.Prefix("::1/128")->contains(this_object()))
    s = "LINK LOCAL LOOPBACK";
  else if (IP.v6.Prefix("::ffff:0:0/96")->contains(this_object())) {
    int a,b,c,d;
    sscanf(inttoipex(ip), "%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%4x:%4x:%4x:%4x", a,b,c,d);
    s = sprintf("IPv4 MAPPED (%d.%d.%d.%d)", a,b,c,d);
  }
  else if (IP.v6.Prefix("::/96")->contains(this_object())) {
    int a,b,c,d;
    sscanf(inttoipex(ip), "%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%4x:%4x:%4x:%4x", a,b,c,d);
    s = sprintf("IPv4 TRANSITION (%d.%d.%d.%d deprecated)", a,b,c,d);
  }
  else if (IP.v6.Prefix("fc00::/7")->contains(this_object()))
    s = "UNIQUE LOCAL UNICAST";
  else if (IP.v6.Prefix("fec0::/10")->contains(this_object()))
    s = "SITE LOCAL (deprecated)";
  else if (IP.v6.Prefix("fe80::/10")->contains(this_object()))
    s = "LINK LOCAL UNICAST";
  else if (IP.v6.Prefix("ff00::/8")->contains(this_object())) {
    s = "MULTICAST";
    int mscope,mdesta,mdestb,mdest;
    sscanf(inttoipex(ip), "%*1x%*1x%*1x%1x:%*4x:%*4x:%*4x:%*4x:%*4x:%4x:%4x", mscope, mdesta, mdestb);
    mdest = (mdesta << 16) + mdestb;
    if (mscopes[mscope]) 
      s = mscopes[mscope];
    if (mdests[mdest])
      s += " " + mdests[mdest];
  }
  return s;
}

int(0..1) `==(IP.v6.Address test) {
  if (objectp(test) && test->numeric)
    return (test->numeric() == numeric());
  else
    return 0;
}

int(0..1) `<(IP.v6.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() < test->numeric());
  else
    return 0;
}

int(0..1) `<=(IP.v6.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() <= test->numeric());
  else
    return 0;
}

int(0..1) `>(IP.v6.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() > test->numeric());
  else
    return 0;
}

int(0..1) `>=(IP.v6.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() >= test->numeric());
  else
    return 0;
}
