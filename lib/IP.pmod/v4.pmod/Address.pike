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

//! This module describes an IP.v4 address.
//! You can use this module by simply casting to an int or string.


static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static int _ip;
static inherit "helpers";
string __hostname;

//! Close the IP.v4.Address module.
//!
//! @param _ip
//!   An IP address.
//!
//! @param dns
//!   True if you want a reverse DNS query done.
//!
void create(int|string _ip, void|int dns) {
  if (intp(_ip))
    ip = _ip;
  else if (stringp(_ip)) {
    int a,b,c,d;
    if (sscanf(_ip, "%d.%d.%d.%d", a,b,c,d) == 4)
      ip = iptoint(_ip);
    else {
      array h;
      if (h = gethostbyname(_ip)) {
	if (arrayp(h) && arrayp(h[1]) && sizeof(h[1]))
	  ip = iptoint(h[1][0]);
	else
	  throw(({ sprintf("Unable to resolve %O", _ip), backtrace() }));
      }
    }
  }
  if (dns)
    IP.Flow.DNSCache->lookup_ip(inttoip(ip), set_hostname);
}

void set_hostname(string __hostname) {
  _hostname = __hostname;
}

string hostname() {
  if (_hostname)
    return _hostname;
  else
    return _hostname = IP.Flow.DNSCache->lookup_ip(inttoip(ip));
}

string reverse() {
 return (predef::reverse(inttoip(ip) / ".") * ".") + ".in-addr.arpa";
}

string scope() {
  string s = "GLOBAL UNICAST";
  if (IP.v4.Prefix("224.0.0.0/4")->contains(this_object())) {
    s = "GLOBAL MULTICAST";
    if (IP.v4.Prefix("239.0.0.0/8")->contains(this_object()))
      s = "LOCAL MULTICAST";
  }
  else if (IP.v4.Prefix("192.168.0.0/16")->contains(this_object()))
    s = "RFC1918 PRIVATE";
  else if (IP.v4.Prefix("10.0.0.0/8")->contains(this_object()))
    s = "RFC1918 PRIVATE";
  else if (IP.v4.Prefix("172.16.0.0/12")->contains(this_object()))
    s = "RFC1918 PRIVATE";
  else if (IP.v4.Prefix("169.254.0.0/16")->contains(this_object()))
    s = "PRIVATE";
  else if (IP.v4.Prefix("127.0.0.0/8")->contains(this_object()))
    s = "LOOPBACK";
  else if (IP.v4.Prefix("192.88.99.0/24")->contains(this_object()))
    s = "GLOBAL UNICAST (6to4 ANYCAST)";
  else if (IP.v4.Prefix("198.18.0.0/15")->contains(this_object()))
    s = "NETWORK BENCHMARK TESTS";
  else if (IP.v4.Address("255.255.255.255") == this_object())
    s = "GLOBAL BROADCAST";
  else if (IP.v4.Prefix("128.0.0.0/16")->contains(this_object()))
    s = "RESERVED (IANA)";
  else if (IP.v4.Prefix("191.255.0.0/16")->contains(this_object()))
    s = "RESERVED (IANA)";
  else if (IP.v4.Prefix("223.255.255.0/24")->contains(this_object()))
    s = "RESERVED (IANA)";
  else if (IP.v4.Prefix("240.0.0.0/4")->contains(this_object()))
    s = "RESERVED";
  else if (IP.v4.Address(0) == this_object())
    s = "DEFAULT";
  return s;
}

string _sprintf() {
  return sprintf("IP.v4.Address(%O)", _hostname||inttoip(ip));
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

IP.v6.Address sixtofour() {
  return IP.v6.Address((0x2002 << 112) + (ip << 80));
}

int(0..1) `==(IP.v4.Address test) {
  if (objectp(test) && test->numeric)
    return (test->numeric() == numeric());
  else 
    return 0;
}

int(0..1) `<(IP.v4.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() < test->numeric());
  else 
    return 0;
}

int(0..1) `<=(IP.v4.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() <= test->numeric());
  else 
    return 0;
}

int(0..1) `>(IP.v4.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() > test->numeric());
  else 
    return 0;
}

int(0..1) `>=(IP.v4.Address test) {
  if (objectp(test) && test->numeric)
    return (numeric() >= test->numeric());
  else 
    return 0;
}

static int `ip() {
  return _ip;
}

static int `ip=(int x) {
  LOCK;
  return _ip = x;
}

static string `_hostname() {
  return __hostname;
}

static string `_hostname=(string x) {
  LOCK;
  return __hostname = x;
}
