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
static IP.Protocol.ICMP.Type _type;
static int _code;
static int _chksum;
static int _error;
static string _data;

void create(string packet) {
  type = IP.Protocol.ICMP.Type(packet[0]);
  if (type->numeric() <= 127) 
    error = 1;
  code = packet[1];
  [chksum] = array_sscanf(packet[2..3], "%2c");
  if (sizeof(packet) > 4)
    data = packet[5..];
}

IP.Protocol.ICMP.Type `type() {
  return _type;
}

IP.Protocol.ICMP.Type `type=(IP.Protocol.ICMP.Type x) {
  LOCK;
  return _type = x;
}

int `code() {
  return _code;
}

int `code=(int x) {
  LOCK;
  return _code = x;
}

int `chksum() {
  return _chksum;
}

int `chksum=(int x) {
  LOCK;
  return _chksum = x;
}

int `error() {
  return _error;
}

int `error=(int x) {
  LOCK;
  return _error = x;
}

string `data() {
  return _data;
}

string `data=(string x) {
  LOCK;
  return _data = x;
}
