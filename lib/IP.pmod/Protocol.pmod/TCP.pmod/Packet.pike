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
static int _src_port;
static int _dst_port;
static int _seq_no;
static int _ack_no;
static int _data_offset;
static multiset _flags;
static int _window;
static int _checksum;
static int _urgent_pointer;
static array _options;
static string _data;
static string __payload;

void create(string payload) {
  _payload = payload;
  flags = (<>);
  options = ({});
  int tmp;
  sscanf(payload[0..1], "%2c", src_port);
  sscanf(payload[2..3], "%2c", dst_port);
  sscanf(payload[4..7], "%4c", seq_no);
  sscanf(payload[8..11], "%4c", ack_no);
  sscanf(payload[12..13], "%2c", tmp);
  sscanf(payload[14..15], "%2c", window);
  sscanf(payload[16..17], "%2c", checksum);
  sscanf(payload[18..19], "%2c", urgent_pointer);
  data_offset = tmp >> 12;
  array _flags = (array(int))reverse(sprintf("%b", tmp) / "");
  if (_flags[0])
    flags += (< "FIN" >);
  if (_flags[1])
    flags += (< "SYN" >);
  if (_flags[2])
    flags += (< "RST" >);
  if (_flags[3])
    flags += (< "PSH" >);
  if (_flags[4])
    flags += (< "ACK" >);
  if (_flags[5])
    flags += (< "URG" >);
  string opts = payload[20..data_offset];
  int i;
  while (i < sizeof(opts)) {
    object o = .Option(opts[i..]);
    if (o->name() == "END")
      break;
    i += o->len;
  }
  if (sizeof(payload) > data_offset)
    data = payload[data_offset..];
}

int `src_port() {
  return _src_port;
}

int `src_port=(int x) {
  LOCK;
  return _src_port = x;
}

int `dst_port() {
  return _dst_port;
}

int `dst_port=(int x) {
  LOCK;
  return _dst_port = x;
}

int `seq_no() {
  return _seq_no;
}

int `seq_no=(int x) {
  LOCK;
  return _seq_no = x;
}

int `ack_no() {
  return _ack_no;
}

int `ack_no=(int x) {
  LOCK;
  return _ack_no = x;
}

int `data_offset() {
  return _data_offset;
}

int `data_offset=(int x) {
  LOCK;
  return _data_offset = x;
}

multiset `flags() {
  return _flags;
}

multiset `flags=(multiset x) {
  LOCK;
  return _flags = x;
}

int `window() {
  return _window;
}

int `window=(int x) {
  LOCK;
  return _window = x;
}

int `checksum() {
  return _checksum;
}

int `checksum=(int x) {
  LOCK;
  return _checksum = x;
}

int `urgent_pointer() {
  return _urgent_pointer;
}

int `urgent_pointer=(int x) {
  LOCK;
  return _urgent_pointer = x;
}

array `options() {
  return _options;
}

array `options=(array x) {
  LOCK;
  return _options = x;
}

string `data() {
  return _data;
}

string `data=(string x) {
  LOCK;
  return _data = x;
}

static string `_payload() {
  return __payload;
}

static string `_payload=(string x) {
  LOCK;
  return __payload = x;
}
