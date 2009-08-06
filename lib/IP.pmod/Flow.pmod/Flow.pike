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

/*
   Don't use this module directly, inherit it from your protocol flow
   handler.

   */


static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static object _src;
static object _dst;
static int _bytes;
static int _packets;
static array _conversation = ({});
static int _state;
static string _payload;
static object _protocol;
static int _start_time;
static float _time_offset;

static function __exp_cb;
static function __state_cb;
static mixed __hash;
static mixed _timeout_co;

#define EXP_TIMEOUT 120

constant ONEWAY = 1;
constant ESTABLISHED = 2;
constant CLOSING = 3;
constant CLOSE = 4;
constant UNKNOWN = 5;

void create(object ip, object layer3, void|mixed _hash, void|function exp, void|function state) {
  src = ip->src;
  dst = ip->dst;
  protocol = ip->protocol||ip->next_header;
  //conversation = ({});
  payload = "";
  start_time = time();
  time_offset = time(start_time);
  if (_hash)
    hash(_hash);
  if (functionp(exp))
    expire_cb(exp);
  if (functionp(state))
    state_cb(state);
  next(ip, layer3);
}

float now() {
  return time(start_time) - time_offset;
}

mixed hash(void|mixed __hash) {
  if (__hash)
    _hash = __hash;
  return _hash;
}

void expire_cb(function cb) {
  if (functionp(cb))
    _exp_cb = cb;
}

void state_cb(function cb) {
  if (functionp(cb))
    _state_cb = cb;
}

void set_timeout() {
#ifdef ENABLE_THREADS
  if (timeout_co)
    timeout_co->kill();
  timeout_co = Thread.thread_create(lambda() { sleep(EXP_TIMEOUT); timeout(); });
#else 
  if (timeout_co)
    remove_call_out(timeout_co);
  timeout_co = call_out(timeout, EXP_TIMEOUT);
#endif
}

void timeout() {
  if (state == CLOSING) {
    state = CLOSE;
    _exp_cb(_hash);
  }
  else {
    state = CLOSING;
    set_timeout();
  }
}

void next(object ip, object udp) {};

string english(void|int dns, void|int scope) {
  string state;
  string dir = "<->";
  switch (this->state) {
    case 1:
      state = "ONEWAY";
      dir = "-->";
      break;
    case 2:
      state = "ESTABLISHED";
      break;
    case 3:
      state = "CLOSING";
      dir = "!!!";
      break;
    case 4: 
      state = "CLOSED";
      dir = "!!!";
      break;
    case 5:
      state = "UNKNOWN";
      dir = "---";
      break;
    case 10:
      state = "SYN_SENT";
      dir = "-->";
      break;
    case 11:
      state = "SYN_RECV";
      dir = "< >";
      break;
    case 12:
      state = "CLOSE_WAIT";
      dir = "<!>";
      break;
    default:
      dir = "<->";
      state = "ESTABLISHED";
      break;
  }
  string _src, _dst;
  if (dns) {
    if (src->hostname)
      _src = src->hostname();
    if (dst->hostname)
      _dst = dst->hostname();
  }
  if (!_src)
    if (sizeof((string)src / ":") > 1)
      _src = sprintf("[%s]", (string)src);
    else
      _src = (string)src;
  if (!_dst)
    if (sizeof((string)dst / ":") > 1)
      _dst = sprintf("[%s]", (string)dst);
    else
      _dst = (string)dst;

  if (this->src_port)
    _src = sprintf("%s:%d", _src, this->src_port);
  if (this->dst_port)
    _dst = sprintf("%s:%d", _dst, this->dst_port);
  string _src_scope, _dst_scope = "";
  if (scope) {
    if (functionp(src->scope))
      _src_scope = sprintf(" %s", src->scope());
    if (functionp(dst->scope))
      _dst_scope = sprintf(" %s", dst->scope());
  }


  string first = (Calendar.Second(start_time)->format_time() / " ")[1];
  string last = flowtime>0.0?sprintf("%:2fs", flowtime):"-.--s";
  string rates;
  if (packets > 1) {
    string brate = replace(String.int2size((int)bps) + "ps", "B", "b");
    brate = replace(brate, "bytes", "b");
    string prate = replace(String.int2size((int)pps) + "ps", "B", "b");
    prate = replace(prate, "bytes", "p");
    prate = replace(prate, "byte", "p");
    prate = replace(prate, "b", "p");
    rates = sprintf("%s %s, %d packets %s", replace(String.int2size(bytes), "b", "B"), brate, packets, prate);
  }
  else 
    rates = sprintf("%s, 1 packet", replace(String.int2size(bytes), "b", "B"));

  return sprintf("%s %6s %s %s%s %s %s%s (%s) %s", first, last, protocol->name(), _src, _src_scope, dir||"", _dst, _dst_scope, rates, state);
}

//string _sprintf() {
  //return sprintf("Protocol.IP.Protocol.%s.Flow(/* %s */)", protocol->name(), english());
//}

//! BITS per second.
float `bps() {
  if (sizeof(conversation) > 1)
    return bytes * 8 / flowtime;
  else 
    return 0.0;
}

float `pps() {
  if (sizeof(conversation) > 1)
    return packets / flowtime;
  else
    return 0.0;
}

float `flowtime() {
  if (sizeof(conversation) > 1)
    return abs(conversation[-1]->time - time_offset);
  else
    return 0.0;
}

object `src() {
  return _src;
}

object `src=(object x) {
  return _src = x;
}

object `dst() {
  return _dst;
}

object `dst=(object x) {
  return _dst = x;
}

int `bytes() {
  return _bytes;
}

int `bytes=(int x) {
  LOCK;
  return _bytes = x;
}

int `packets() {
  return _packets;
}

int `packets=(int x) {
  LOCK;
  return _packets = x;
}

array `conversation() {
  return _conversation;
}

array `conversation=(array x) {
  LOCK;
  return _conversation = x;
}

int `state() {
  return _state;
}

int `state=(int x) {
  if (_state != x) {
    int oldstate = _state;
    LOCK;
    _state = x;
    UNLOCK;
    if (functionp(_state_cb))
      _state_cb(_hash, oldstate, _state);
    return _state;
  }
  else 
    return x;
}

string `payload() {
  return _payload;
}

string `payload=(string x) {
  LOCK;
  return _payload = x;
}

object `protocol() {
  return _protocol;
}

object `protocol=(object x) {
  LOCK;
  return _protocol = x;
}

int `start_time() {
  return _start_time;
}

int `start_time=(int x) {
  LOCK;
  return _start_time = x;
}

float `time_offset() {
  return _time_offset;
}

float `time_offset=(float x) {
  LOCK;
  return _time_offset = x;
}

static function `_exp_cb() {
  return __exp_cb;
}

static function `_exp_cb=(function x) {
  LOCK;
  return __exp_cb = x;
}

static function `_state_cb() {
  return __state_cb;
}

static function `_state_cb=(function x) {
  LOCK;
  return __state_cb = x;
}

static mixed `_hash() {
  return __hash;
}

static mixed `_hash=(mixed x) {
  LOCK;
  return __hash = x;
}

static mixed `timeout_co() {
  return _timeout_co;
}

static mixed `timeout_co=(mixed x) {
  LOCK;
  return _timeout_co = x;
}
