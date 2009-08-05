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

inherit IP.Flow.Flow;

static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static int _src_port;
static int _dst_port;

constant SYN_SENT = 10;
constant SYN_RECV = 11;
constant CLOSE_WAIT = 12;

void create(object ip, object tcp, mixed ... args) {
  src_port = tcp->src_port;
  dst_port = tcp->dst_port;
  ::create(ip, tcp, @args);
}

void tcp_state(object tcp) {
  if (tcp->flags["SYN"] &
      !tcp->flags["ACK"])
    state = SYN_SENT;
  else if (tcp->flags["SYN"] &&
      tcp->flags["ACK"])
    state = SYN_RECV;
  else if ((tcp->flags["RST"] && !tcp->flags["ACK"]) ||
      (tcp->flags["FIN"] && !tcp->flags["ACK"]))
    state = CLOSE_WAIT;
  else if ((tcp->flags["RST"] && tcp->flags["ACK"]) || 
      (tcp->flags["FIN"] && tcp->flags["ACK"])) {
    state = CLOSE;
    if (timeout_co) {
#ifdef ENABLE_THREADS
      timeout_co->kill();
      timeout_co = 0;
#else
      remove_call_out(timeout_co);
#endif
    }
    if (log_co) {
#ifdef ENABLE_THREADS
      log_co->kill();
      log_co = 0;
#else
      remove_call_out(log_co);
#endif
    }
    if (_exp_cb)
      _exp_cb(_hash);
  }
  else if (tcp->flags["ACK"] &&
      !tcp->flags["SYN"] && (state != CLOSE))
    state = ESTABLISHED;
  else if (state != CLOSE)
    state = UNKNOWN;
}

void next(object ip, object tcp) {
  //if (state == CLOSE)
    //return;
  if (((src == ip->src) && dst == ip->dst) ||
      ((dst == ip->dst) && src == ip->dst)) {
    set_timeout();
    payload += tcp->data;
    // If the source and destination don't match our 
    // flow then just leave.
    bytes += ip->len;
    packets++;
    if (!state) {
      // We're the first packet!
      src_port = tcp->src_port;
      dst_port = tcp->dst_port;
      conversation = ({ ([ "time" : now(), "direction" : "out", "packet" : tcp ]) });
      tcp_state(tcp);
    }
    else if (state) {
      if ((src == tcp->src) &&
	  (dst == tcp->dst)) {
	conversation += ({ ([ "time" : now(), "direction" : "out", "packet" : tcp ]) });
      }
      else {
	conversation += ({ ([ "time" : now(), "direction" : "in", "packet" : tcp ]) });
      }

      tcp_state(tcp);
    }
  }
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
