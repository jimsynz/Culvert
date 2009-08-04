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

void create(object ip, object udp, mixed ... args) {
  src_port = udp->src_port;
  dst_port = udp->dst_port;
  ::create(ip, udp, @args);
}

void next(object ip, object udp) {
  if (state == CLOSE)
    return;
  if (((src == ip->src) && dst == ip->dst) ||
      ((dst == ip->dst) && src == ip->dst)) {
    set_timeout();
    payload += udp->data;
    // If the source and destination don't match our 
    // flow then just leave.
    bytes += ip->len;
    packets++;
    if (!state) {
      // We're the first packet!
      src_port = udp->src_port;
      dst_port = udp->dst_port;
      set_state(ONEWAY);
      conversation += ({ ([ "time" : now(), "direction" : "out", "packet" : udp ]) });
    }
    else if (state) {
      if ((src_port = udp->src_port) &&
	  (dst_port = udp->dst_port)) {
	// We're unidirectional, so far at least.
	if (state != ESTABLISHED)
	  set_state(ONEWAY);
	conversation += ({ ([ "time" : now(), "direction" : "out", "packet" : udp ]) });
      }
      else {
	set_state(ESTABLISHED);
	conversation += ({ ([ "time" : now(), "direction" : "in", "packet" : udp ]) });
      }
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
