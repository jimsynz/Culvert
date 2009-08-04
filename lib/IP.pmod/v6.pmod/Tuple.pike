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

//! This module defines a connection between two machines, for example a TCP
//! socket, or a UDP datagram.

static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key);


//! The local address of the datagram or stream.
static IP.v6.Address _local_addr;

//! The remote address of the datagram or stream.
static IP.v6.Address _remote_addr;

//! The local port of the datagram or streamm if applicable.
static int _local_port;

//! The remote port of the datagram or stream, if applicable.
static int _remote_port;

//! The IP protocol used for this datagram or stream.
static IP.Protocol.Protocol _protocol;

//! Clone the IP.v6.Tuple class.
//!
//! @param l_addr
//!   Either an IP.v6.Address representing the local address of the
//!   connection, or a Stdio.File object containing the TCP socket.
//!
//! @param l_port
//!   The local port, if applicable.
//!
//! @param r_addr
//!   An IP.v6.Address represnting the remote endpoint of the connection.
//!
//! @param r_port
//!   The remote port.
//!
//! @param proto
//!   An IP.Protocol.Protocol.Protocol representing the IP protocol.
//!
void create(Stdio.File|IP.v6.Address l_addr, void|int l_port, void|IP.v6.Address r_addr, void|int r_port, void|IP.Protocol.Protocol.Protocol proto) {
  if (l_addr->stat)
    from_fd(l_addr);
  else {
    local_addr = l_addr;
    remote_addr = r_addr;
    local_port = l_port;
    remote_port = r_port;
    protocol = proto;
  }
}

IP.v6.Address `local_addr() {
  return _local_addr;
}

IP.v6.Address `local_addr=(IP.v6.Address x) {
  LOCK;
  return _local_addr = x;
}

IP.v6.Address `remote_addr() {
  return _remote_addr;
}

IP.v6.Address `remote_addr=(IP.v6.Address x) {
  LOCK;
  return _remote_addr = x;
}

int `local_port() {
  return _local_port;
}

int `local_port=(int x) {
  LOCK;
  return _local_port = x;
}

int `remote_port() {
  return _remote_port;
}

int `remote_port=(int x) {
  LOCK;
  return _remote_port = x;
}

IP.Protocol.Protocol `protocol() {
  return _protocol;
}

IP.Protocol.Protocol `protocol=(IP.Protocol.Protocol x) {
  LOCK;
  return _protocol;
}

static void from_fd(Stdio.File fd) {
  string l_addr, r_addr;
  int l_port, r_port;
  sscanf(fd->query_address(), "%s %d", r_addr, r_port);
  sscanf(fd->query_address(1), "%s %d", l_addr, l_port);
  local_addr = IP.v6.Address(l_addr);
  local_port = l_port;
  remote_addr = IP.v6.Address(r_addr);
  remote_port = r_port;
  protocol = IP.Protocol.Protocol.Protocol("TCP");
}

string _sprintf() {
  return
    sprintf("IP.v6.Tuple(%O, %O, %O, %O, %O)",
      (string)local_addr,
      (int)local_port,
      (string)remote_addr,
      (int)remote_port,
      (string)protocol
    );
}

