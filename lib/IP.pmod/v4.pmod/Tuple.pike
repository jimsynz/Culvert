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
 * Portions created by the Initial Developer are Copyright (C) 2005
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Bill Welliver <hww3@riverweb.com>.
 *
 * ***** END LICENSE BLOCK ***** */

//! This module defines a connection between two machines, for example a TCP
//! socket, or a UDP datagram.

//! The local address of the datagram or stream.
static IP.v4.Address _local_addr;

//! The remote address of the datagram or stream.
static IP.v4.Address _remote_addr;

//! The local port of the datagram or streamm if applicable.
static int _local_port;

//! The remote port of the datagram or stream, if applicable.
static int _remote_port;

//! The IP protocol used for this datagram or stream.
static IP.Protocol.Protocol _protocol;

//! Clone the IP.v4.Tuple class.
//!
//! @param l_addr
//!   Either an IP.v4.Address representing the local address of the
//!   connection, or a Stdio.File object containing the TCP socket.
//!
//! @param l_port
//!   The local port, if applicable.
//!
//! @param r_addr
//!   An IP.v4.Address represnting the remote endpoint of the connection.
//!
//! @param r_port
//!   The remote port.
//!
//! @param proto
//!   An IP.Protocol.Protocol representing the IP protocol.
//!
void create(Stdio.File|IP.v4.Address l_addr, void|int l_port, void|IP.v4.Address r_addr, void|int r_port, void|IP.Protocol.Protocol proto) {
  if (l_addr->stat)
    from_fd(l_addr);
  else {
    _local_addr = l_addr;
    _remote_addr = r_addr;
    _local_port = l_port;
    _remote_port = r_port;
    _protocol = proto;
  }
}

static void from_fd(Stdio.File fd) {
  string l_addr, r_addr;
  int l_port, r_port;
  sscanf(fd->query_address(), "%s %d", r_addr, r_port);
  sscanf(fd->query_address(1), "%s %d", l_addr, l_port);
  _local_addr = IP.v4.Address(l_addr);
  _local_port = l_port;
  _remote_addr = IP.v4.Address(r_addr);
  _remote_port = r_port;
  _protocol = IP.Protocol.Protocol("TCP");
}

string _sprintf() {
  return
    sprintf("IP.v4.Tuple(%O, %O, %O, %O, %O)",
      (string)_local_addr,
      (int)_local_port,
      (string)_remote_addr,
      (int)_remote_port,
      (string)_protocol
    );
}

IP.v4.Address local_addr(void|int|string|IP.v4.Address l_addr) {
  if (objectp(l_addr)) {
    if (l_addr->numeric && (l_addr->numeric() != _local_addr->numeric()))
      _local_addr = l_addr;
    return _local_addr;
  }
  else if (stringp(l_addr) || intp(l_addr)) {
    if (IP.v4.Address(l_addr)->numeric() != _local_addr->numeric())
      _local_addr = l_addr;
    return _local_addr;
  }
  else 
    return _local_addr;
}

IP.v4.Address remote_addr(void|int|string|IP.v4.Address r_addr) {
  if (objectp(r_addr)) {
    if (r_addr->numeric && (r_addr->numeric() != _remote_addr->numeric()))
      _remote_addr = r_addr;
    return _remote_addr;
  }
  else if (stringp(r_addr) || intp(r_addr)) {
    if (IP.v4.Address(r_addr)->numeric() != _remote_addr->numeric())
      _remote_addr = IP.v4.Address(r_addr);
    return _remote_addr;
  }
  else 
    return _remote_addr;
}

void|int local_port(int p) {
  if (p != _local_port)
    _local_port = p;
  return _local_port;
}

void|int remote_port(int p) {
  if (p != _remote_port)
    _remote_port = p;
  return _remote_port;
}

void|IP.Protocol.Protocol protocol(void|int|string|IP.Protocol.Protocol p) {
  if (objectp(p)) {
    if (p->name && (p->name() != _protocol->name()))
      _protocol = p;
    return _protocol;
  }
  else if (stringp(p) || intp(p)) {
    _protocol = IP.Protocol.Protocol(p);
    return _protocol;
  }
  else
    return _protocol;
}
