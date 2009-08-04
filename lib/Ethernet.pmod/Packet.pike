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

int len;
int dst;
int src;
Ethernet.FrameType type;
string data;

void create(void|string payload) {
  if (stringp(payload)) {
    parse(payload);
  }
}

void parse(string payload) {
  len = sizeof(payload);
  string _src = payload[0..5];
  string _dst = payload[6..11];
  string _type = payload[12..13];
  data = payload[14..];
  [src] = array_sscanf(_src, "%6c");
  [dst] = array_sscanf(_dst, "%6c");
  int __type;
  [__type] = array_sscanf(_type, "%2c");
  type = Ethernet.FrameType(__type);
}

string src_mac() {
  if (src) {
    return (sprintf("%0:12x", src) / 2) * ":";
  }
}

string dst_mac() {
  if (dst) {
    return (sprintf("%0:12x", dst) / 2) * ":";
  }
}


static string _sprintf() {
  return sprintf("Ethernet.Frame(/* %s -> %s */)", src_mac(), dst_mac());
}
