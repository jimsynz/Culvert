
int version;
int traffic_class;
int flow_label;
int snaplen;
int len;
IP.Protocol.Protocol next_header;
int hop_limit;
IP.v6.Address src;
IP.v6.Address dst;
string data;
static string __payload;
static int dns;

void create(void|string payload, void|int _dns) {
  __payload = payload;
  snaplen = sizeof(payload);
  if (snaplen < 40) {
    Stdio.write_file("ipv6.error", payload);
    throw(Error.Generic("Packet too small - can't get complete IPv6 header"));
  }
  dns = _dns;
  if (stringp(payload))
    parse(payload);
}

void parse(string _payload, void|int pos) {
  string payload = _payload[pos..];
  int tmp;
  [tmp] = array_sscanf(payload[0..3], "%4c");
  version = tmp >> 27;
  traffic_class = ((version<<27)^tmp)>>3;
  flow_label = ((tmp>>19)<<19)^tmp;
  [len] = array_sscanf(payload[4..5], "%2c");
  int _next_header;
  [_next_header,hop_limit] = array_sscanf(payload[6..7], "%c%c");
  next_header = IP.Protocol.Protocol(_next_header);
  int _src, _dst;
  [_src] = array_sscanf(payload[8..23], "%16c");
  [_dst] = array_sscanf(payload[24..39], "%16c");
  src = IP.v6.Address(_src, dns);
  dst = IP.v6.Address(_dst, dns);
  if ((sizeof(payload) > 40) && (!data))
    data = _payload[40..];
}
