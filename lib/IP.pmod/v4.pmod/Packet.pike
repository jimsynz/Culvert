
int version;
int ihl;
int tos;
int len;
int snaplen;
int identification;
int flags;
int frag_offset;
int ttl;
IP.Protocol.Protocol protocol;
int header_checksum;
IP.v4.Address src;
IP.v4.Address dst;
string data;
static int dns;

void create(void|string payload, void|int _dns) {
  dns = _dns;
  if (stringp(payload))
    parse(payload);
}

void parse(string payload) {
  snaplen = sizeof(payload);
  if (snaplen < 20) {
    throw(Error.Generic("Packet too small - can't get complete IP header"));
  }
  int tmp;
  tmp = (int)payload[0];
  version = tmp >> 4;
  ihl = tmp << 4;
  tos = (int)payload[1];
  [len] = array_sscanf(payload[2..3], "%2c");
  [identification] = array_sscanf(payload[4..5], "%2c");
  [tmp] = array_sscanf(payload[6..7], "%2c");
  // FIXME: flags = 3 bits, frag_offset = 13 bits.
  flags = frag_offset = tmp;
  ttl = (int)payload[8];
  protocol = IP.Protocol.Protocol((int)payload[9]);
  [header_checksum] = array_sscanf(payload[10..11], "%2c");
  int _src, _dst;
  [_src] = array_sscanf(payload[12..15], "%4c");
  [_dst] = array_sscanf(payload[16..19], "%4c");
  src = IP.v4.Address(_src, dns);
  dst = IP.v4.Address(_dst, dns);
  data = payload[20..];
}
