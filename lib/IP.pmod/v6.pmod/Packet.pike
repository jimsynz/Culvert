
static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key);
static int _version;
static int _traffic_class;
static int _flow_label;
static int _snaplen;
static int _len;
static IP.Protocol.Protocol _next_header;
static int _hop_limit;
static IP.v6.Address _src;
static IP.v6.Address _dst;
static string _data;
static string ___payload;
static int _dns;

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

int `version() {
  return _version;
}

int `version=(int x) {
  LOCK;
  return _version = x;
}

int `traffic_class() {
  return _traffic_class;
}

int `traffic_class=(int x) {
  LOCK;
  return _traffic_class;
}

int `flow_label() {
  return _flow_label;
}

int `flow_label=(int x) {
  LOCK;
  return _flow_label = x;
}

int `snaplen() {
  return _snaplen;
}

int `snaplen=(int x) {
  LOCK;
  return _snaplen = x;
}

int `len() {
  return _len;
}

int `len=(int x) {
  LOCK;
  return _len = x;
}

IP.Protocol.Protocol `next_header() {
  return _next_header;
}

IP.Protocol.Protocol `next_header=(IP.Protocol.Protocol x) {
  LOCK;
  return _next_header = x;
}

int `hop_limit() {
  return _hop_limit;
}

int `hop_limit=(int x) {
  LOCK;
  return _hop_limit;
}

IP.v6.Address `src() {
  return _src;
}

IP.v6.Address `src=(IP.v6.Address x) {
  LOCK;
  return _src = x;
}

IP.v6.Address `dst() {
  return _dst;
}

IP.v6.Address `dst=(IP.v6.Address x) {
  LOCK;
  return _dst = x;
}

string `data() {
  return _data;
}

string `data=(string x) {
  LOCK;
  return _data = x;
}

static string `__payload() {
  return ___payload;
}

static string `__payload=(string x) {
  LOCK;
  return ___payload = x;
}

static int `dns() {
  return _dns;
}

static int `dns=(int x) {
  LOCK;
  return _dns = x;
}
