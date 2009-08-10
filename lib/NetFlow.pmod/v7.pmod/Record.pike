
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

static object _mutex = Thread.Mutex();
static int _srcaddr;
static int _dstaddr;
static int _nexthop;
static int _input;
static int _output;
static int _dPkts;
static int _dOctets;
static int _first;
static int _last;
static int _srcport;
static int _dstport;
static int _tcp_flags;
static int _prot;
static int _tos;
static int _src_as;
static int _dst_as;
static int _src_mask;
static int _dst_mask;
static int _flags;
static int _router_sc;

constant size = 52;

object decode_record(string rbuff) {
  [srcaddr,dstaddr,nexthop,input,output,dPkts,dOctets,first,last,srcport,dstport,tcp_flags,prot,tos,src_as,dst_as,src_mask,dst_mask,flags,router_sc] = array_sscanf(rbuff, "%4c%4c%4c%2c%2c%4c%4c%4c%4c%2c%2c%*c%c%c%c%2c%2c%c%c%2c%4c");
  return this_object();
}

// Setters are fast, but locking.

int `srcaddr=(int x) {
  LOCK;
  return _srcaddr = x;
}

int `dstaddr=(int x) {
  LOCK;
  return _dstaddr = x;
}

int `nexthop=(int x) {
  LOCK;
  return _nexthop = x;
}

int `input=(int x) {
  LOCK;
  return _input = x;
}

int `output=(int x) {
  LOCK;
  return _output = x;
}

int `dPkts=(int x) {
  LOCK;
  return _dPkts = x;
}

int `dOctets=(int x) {
  LOCK;
  return _dOctets = x;
}

int `first=(int x) {
  LOCK;
  return _first = x;
}

int `last=(int x) {
  LOCK;
  return _last = x;
}

int `srcport=(int x) {
  LOCK;
  return _srcport = x;
}

int `dstport=(int x) {
  LOCK;
  return _dstport = x;
}

int `tcp_flags=(int x) {
  LOCK;
  return _tcp_flags = x;
}

int `prot=(int x) {
  LOCK;
  return _prot = x;
}

int `tos=(int x) {
  LOCK;
  return _tos = x;
}

int `src_as=(int x) {
  LOCK;
  return _src_as = x;
}

int `dst_as=(int x) {
  LOCK;
  return _dst_as;
}

int `src_mask=(int x) {
  LOCK;
  return _src_mask = x;
}

int `dst_mask=(int x) {
  LOCK;
  return _dst_mask = x;
}

int `flags=(int x) {
  LOCK;
  return _flags = x;
}

int `router_sc=(int x) {
  LOCK;
  return _router_sc = x;
}

// Getters do output transformation.

void|object `srcaddr() {
  return IP.v4.Address(_srcaddr);
}

void|object `dstaddr() {
  return IP.v4.Address(_dstaddr);
}

void|object `nexthop() {
  return IP.v4.Address(_nexthop);
}

int `input() {
  return _input;
}

int `output() {
  return _output;
}

int `dPkts() {
  return _dPkts;
}

int `dOctets() {
  return _dOctets;
}

void|object `first() {
  return Calendar.Second("unix", _first);
}

void|object `last() {
  return Calendar.Second("unix", _last);
}

int `srcport() {
  return _srcport;
}

int `dstport() {
  return _dstport;
}

int `tcp_flags() {
  return _tcp_flags;
}

void|object `prot() {
  return IP.Protocol.Protocol(_prot);
}

int `tos() {
  return _tos;
}

int `src_as() {
  return _src_as;
}

int `dst_as() {
  return _dst_as;
}

int `src_mask() {
  return _src_mask;
}

int `dst_mask() {
  return _dst_mask;
}

int `flags() {
  return _flags;
}

void|object `router_sc() {
  return IP.v4.Address(_router_sc);
}
