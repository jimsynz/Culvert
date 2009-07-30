static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static int __type;
static mapping types = ([
    1 : "DESTUNREACH",
    2 : "TOOBIG",
    3 : "TTLEX",
    4 : "PARAMPROB",
    100 : "PRIVEXP",
    101 : "PRIVEXP",
    127 : "RESERVED",
    128 : "ECHOREQ",
    129 : "ECHOREP",
    200 : "PRIVEXP",
    201 : "PRIVEXP",
    255 : "RESERVED",
  ]);

void create(int|string type) {
  if (intp(type))
    _type = type;
  else if (stringp(type)) {
    mapping tmp = mkmapping(values(types), indices(types));
    if (tmp[type])
      _type = tmp[type];
  }
}

int numeric() {
  return _type;
}

string hex() {
  return sprintf("0x%0:4x", _type);
}

void|string name() {
  if (types[_type])
    return types[_type];
  else
    return "UNKNOWN";
}

string _sprintf() {
  return sprintf("IP.Protocol.ICMP.Type(%O)", name());
}

static int `_type() {
  return __type;
}

static int `_type=(int x) {
  LOCK;
  return __type = x;
}
