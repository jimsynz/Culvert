static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static IP.Protocol.ICMP.Type _type;
static int _code;
static int _chksum;
static int _error;
static string _data;

void create(string packet) {
  type = IP.Protocol.ICMP.Type(packet[0]);
  if (type->numeric() <= 127) 
    error = 1;
  code = packet[1];
  [chksum] = array_sscanf(packet[2..3], "%2c");
  if (sizeof(packet) > 4)
    data = packet[5..];
}

IP.Protocol.ICMP.Type `type() {
  return _type;
}

IP.Protocol.ICMP.Type `type=(IP.Protocol.ICMP.Type x) {
  LOCK;
  return _type = x;
}

int `code() {
  return _code;
}

int `code=(int x) {
  LOCK;
  return _code = x;
}

int `chksum() {
  return _chksum;
}

int `chksum=(int x) {
  LOCK;
  return _chksum = x;
}

int `error() {
  return _error;
}

int `error=(int x) {
  LOCK;
  return _error = x;
}

string `data() {
  return _data;
}

string `data=(string x) {
  LOCK;
  return _data = x;
}
