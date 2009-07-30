static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static int _src_port;
static int _dst_port;
static int _len;
static int _chksum;
static string _data;

void create(string payload) {
  [src_port,dst_port,len,chksum,data] = array_sscanf(payload,"%2c%2c%2c%2c%s");
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

int `len() {
  return _len;
}

int `len=(int x) {
  LOCK;
  return _len = x;
}

int `chksum() {
  return _chksum;
}

int `chksum=(int x) {
  LOCK;
  return _chksum = x;
}

string `data() {
  return _data;
}

string `data=(string x) {
  LOCK;
  return _data = x;
}
