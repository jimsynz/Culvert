
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

// Require's Pike 7.8

static object _mutex = Thread.Mutex();

static int _version;
static int _count;
static int _sys_uptime;
static int _unix_secs;
static array _records;

object decode_packet(string pbuff) {
  [version, count, sys_uptime, unix_secs] = array_sscanf(pbuff, "%2c%2c%4c%4c");
  records = ({});
  return this_object();
}

int `version() {
  return _version;
}

int `version=(int v) {
  LOCK;
  return _version = v;
}

int `count() {
  return _count;
}

int `count=(int c) {
  LOCK;
  return _count = c;
}

int `sys_uptime() {
  return _sys_uptime;
}

int `sys_uptime=(int s) {
  LOCK;
  return _sys_uptime = s;
}

int `unix_secs() {
  return _unix_secs;
}

int `unix_secs=(int s) {
  LOCK;
  return _unix_secs = s;
}

array `records() {
  return _records;
}

array `records=(array a) {
  LOCK;
  return _records = a;
}
