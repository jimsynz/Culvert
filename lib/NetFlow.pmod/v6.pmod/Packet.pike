inherit NetFlow.BasePacket;

#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

static int _unix_nsecs;
static int _flow_sequence;
static int _engine_type;
static int _engine_id;
static int _sampling_interval;

object decode_packet(string pbuff) {
  ::decode_packet(pbuff);
  [unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval] = array_sscanf(pbuff[12..], "%4c%4c%c%c%2c");
  string payload = pbuff[24..];
  for (int i = 0; i < count; i++) {
    records += ({ .Record()->decode_record(pbuff[(i * .Record.size)..((i * .Record.size) + .Record.size)]) });
  }
  return this_object();
}

int `unix_nsecs() {
  return _unix_nsecs;
}

int `unix_nsecs=(int x) {
  LOCK;
  return _unix_nsecs = x;
}

int `flow_sequence() {
  return _flow_sequence;
}

int `flow_sequence=(int s) {
  LOCK;
  return _flow_sequence = s;
}

int `engine_type() {
  return _engine_type;
}

int `engine_type=(int t) {
  LOCK;
  return _engine_type = t;
}

int `engine_id() {
  return _engine_id;
}

int `engine_id=(int i) {
  LOCK;
  return _engine_id = i;
}

int `sampling_interval() {
  return _sampling_interval;
}

int `sampling_interval=(int s) {
  LOCK;
  return _sampling_interval = s;
}
