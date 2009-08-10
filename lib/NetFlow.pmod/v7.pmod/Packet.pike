inherit NetFlow.BasePacket;

#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

static int _unix_nsecs;
static int _flow_sequence;

object decode_packet(string pbuff) {
  ::decode_packet(pbuff);
  [unix_nsecs, flow_sequence] = array_sscanf(pbuff[12..], "%4c%4c%4*c");
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
