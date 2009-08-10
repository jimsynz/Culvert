inherit NetFlow.BasePacket;

#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

static int _unix_nsecs;

object decode_packet(string pbuff) {
  ::decode_packet(pbuff);
  [unix_nsecs] = array_sscanf(pbuff[12..16], "%4c");
  pbuff = pbuff[16..];
  for (int i = 0; i < count; i++) {
    records += ({ .Record()->decode_record(pbuff[(i * .Record.size)..((i * .Record.size) + .Record.size)]) });
  }
  return this_object();
}

int `unix_nsecs() {
  return _unix_nsecs;
}

int `unix_nsecs=(int s) {
  LOCK;
  return _unix_nsecs = s;
}

