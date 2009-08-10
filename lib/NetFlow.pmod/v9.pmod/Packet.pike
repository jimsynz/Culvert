inherit NetFlow.BasePacket;

#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

static int _package_sequence;
static int _source_id;

object decode_packet(string pbuff) {
  ::decode_packet(pbuff);
  [package_sequence, source_id] = array_sscanf(pbuff[12..], "%4c%4c");
  string payload = pbuff[20..];
  for (int i = 0; i < count; i++) {
    records += ({ .Record()->decode_record(pbuff[(i * .Record.size)..((i * .Record.size) + .Record.size)]) });
  }
  return this_object();
}

int `package_sequence() {
  return _package_sequence;
}

int `package_sequence=(int x) {
  LOCK;
  return _package_sequence = x;
}

int `source_id() {
  return _source_id;
}

int `source_id=(int s) {
  LOCK;
  return _source_id = s;
}
