int src_port;
int dst_port;
int seq_no;
int ack_no;
int data_offset;
multiset flags;
int window;
int checksum;
int urgent_pointer;
array options;
string data;
static string _payload;

void create(string payload) {
  _payload = payload;
  flags = (<>);
  options = ({});
  int tmp;
  sscanf(payload[0..1], "%2c", src_port);
  sscanf(payload[2..3], "%2c", dst_port);
  sscanf(payload[4..7], "%4c", seq_no);
  sscanf(payload[8..11], "%4c", ack_no);
  sscanf(payload[12..13], "%2c", tmp);
  sscanf(payload[14..15], "%2c", window);
  sscanf(payload[16..17], "%2c", checksum);
  sscanf(payload[18..19], "%2c", urgent_pointer);
  data_offset = tmp >> 12;
  array _flags = (array(int))reverse(sprintf("%b", tmp) / "");
  if (_flags[0])
    flags += (< "FIN" >);
  if (_flags[1])
    flags += (< "SYN" >);
  if (_flags[2])
    flags += (< "RST" >);
  if (_flags[3])
    flags += (< "PSH" >);
  if (_flags[4])
    flags += (< "ACK" >);
  if (_flags[5])
    flags += (< "URG" >);
  string opts = payload[20..data_offset];
  int i;
  while (i < sizeof(opts)) {
    object o = .Option(opts[i..]);
    if (o->name() == "END")
      break;
    i += o->len;
  }
  if (sizeof(payload) > data_offset)
    data = payload[data_offset..];
}
