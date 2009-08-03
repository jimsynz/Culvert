int len;
int dst;
int src;
Ethernet.FrameType type;
string data;

void create(void|string payload) {
  if (stringp(payload)) {
    parse(payload);
  }
}

void parse(string payload) {
  len = sizeof(payload);
  string _src = payload[0..5];
  string _dst = payload[6..11];
  string _type = payload[12..13];
  data = payload[14..];
  [src] = array_sscanf(_src, "%6c");
  [dst] = array_sscanf(_dst, "%6c");
  int __type;
  [__type] = array_sscanf(_type, "%2c");
  type = Ethernet.FrameType(__type);
}

string src_mac() {
  if (src) {
    return (sprintf("%0:12x", src) / 2) * ":";
  }
}

string dst_mac() {
  if (dst) {
    return (sprintf("%0:12x", dst) / 2) * ":";
  }
}


static string _sprintf() {
  return sprintf("Ethernet.Frame(/* %s -> %s */)", src_mac(), dst_mac());
}
