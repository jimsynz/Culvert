
IP.Protocol.ICMPv6.Type type;
int code;
int chksum;
int error;
string data;

void create(string packet) {
  type = IP.Protocol.ICMPv6.Type(packet[0]);
  if (type->numeric() <= 127) 
    error = 1;
  code = packet[1];
  [chksum] = array_sscanf(packet[2..3], "%2c");
  if (sizeof(packet) > 4)
    data = packet[5..];
}
