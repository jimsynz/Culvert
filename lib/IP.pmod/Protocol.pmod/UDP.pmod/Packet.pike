int src_port;
int dst_port;
int len;
int chksum;
string data;

void create(string payload) {
  [src_port,dst_port,len,chksum,data] = array_sscanf(payload,"%2c%2c%2c%2c%s");
}
