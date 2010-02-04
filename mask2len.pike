#!/usr/local/bin/pike -Mlib/

void main(int argc, array argv) {
  object prefix = IP.v4.Prefix(sprintf("%s/%s", argv[1], argv[2]));
  write("%s %d\n", (string)prefix->network(), prefix->length());
}
