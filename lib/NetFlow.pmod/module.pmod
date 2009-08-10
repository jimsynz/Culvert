object packet(string pbuff) {
  int version;
  object decoder;
  [version] = array_sscanf(pbuff[0..1], "%c");
  switch (version) {
    case 1: 
      decoder = .v1.Packet();
      break;
    case 5:
      decoder = .v5.Packet();
      break;
    case 6:
      decoder = .v6.Packet();
      break;
    case 7:
      decoder = .v7.Packet();
      break;
    /*
    case 8:
      decoder = .v8.Packet();
      break;
    case 9:
      decoder = .v9.Packet();
      break;
    */
  }
  decoder->decode_packet(pbuff);
  return decoder;
}
