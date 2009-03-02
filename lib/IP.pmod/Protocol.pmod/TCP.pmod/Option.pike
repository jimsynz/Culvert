static mapping options = ([
      0 : "END",
      1 : "MOOP",
      2 : "MSS",
      3 : "WSOPT",
      4 : "SACKP",
      5 : "SACK",
      6 : "ECHOREQ",
      7 : "ECHQREP",
      8 : "TSOPT",
      9 : "POCP",
      10 : "POSP",
      11 : "CC",
      12 : "CC.NEW",
      13 : "CC.ECHO",
      14 : "ALTCHKSUMREQ",
      15 : "ALTCHKSUM",
      16 : "SKEETER",
      17 : "BUBBA",
      18 : "TRAILERCHKSUM",
      19 : "MD5",
      20 : "SCPSCAP",
      21 : "SNACK",
      22 : "RECBOUND",
      23 : "CORRUPT",
      24 : "SNAP",
      26 : "COMPFILT",
      27 : "QUICKSTARTRESP",
      253 : "RFC3692EXP1",
      254 : "RFC3692EXP2",
    ]);

static multiset lengths = (< 2, 3, 4, 6, 7, 8, 9, 10, 14, 18, 19, 27 >);

int option;
int value;
int len;

void create(string opt) {
  option = opt[0];
  if (lengths[option]) {
    len = opt[1];
    sscanf(opt, sprintf("%%%dc", len-2), value);
  }
}

void|string name() {
  return options[option];
}
