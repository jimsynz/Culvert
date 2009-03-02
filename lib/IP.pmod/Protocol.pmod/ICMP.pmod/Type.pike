static int _type;
static mapping types = ([
    0 : "ECHOREP",
    3 : "DESTUNREACH",
    4 : "SOURCEQUENCH",
    5 : "REDIRECT",
    6 : "ALTHOST",
    8 : "ECHOREQ",
    9 : "RA",
    10 : "RS",
    11 : "TTLEX",
    12 : "PARAMPROB",
    13 : "TIMEREQ",
    14 : "TIMEREP",
    15 : "INFOREQ",
    16 : "INFOREP",
    17 : "ADDRMASKREQ",
    18 : "ADDRMASKREP",
    30 : "TRACERT",
    31 : "CONVERR",
    32 : "MOBHOSTREDIR",
    33 : "IPV6WHEREAREYOU",
    34 : "IPV6IAMHERE",
    35 : "MOBREGREQ",
    36 : "MOBREGREP",
    37 : "DOMAINREQ",
    38 : "DOMAINREP",
    39 : "SKIP",
    40 : "PHOTURIS",
    41 : "EXTMOB",
  ]);

void create(int|string type) {
  if (intp(type))
    _type = type;
  else if (stringp(type)) {
    mapping tmp = mkmapping(values(types), indices(types));
    if (tmp[type])
      _type = tmp[type];
  }
}

int numeric() {
  return _type;
}

string hex() {
  return sprintf("0x%0:4x", _type);
}

void|string name() {
  if (types[_type])
    return types[_type];
  else
    return "UNKNOWN";
}

string _sprintf() {
  return sprintf("IP.Protocol.ICMP.Type(%O)", name());
}
