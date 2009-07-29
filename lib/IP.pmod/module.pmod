//! Dynamically detect IPv6 or IPv4 addresses.
.v4.Address|.v6.Address address(int|string addr) {
  if (intp(addr)) {
    if (addr > (1<<32)-1)
      return .v6.Address(addr);
    else
      return .v4.Address(addr);
  }
  else if (stringp(addr)) {
    if (sscanf(addr, "%*d.%*d.%*d.%*d")==4)
      return .v4.Address(addr);
    if (Regexp("([0-9,a-f,A-F]*:)+")->match(addr))
      return .v6.Address(addr);
    
    else 
      // do dns.
      if (!catch(object ip = .v6.Address(addr, 1)))
	return ip;
      else if (!catch(object ip = .v4.Address(addr, 1)))
	return ip;
  }
  throw(Error.Generic("Unable to parse IP address.\n"));
}

//! Dynamically detects IPv6 or IPv4 prefixes.
.v4.Prefix|.v6.Prefix prefix(string prefix) {
  string addr_part;
  int prefix_length;
  [addr_part, prefix_length] = array_sscanf(prefix, "%s/%d");
  if (!catch(.v6.Address(addr_part))) {
    // we think it's a v6 address.
    if ((prefix_length < 0) || (prefix_length > 128))
      throw(Error.Generic(sprintf("Prefix length %O not valid for IPv6 networks.\n", prefix_length)));
    return IP.v6.Prefix(prefix);
  }
  if (!catch(.v4.Address(addr_part))) {
    if ((prefix_length < 0) || (prefix_length > 32))
      throw(Error.Generic(sprintf("Prefix length %O not valid for IPv4 networks.\n", prefix_length)));
    return IP.v4.Prefix(prefix);
  }
  throw(Error.Generic("Unable to parse IP prefix.\n"));
}
