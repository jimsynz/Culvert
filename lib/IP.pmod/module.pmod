void|.v4.Address|.v6.Address address(int|string addr) {
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
}
