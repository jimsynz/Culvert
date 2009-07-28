
#define TTL 300
#define EXPIRE 30

static mapping dns_cache = ([]);
static int _start;

void|string lookup_ip(string ip, void|function cb) {
  if (!_start)
    start();
  if (dns_cache[ip] && dns_cache[ip]->t > time() - TTL) 
    if (functionp(cb))
      cb(dns_cache[ip]->h);
    else
      return dns_cache[ip]->h;
  else if (functionp(cb))
    Protocols.DNS.async_ip_to_host(ip, lambda(string ip, string host) { dns_cache[ip] = ([ "t" : time(), "h" : host ]); cb(host); });
  else {
    string host;
    array tmp = Protocols.DNS.gethostbyaddr(ip);
    host = tmp[0];
    dns_cache[ip] = ([ "t" : time(), "h" : host ]);
    return host;
  }
}

static void start() {
  _start++;
  //write("started....\n");
  call_out(expire, EXPIRE);
}

static void expire() {
  write("DNS cache size: %d\n", sizeof(dns_cache));
  int old = time() - TTL;
  foreach(indices(dns_cache), string ip) {
    if (dns_cache[ip]->t < old) {
      //write("removing %O\n", dns_cache[ip]);
      m_delete(dns_cache, ip);
    }
  }
  call_out(expire, EXPIRE);
}
