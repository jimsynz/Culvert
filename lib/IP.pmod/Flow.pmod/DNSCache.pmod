
#define TTL 300
#define EXPIRE 30

static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static mapping _dns_cache = ([]);
static mapping _host_cache = ([]);
static int __start;

static void|string lookup(string ip, string using, void|function cb) {
  if (!_start)
    start();
  if (dns_cache[ip] && dns_cache[ip]->t > time() - TTL) 
    if (functionp(cb))
      cb(dns_cache[ip]->h);
    else
      return dns_cache[ip]->h;
  else if (functionp(cb))
    if (using == "host")
      Protocols.DNS.async_host_to_ip(ip, lambda(string ip, string host) { dns_cache[ip] = ([ "t" : time(), "h" : host ]); cb(host); });
    else 
      Protocols.DNS.async_ip_to_host(ip, lambda(string ip, string host) { dns_cache[ip] = ([ "t" : time(), "h" : host ]); cb(host); });
  else {
    string host;
    array tmp;
    if (using == "host")
      tmp = Protocols.DNS.gethostbyaddr(ip);
    else
      tmp = Protocols.DNS.gethostbyname(ip);
    host = tmp[0];
    dns_cache[ip] = ([ "t" : time(), "h" : host ]);
    return host;
  }
}

void|string lookup_ip(string ip, void|function cb) {
  lookup(ip, "ip", cb);
}

void|string lookup_host(string host, void|function cb) {
  lookup(host, "host", cb);
}

static void start() {
  _start++;
  //write("started....\n");
  call_out(expire, EXPIRE);
}

static void expire() {
  //write("DNS cache size: %d\n", sizeof(dns_cache));
  int old = time() - TTL;
  foreach(indices(dns_cache), string ip) {
    if (dns_cache[ip]->t < old) {
      //write("removing %O\n", dns_cache[ip]);
      m_delete(dns_cache, ip);
    }
  }
  call_out(expire, EXPIRE);
}

mapping `dns_cache() {
  return _dns_cache;
}

mapping `dns_cache=(mapping x) {
  LOCK;
  return _dns_cache = x;
}

int `_start() {
  return __start;
}

int `_start=(int x) {
  LOCK;
  return __start = x;
}
