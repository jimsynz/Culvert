inherit IP.Flow.Flow;

static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static int _src_port;
static int _dst_port;

constant SYN_SENT = 10;
constant SYN_RECV = 11;
constant CLOSE_WAIT = 12;

void create(object ip, object tcp, mixed ... args) {
  src_port = tcp->src_port;
  dst_port = tcp->dst_port;
  ::create(ip, tcp, @args);
}

void tcp_state(object tcp) {
  if (tcp->flags["SYN"] &
      !tcp->flags["ACK"])
    set_state(SYN_SENT);
  else if (tcp->flags["SYN"] &&
      tcp->flags["ACK"])
    set_state(SYN_RECV);
  else if (tcp->flags["RST"] &&
      !tcp->flags["ACK"])
    set_state(CLOSE_WAIT);
  else if (tcp->flags["RST"] &&
      tcp->flags["ACK"]) {
    set_state(CLOSE);
    if (timeout_co) {
#ifdef ENABLE_THREADS
      timeout_co->kill();
      timeout_co = 0;
#else
      remove_call_out(timeout_co);
#endif
    }
    if (log_co) {
#ifdef ENABLE_THREADS
      log_co->kill();
      log_co = 0;
#else
      remove_call_out(log_co);
#endif
    }
    if (_exp_cb)
      _exp_cb(_hash);
  }
  else if (tcp->flags["ACK"] &&
      !tcp->flags["SYN"])
    set_state(ESTABLISHED);
  else
    set_state(UNKNOWN);
}

void next(object ip, object tcp) {
  //if (state == CLOSE)
    //return;
  if (((src == ip->src) && dst == ip->dst) ||
      ((dst == ip->dst) && src == ip->dst)) {
    set_timeout();
    payload += tcp->data;
    // If the source and destination don't match our 
    // flow then just leave.
    bytes += ip->len;
    packets++;
    if (!state) {
      // We're the first packet!
      src_port = tcp->src_port;
      dst_port = tcp->dst_port;
      conversation = ({ ([ "time" : now(), "direction" : "out", "packet" : tcp ]) });
      tcp_state(tcp);
    }
    else if (state) {
      if ((src == tcp->src) &&
	  (dst == tcp->dst)) {
	conversation += ({ ([ "time" : now(), "direction" : "out", "packet" : tcp ]) });
      }
      else {
	conversation += ({ ([ "time" : now(), "direction" : "in", "packet" : tcp ]) });
      }

      tcp_state(tcp);
    }
  }
}

int `src_port() {
  return _src_port;
}

int `src_port=(int x) {
  LOCK;
  return _src_port = x;
}

int `dst_port() {
  return _dst_port;
}

int `dst_port=(int x) {
  LOCK;
  return _dst_port = x;
}
