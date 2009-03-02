inherit IP.Flow.Flow;

int src_port;
int dst_port;

void create(object ip, object udp) {
  src_port = udp->src_port;
  dst_port = udp->dst_port;
  ::create(ip, udp);
}

void next(object ip, object udp) {
  if (state == CLOSE)
    return;
  if (((src == ip->src) && dst == ip->dst) ||
      ((dst == ip->dst) && src == ip->dst)) {
    set_timeout();
    payload += udp->data;
    // If the source and destination don't match our 
    // flow then just leave.
    bytes += ip->len;
    packets++;
    if (!state) {
      // We're the first packet!
      src_port = udp->src_port;
      dst_port = udp->dst_port;
      set_state(ONEWAY);
      conversation += ({ ([ "time" : now(), "direction" : "out", "packet" : udp ]) });
    }
    else if (state) {
      if ((src_port = udp->src_port) &&
	  (dst_port = udp->dst_port)) {
	// We're unidirectional, so far at least.
	if (state != ESTABLISHED)
	  set_state(ONEWAY);
	conversation += ({ ([ "time" : now(), "direction" : "out", "packet" : udp ]) });
      }
      else {
	set_state(ESTABLISHED);
	conversation += ({ ([ "time" : now(), "direction" : "in", "packet" : udp ]) });
      }
    }
  }
}

