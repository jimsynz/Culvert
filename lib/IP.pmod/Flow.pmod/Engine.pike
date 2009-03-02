

static mapping flows;
static int max;
static int drop;
static int exp_count;
static function _flow_new_cb, _flow_exp_cb, _flow_log_cb, _flow_state_cb;
static int total_bytes;
static int total_packets;
static int total_flows;

void create(void|int _max) {
  flows = ([]);
  max = _max;
  write("Starting FlowEngine.\n");
}

void packet(object ip) {
  total_packets++;
  total_bytes += ip->len;
  string proto;
  if (ip->protocol)
    proto = ip->protocol->name();
  else if (ip->next_header)
    proto = ip->next_header->name();
  switch (proto) {
    case "TCP":
      tcp(ip);
      break;
    case "UDP":
      udp(ip);
      break;
    case "ICMP":
      icmp(ip);
      break;
    case "ICMPv6":
      icmp6(ip);
      break;
  }
}

void set_new_flow_cb(function cb) {
  _flow_new_cb = cb;
}

void set_expired_flow_cb(function cb) {
  _flow_exp_cb = cb;
}

void set_log_flow_cb(function cb) {
  _flow_log_cb = cb;
}

void set_flow_statechange_cb(function cb) {
  _flow_state_cb = cb;
}

static void tcp(object ip) {
  object tcp = IP.Protocol.TCP.Packet(ip->data);
  string _hash = hash(ip, tcp);
  if (flows[_hash])
    flows[_hash]->next(ip, tcp);
  else {
    object flow = IP.Protocol.TCP.Flow(ip, tcp);
    add_flow(_hash, flow);
    flow->hash(_hash);
    flow->expire_cb(exp_cb);
    flow->state_cb(state_cb);
    flow->log_cb(log_cb);
  }
}

static void udp(object ip) {
  object udp = IP.Protocol.UDP.Packet(ip->data);
  string _hash = hash(ip, udp);
  if (flows[_hash])
    flows[_hash]->next(ip, udp);
  else {
    object flow = IP.Protocol.UDP.Flow(ip, udp);
    add_flow(_hash, flow);
    flow->hash(_hash);
    flow->expire_cb(exp_cb);
    flow->state_cb(state_cb);
    flow->log_cb(log_cb);
  }
}

static void icmp(object ip) {}

static void icmp6(object ip) {}

void add_flow(string hash, object flow) {
  if (max) {
    if (sizeof(flows) < max) {
      flows[hash] = flow;
      new_cb(hash);
      total_flows++;
    }
    else 
      drop++;
  }
  else {
    flows[hash] = flow;
    new_cb(hash);
    total_flows++;
  }
}

static void new_cb(mixed hash) {
  if (_flow_new_cb)
    _flow_new_cb(flows[hash]);
}

static void exp_cb(mixed hash) {
  if (flows[hash]) {
    if (_flow_exp_cb)
      _flow_exp_cb(flows[hash]);
    exp_count++;
    write("removing flow %O\n", flows[hash]->english());
    destruct(flows[hash]);
    m_delete(flows, hash);
  }
  if (exp_count > sizeof(flows) / 20) {
    // If we've expired > 5% of flows then manually run the GC
    call_out(gc, 0);
    exp_count = 0;
  }
}

static void log_cb(mixed hash) {
  if (_flow_log_cb)
    _flow_log_cb(flows[hash]);
}

static void state_cb(mixed hash) {
  if (_flow_state_cb)
    _flow_state_cb(flows[hash]);
}


mapping status() {
  array f = values(flows);
  sort(f->bytes, f);
  reverse(f);
  if (sizeof(flows))
    return ([
	"flowcount" : total_flows,
	"bytes" : replace(String.int2size(total_bytes), "b", "B"),
	"packets" : total_packets,
	"dropped" : drop,
	"flows" : f,
	]);
  else
    return ([]);
}

string hash(object ip, object p) {
  string a, b, c, d, f;
  if (ip->next_header) {
    // v6
    if (ip->src < ip->dst) {
      a = sprintf("[%s]", (string)ip->src);
      b = sprintf("[%s]", (string)ip->dst);
      if (p->src_port) {
	c = (string)p->src_port;
	d = (string)p->dst_port;
      }
      else if (p->code) {
	c = (string)p->code;
	d = (string)p->code;
      }
    }
    else {
      b = sprintf("[%s]", (string)ip->src);
      a = sprintf("[%s]", (string)ip->dst);
      if (p->src_port) {
	d = (string)p->src_port;
	c = (string)p->dst_port;
      }
      else if (p->code) {
	d = (string)p->code;
	c = (string)p->code;
      }
    }
  }
  else {
    if (ip->src < ip->dst) {
      a = (string)ip->src;
      b = (string)ip->dst;
      if (p->src_port) {
	c = (string)p->src_port;
	d = (string)p->dst_port;
      }
      else if (p->code) {
	c = (string)p->code;
	d = (string)p->code;
      }
    }
    else {
      b = (string)ip->src;
      a = (string)ip->dst;
      if (p->src_port) {
	d = (string)p->src_port;
	c = (string)p->dst_port;
      }
      else if (p->code) {
	d = (string)p->code;
	c = (string)p->code;
      }
    }
  }
  if (ip->protocol)
    f = ip->protocol->name();
  else if (ip->next_header)
    f = ip->next_header->name();
  else
    f = "UNKNOWN";
  return sprintf("%s %s:%s %s:%s", f, a, c, b, d);
}
