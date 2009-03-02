/*
   Don't use this module directly, inherit it from your protocol flow
   handler.

   */


object src;
object dst;
int bytes;
int packets;
array conversation;
int state;
string payload;
object protocol;
int start_time;
float time_offset;

static function _log_cb;
static function _exp_cb;
static function _state_cb;
static mixed _hash;
static mixed timeout_co;
static mixed log_co;

#define EXP_TIMEOUT 120
#define LOG_TICK 30

constant ONEWAY = 1;
constant ESTABLISHED = 2;
constant CLOSING = 3;
constant CLOSE = 4;
constant UNKNOWN = 5;

void create(object ip, object layer3) {
  src = ip->src;
  dst = ip->dst;
  protocol = ip->protocol||ip->next_header;
  conversation = ({});
  payload = "";
  start_time = time();
  time_offset = time(start_time);
  next(ip, layer3);
}

float now() {
  return time(start_time) - time_offset;
}

mixed hash(void|mixed __hash) {
  if (__hash)
    _hash = __hash;
  return _hash;
}

void log_cb(function cb) {
  if (functionp(cb))
    _log_cb = cb;
    if (_hash)
      log_co = call_out(do_log, LOG_TICK);
  else {
    remove_call_out(log_co);
    log_co = 0;
  }
}

void expire_cb(function cb) {
  if (functionp(cb))
    _exp_cb = cb;
}

void state_cb(function cb) {
  if (functionp(cb))
    _state_cb = cb;
}

static void do_log() {
  _log_cb(_hash);
  log_co = call_out(do_log, LOG_TICK);
}

void set_timeout() {
  if (timeout_co) {
    remove_call_out(timeout_co);
  }
  timeout_co = call_out(timeout, EXP_TIMEOUT);
}

void timeout() {
  if (state == CLOSING) {
    set_state(CLOSE);
    _exp_cb(_hash);
  }
  else {
    set_state(CLOSING);
    set_timeout();
  }
}

void set_state(int _state) {
  if (state != _state) {
    state = _state;
    if (functionp(_state_cb))
      _state_cb(_hash);
    else
      call_out(_state_cb, 0, _hash);
  }
}

void next(object ip, object udp) {};

string english(void|int dns, void|int scope) {
  string state;
  string dir = "<->";
  switch (this->state) {
    case 1:
      state = "ONEWAY";
      dir = "-->";
      break;
    case 2:
      state = "ESTABLISHED";
      break;
    case 3:
      state = "CLOSING";
      dir = "!!!";
      break;
    case 4: 
      state = "CLOSED";
      dir = "!!!";
      break;
    case 5:
      state = "UNKNOWN";
      dir = "---";
      break;
    case 10:
      state = "SYN_SENT";
      dir = "-->";
      break;
    case 11:
      state = "SYN_RECV";
      dir = "< >";
      break;
    case 12:
      state = "CLOSE_WAIT";
      dir = "<!>";
      break;
  }
  string _src, _dst;
  if (dns) {
    if (src->hostname)
      _src = src->hostname();
    if (dst->hostname)
      _dst = dst->hostname();
  }
  if (!_src)
    if (sizeof((string)src / ":") > 1)
      _src = sprintf("[%s]", (string)src);
    else
      _src = (string)src;
  if (!_dst)
    if (sizeof((string)dst / ":") > 1)
      _dst = sprintf("[%s]", (string)dst);
    else
      _dst = (string)dst;

  if (this->src_port)
    _src = sprintf("%s:%d", _src, this->src_port);
  if (this->dst_port)
    _dst = sprintf("%s:%d", _dst, this->dst_port);
  string _src_scope, _dst_scope = "";
  if (scope) {
    if (functionp(src->scope))
      _src_scope = sprintf(" %s", src->scope());
    if (functionp(dst->scope))
      _dst_scope = sprintf(" %s", dst->scope());
  }


  string first = (Calendar.Second(start_time)->format_time() / " ")[1];
  float _last = conversation[-1]->time;
  string last = _last>0?sprintf("%:2fs", _last):"-.--s";
  string brate = replace(String.int2size((int)(bytes * 8/ _last)) + "ps", "bytes", "b");
  string prate = replace(String.int2size((int)(packets / _last)) + "ps", ({ "bytes", "b" }), ({ "p", "p" }));

  return sprintf("%s %6s %s %s%s %s %s%s (%s %s, %d packets %s) %s", first, last, protocol->name(), _src, _src_scope, (string)dir, _dst, _dst_scope, replace(String.int2size(bytes), "b", "B"), brate, packets, prate, state);
}

//string _sprintf() {
  //return sprintf("Protocol.IP.Protocol.%s.Flow(/* %s */)", protocol->name(), english());
//}
