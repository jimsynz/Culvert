/*
   Don't use this module directly, inherit it from your protocol flow
   handler.

   */


static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)
static object _src;
static object _dst;
static int _bytes;
static int _packets;
static object _conversation;
static int _state;
static string _payload;
static object _protocol;
static int _start_time;
static float _time_offset;

static function __log_cb;
static function __exp_cb;
static function __state_cb;
static mixed __hash;
static mixed _timeout_co;
static mixed _log_co;

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
  conversation = Locking.Array();
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
    default:
      dir = "<->";
      state = "ESTABLISHED";
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

  return sprintf("%s %6s %s %s%s %s %s%s (%s %s, %d packets %s) %s", first, last, protocol->name(), _src, _src_scope, dir||"", _dst, _dst_scope, replace(String.int2size(bytes), "b", "B"), brate, packets, prate, state);
}

//string _sprintf() {
  //return sprintf("Protocol.IP.Protocol.%s.Flow(/* %s */)", protocol->name(), english());
//}

object `src() {
  return _src;
}

object `src=(object x) {
  return _src = x;
}

object `dst() {
  return _dst;
}

object `dst=(object x) {
  return _dst = x;
}

int `bytes() {
  return _bytes;
}

int `bytes=(int x) {
  LOCK;
  return _bytes = x;
}

int `packets() {
  return _packets;
}

int `packets=(int x) {
  LOCK;
  return _packets = x;
}

object `conversation() {
  return _conversation;
}

object `conversation=(object x) {
  LOCK;
  return _conversation = x;
}

int `state() {
  return _state;
}

int `state=(int x) {
  LOCK;
  return _state = x;
}

string `payload() {
  return _payload;
}

string `payload=(string x) {
  LOCK;
  return _payload = x;
}

object `protocol() {
  return _protocol;
}

object `protocol=(object x) {
  LOCK;
  return _protocol = x;
}

int `start_time() {
  return _start_time;
}

int `start_time=(int x) {
  LOCK;
  return _start_time = x;
}

float `time_offset() {
  return _time_offset;
}

float `time_offset=(float x) {
  LOCK;
  return _time_offset = x;
}

static function `_log_cb() {
  return __log_cb;
}

static function `_log_cb=(function x) {
  LOCK;
  return __log_cb = x;
}

static function `_exp_cb() {
  return __exp_cb;
}

static function `_exp_cb=(function x) {
  LOCK;
  return __exp_cb = x;
}

static function `_state_cb() {
  return __state_cb;
}

static function `_state_cb=(function x) {
  LOCK;
  return __state_cb = x;
}

static mixed `_hash() {
  return __hash;
}

static mixed `_hash=(mixed x) {
  LOCK;
  return __hash = x;
}

static mixed `timeout_co() {
  return _timeout_co;
}

static mixed `timeout_co=(mixed x) {
  LOCK;
  return _timeout_co = x;
}

static mixed `log_co() {
  return _log_co;
}

static mixed `log_co=(mixed x) {
  LOCK;
  return _log_co = x;
}

class LockingArray {

  static array _store = ({});
  static object _mutex = Thread.Mutex();

  mixed `!(mixed ... args) {
    LOCK;
    return _store->`!(args);
  }
  mixed `!=(mixed ... args) {
    LOCK;
    return _store->`!=(@args);
  }
  mixed `%(mixed ... args) {
    LOCK;
    return _store->`%(@args);
  }
  mixed `&(mixed ...args) {
    LOCK;
    return _store->`&(@args);
  }
  mixed `()(mixed ... args) {
    LOCK;
    return _store->`()(@args);
  }
  mixed call_function(mixed ... args) {
    LOCK;
    return _store->call_function(@args);
  }
  mixed `*(mixed ... args) {
    LOCK;
    return _store->`*(@args);
  }
  mixed `+(mixed ... args) {
    LOCK;
    return _store->`+(@args);
  }
  mixed `-(mixed ... args) {
    LOCK;
    return _store->`-(@args);
  }
  mixed `->(mixed ... args) {
    LOCK;
    return _store->`->(@args);
  }
  mixed `->=(mixed ... args) {
    LOCK;
    return _store->`->=(@args);
  }
  mixed `/(mixed ... args) {
    LOCK;
    return _store->`/(@args);
  }
  mixed `<(mixed ... args) {
    LOCK;
    return _store->`<(@args);
  }
  mixed `<<(mixed ... args) {
    LOCK;
    return _store->`<<(@args);
  }
  mixed `<=(mixed ... args) {
    LOCK;
    return _store->`<=(@args);
  }
  mixed `==(mixed ... args) {
    LOCK;
    return _store->`==(@args);
  }
  mixed `>(mixed ... args) {
    LOCK;
    return _store->`>(@args);
  }
  mixed `>=(mixed ... args) {
    LOCK;
    return _store->`>=(@args);
  }
  mixed `>>(mixed ... args) {
    LOCK;
    return _store->`>>(@args);
  }
  mixed `[..](mixed ... args) {
    LOCK;
    return _store->`[..](@args);
  }
  mixed `[](mixed ... args) {
    LOCK;
    return _store->`[](@args);
  }
  mixed `[]=(mixed ... args) {
    LOCK;
    return _store->`[]=(@args);
  }
  mixed `^(mixed ... args) {
    LOCK;
    return _store->`^(@args);
  }
  mixed `|(mixed ... args) {
    LOCK;
    return _store->`|(@args);
  }
  mixed `~(mixed ... args) {
    LOCK;
    return _store->`~(@args);
  }
  mixed _values(mixed ... args) {
    LOCK;
    return _store->_values(@args);
  }
  mixed _sizeof(mixed ... args) {
    LOCK;
    return _store->_sizeof(@args);
  }
  mixed _indices(mixed ... args) {
    LOCK;
    return _store->_indices(@args);
  }
  mixed __hash(mixed ... args) {
    LOCK;
    return _store->__hash(@args);
  }
  mixed `_equal(mixed ... args) {
    LOCK;
    return _store->_equal(@args);
  }
  mixed `_is_type(mixed ... args) {
    LOCK;
    return _store->`_is_type(@args);
  }
  mixed `_sprintf(mixed ... args) {
    LOCK;
    return _store->`_sprintf(@args);
  }
  mixed `_m_delete(mixed ... args) {
    LOCK;
    return _store->`_m_delete(@args);
  }
  mixed `_get_iterator(mixed ... args) {
    LOCK;
    return _store->`_get_iterator(@args);
  }
  mixed `_search(mixed ... args) {
    LOCK;
    return _store->`_search(@args);
  }

}
