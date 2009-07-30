static array _store = ({});
static object _mutex = Thread.Mutex();
#define LOCK object __key = _mutex->lock(1)
#define UNLOCK destruct(__key)

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
