#!/usr/bin/pike7.6 -Mlib/

#define IF "eth0"
#define MTU 68

object fe;
array threads;
object cap;
object queue;

int main() {
  threads = ({});
  threads += ({ Thread.thread_create(counterloop) });
  queue = ADT.Queue();

  fe = IP.Flow.Engine();

  cap = Public.Network.Pcap.Pcap();
  cap->set_capture_length(MTU);
  cap->set_promisc(1);
  cap->open_live(IF);
  threads += ({ Thread.thread_create(caploop) });
  //for (int i; i<10; i++)
    //threads += ({ Thread.thread_create(queueloop) });

  return -1;
}

void caploop() {
  while(1) {
    capture_cb(cap->next());
    //mixed c = cap->next();
    //if (c)
      //queue->write(c);
  }
}

void counterloop() {
  while(1) {
    sleep(2);
    write_counters();
  }
}

void queueloop() {
  while(1) {
    mixed c = queue->read();
    if (c)
      capture_cb(c);
  }
}

void write_counters(void|int sleep) {
  //write("%O\n", fe->status());
  array flows = fe->status()->flows;
  array bytes = copy_value(flows->bytes);
  sort(bytes, flows);
  flows = reverse(flows);
  write("Total Flows: %d\tTotal Bytes: %s\tTotal Packets: %d\n", fe->status()->flowcount, fe->status()->bytes, fe->status()->packets);
  int z = 10;
  if (sizeof(flows) < 10)
    z = sizeof(flows);
  write("Top %d flows:\n", z);
  for (int i; i < z; i++) {
    object f = flows[i];
    if (f)
      write("%s\n", f->english(1,1));
  }
  write("\n");
  if (sleep)
    call_out(write_counters, sleep);
}

void capture_cb(mixed ... args) {
  object frame = Ethernet.Packet(args[0]->data);
  if (frame->type->name() == "IPv4") {
    object packet;
    mixed err = catch(packet = IP.v4.Packet(frame->data, 1));
    if (err)
      write("%O\n", err);
    else {
      if (packet->protocol->name() == "IPv6") {
	object sixtofour;
	mixed err = catch(sixtofour = IP.v6.Packet(packet->data, 1));
	if (err)
	  write("%O\n", err);
	fe->packet(sixtofour);
      }
      else 
	fe->packet(packet);
    }
  }
  else if (frame->type->name() == "IPv6") {
    object packet;
    mixed err = catch(packet = IP.v6.Packet(frame->data, 1));
    if (err)
      write("%O\n", err);
    else
      fe->packet(packet);
  }
}

