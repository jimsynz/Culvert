#!/usr/bin/pike7.6 -Mlib/

#define IF "en0"
#define MTU 68

object fe;
array threads;
object cap;
object queue;
object logfile;

int main() {
  //threads = ({});
  //threads += ({ Thread.thread_create(counterloop) });
  //queue = Thread.Queue();

  logfile = Stdio.File("logfile", "cwa");

  fe = IP.Flow.Engine();
  //fe->set_log_flow_cb(lambda(object flow) { logfile->write("%s\n", flow->english(1,1)); });
  fe->set_log_flow_cb(lambda(object flow) { write("%s\n", flow->english()); });
  fe->set_new_flow_cb(lambda(object flow) { IP.Flow.DNSCache->lookup_ip((string)flow->src); (string)IP.Flow.DNSCache->lookup_ip(flow->dst); } );

  cap = Public.Network.Pcap.Pcap();
  //threads += ({ Thread.thread_create(caploop) });
  //for (int i; i<2; i++)
    //threads += ({ Thread.thread_create(queueloop) });
  cap->open_live(IF);
  cap->set_capture_length(MTU);
  cap->set_capture_callback(capture_cb);
  cap->set_promisc(1);
  while(1)
    cap->dispatch(50);

  return 1;
}

void caploop() {
  while(1) {
    //capture_cb(cap->next());
    write("*");
    //catch(cap->dispatch(50));
    catch(mixed c = cap->next());
    if (c)
      queue->write(c);
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
  mapping status = fe->status();
  if (sizeof(status)) {
    array flows = status->flows;
    write("Total Flows: %d\tTotal Bytes: %s\tTotal Packets: %d\n", status->flowcount, status->bytes, status->packets);
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
  }
  if (sleep)
    call_out(write_counters, sleep);
}

void capture_cb(mixed ... args) {
  write(".");
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

