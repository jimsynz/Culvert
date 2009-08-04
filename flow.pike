#!/usr/local/bin/pike -Mlib/

#ifdef DISABLE_THREADS
constant threads = 0;
#else
#define ENABLE_THREADS
constant threads = 10;
#endif
constant snaplen = 68;
constant options =
  ({
    ({ "interface", Getopt.HAS_ARG, ({ "-i", "--interface" }) }),
    ({ "logfile", Getopt.HAS_ARG, ({ "-l", "--log-file" }) }),
    ({ "filter", Getopt.HAS_ARG, ({ "-f", "--filter" }) }),
    ({ "snaplen", Getopt.HAS_ARG, ({ "-s", "--snaplen" }) }),
    ({ "nodns", Getopt.NO_ARG, ({ "-n", "--no-dns" }) }),
    ({ "help", Getopt.NO_ARG, ({ "-h", "--help" }) }),
    ({ "threads", Getopt.HAS_ARG, ({ "-t", "--threads" }) }),
    ({ "topten", Getopt.HAS_ARG, ({ "--interval" }) }),
  });


int main(int argc, array argv) {

  mapping args = (mapping)Getopt.find_all_options(argv, options, 0);
  if (args->help) {
    werror("No help for you. Sorry.\n\n");
    return 1;
  }
  if (!args->interface) {
    werror("You must specify an interface to listen on.\n\n");
    return 1;
  }
  if (args->nodns)
    args->nodns=1;
  if (args->threads)
    args->threads = (int)args->threads;
  if (args->snaplen)
    args->snaplen = (int)args->snaplen;
  if (args->topten)
    args->topten = (int)args->topten;

  //object queue = Thread.Fifo(2000);
  object queue = Thread.Fifo(threads||args->threads);
  //object queue = Thread.Queue();


  object fe = IP.Flow.Engine();
  //if (!args->nodns) 
    //fe->set_new_flow_cb(precache_dns, queue);
  if (args->logfile) {
    object logfile = Stdio.File(args->logfile, "cwa");
    fe->set_expired_flow_cb(log, queue, logfile, !args->nodns);
  }
  //fe->set_flow_statechange_cb(lambda(mixed f, int o, int n) { write("%d:%d %s\n", o, n, f->english(!args->nodns,1)); } );

  object cap = Public.Network.Pcap.Pcap();
  cap->set_capture_length(args->snaplen||snaplen);
  cap->set_capture_timeout(10);
  mixed err = catch(cap->open_live(args->interface));
  if (err) {
    werror("Unable to open packet capture interface:\n");
    array tmp = (err[0] / ":")[1..];
    werror("%{%s%}\n", tmp);
    return 1;
  }
  if (args->filter)
    cap->set_filter(args->filter);
  cap->set_promisc(1);
  int start_threads = args->threads||threads;
  if (start_threads) {
    for (int i=0; i < start_threads; i++) {
      Thread.thread_create(dequeue, queue);
    }
    Thread.thread_create(dispatch, cap, queue, fe);
  }
  else {
    werror("Can't run with no threads, for now.\n\n");
    return 1;
    dispatch(cap,queue,fe);
  }

  if (args->topten && start_threads)
    Thread.thread_create(do_top_ten, fe, !args->nodns, args->topten);
  else if (args->topten)
    call_out(top_ten, args->topten, fe, !args->nodns, args->topten);

  return -1;
}

void dispatch(object cap, object queue, object fe) {
  while(1) {
  //for (int i; i < 10; i++) {
    mixed c = cap->next();
    if (mappingp(c)) {
      queue->write(({ desplat, fe, c }));
    }
  }
}

void dequeue(object queue) {
  while(1) {
    mixed c = queue->read();
    if (sizeof(c) > 1)
      c[0](@c[1..]);
    else
      c[0]();
  }
}

void precache_dns(object flow, object queue) {
#ifdef ENABLE_THREADS  
  queue->write(({ IP.Flow.DNSCache->lookup_ip,(string)flow->src }));
  queue->write(({ IP.Flow.DNSCache->lookup_ip,(string)flow->dst }));
#else
  catch(IP.Flow.DNSCache->lookup_ip((string)flow->src));
  catch(IP.Flow.DNSCache->lookup_up((string)flow->dst));
#endif
}

void log(object flow, object queue, object logfile, int dns) {
#ifdef ENABLE_THREADS
  queue->write(({ lambda() { catch(logfile->write("%s\n", flow->english(dns, 1))); } }));
#else
  catch(logfile->write("%s\n", flow->english(dns, 1)));
#endif
}

void desplat(object fe, mixed ... args) {
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

void do_top_ten(object fe, int dns, int interval) {
  while(1) {
    sleep(interval);
    top_ten(fe, dns);
  }
}

void top_ten(object fe, int dns, void|int interval) {
  mapping status = fe->status();
  if (sizeof(status)) {
    array flows = status->flows;
    sort(flows, flows->bytes);
    flows = reverse(flows);
    write("Total Flows: %d\tTotal Bytes: %s\tTotal Packets: %d\n", status->flowcount, status->bytes, status->packets);
    int z = 10;
    if (sizeof(flows) < 10)
      z = sizeof(flows);
    write("Top %d flows:\n", z);
    for (int i; i < z; i++) {
      object f = flows[i];
      if (f)
	write("%s\n", f->english(dns,1));
    }
    write("\n");
  }
  if (interval)
    call_out(top_ten, interval, fe, dns, interval);
}
