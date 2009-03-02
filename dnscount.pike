#!/usr/bin/pike7.6 -Mlib/

#define IF "eth0"
#define MTU 1500
#define LOGFILE "dnscount.stats"

object fe;
array threads;
object cap;
object dnsproto;
mapping stats;

int main() {
  threads = ({});
  dnsproto = Protocols.DNS.protocol();
  stats = ([]);
  stats["dns.a_successful"]=0;
  stats["dns.aaaa_successful"]=0;
  stats["dns.a_nxdomain"]=0;
  stats["dns.aaaa_nxdomain"]=0;

  cap = Public.Network.Pcap.Pcap();
  cap->set_capture_length(MTU);
  //cap->set_filter("udp port 53");
  cap->open_live(IF);
  call_out(write_stats, 300);

  threads += ({ Thread.thread_create(caploop) });

  return -1;
}

void caploop() {
  while(1)
    capture_cb(cap->next());
}

void write_stats() {
  object log = Stdio.File(LOGFILE, "cwa");
  foreach(sort(indices(stats)), string idx) {
    log->write("%d %s: %d\n", time(), idx, stats[idx]);
    stats[idx]=0;
  }
  log->close();
  call_out(write_stats, 300);
}

void capture_cb(mixed ... args) {
  object frame = Ethernet.Packet(args[0]->data);
  if (frame->type->name() == "IPv4") {
    object packet;
    mixed err = catch(packet = IP.v4.Packet(frame->data));
    if (err)
      write("%O\n", err);
    else {
      if (packet->protocol->name() == "IPv6") {
	object sixtofour;
	mixed err = catch(sixtofour = IP.v6.Packet(packet->data));
	if (err)
	  write("%O\n", err);
	ip_cb(sixtofour->protocol, sixtofour);
      }
      else 
	ip_cb(packet->protocol, packet);
    }
  }
  else if (frame->type->name() == "IPv6") {
    object packet;
    mixed err = catch(packet = IP.v6.Packet(frame->data));
    if (err)
      write("%O\n", err);
    else
      ip_cb(packet->protocol, packet);
  }
}

void ip_cb(object proto, object ip) {
  if (objectp(proto) && (proto->name() == "UDP")) {
    object udp = IP.Protocol.UDP.Packet(ip->data);
    if ((udp->src_port == 53) ||
	(udp->dst_port == 53)) {
      mapping res;
      mixed err = catch(res = dnsproto->decode_res(udp->data));
      if (err)
	werror("%O\n", err);
      else {
	if (!res->qr)
	  return;
	if ((res->qd[0]->type == Protocols.DNS.T_A) &&
	    (res->rcode == Protocols.DNS.NOERROR))
	  stats["dns.a_successful"]++;
	else if ((res->qd[0]->type == Protocols.DNS.T_A) &&
	    (res->rcode == Protocols.DNS.NXDOMAIN))
	  stats["dns.a_nxdomain"]++;
	else if ((res->qd[0]->type == Protocols.DNS.T_AAAA) &&
	    (res->rcode == Protocols.DNS.NOERROR))
	  stats["dns.aaaa_successful"]++;
	else if ((res->qd[0]->type == Protocols.DNS.T_AAAA) &&
	    (res->rcode == Protocols.DNS.NXDOMAIN))
	  stats["dns.aaaa_nxdomain"]++;
      }
    }
  }
}
