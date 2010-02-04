#!/usr/local/bin/pike -Mlib/

/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is IP.v4 Public Module.
 *
 * The Initial Developer of the Original Code is
 * James Harton, <james@mashd.cc>.
 * Portions created by the Initial Developer are Copyright (C) 2005-2009
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * ***** END LICENSE BLOCK ***** */

#ifdef DISABLE_THREADS
#undef ENABLE_THREADS
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
    ({ "help", Getopt.NO_ARG, ({ "-h", "--help" }) }),
    ({ "threads", Getopt.HAS_ARG, ({ "-t", "--threads" }) }),
  });

object five_minute_avg;
object one_hour_avg;
object one_day_avg;
object one_month_avg;

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
  if (args->threads)
    args->threads = (int)args->threads;
  if (args->snaplen)
    args->snaplen = (int)args->snaplen;

#ifdef ENABLE_THREADS
  if ((!args->threads) || (args->threads == 0))
    args->threads = threads;
#endif

  object queue = Thread.Fifo(args->threads);


  object fe = IP.Flow.Engine();
#ifdef ENABLE_THREADS
  write("Culvert %d.%d-%s started with %d worker threads.\n\n", Culvert.MAJOR, Culvert.MINOR, Culvert.BRANCH, args->threads);
#else
  write("Culvert %d.%d-%s started.\n\n", Culvert.MAJOR, Culvert.MINOR, Culvert.BRANCH);
#endif

  five_minute_avg = SampleJar(5 * 60);
  one_hour_avg = SampleJar(60 * 60);
  one_day_avg = SampleJar(60 * 60 * 24);
  one_month_avg = SampleJar(60 * 60 * 24 * 31);

  if (args->logfile) {
    object logfile = Stdio.File(args->logfile, "cwa");
    fe->set_expired_flow_cb(log, queue, logfile, !args->nodns);
  }
  else
    fe->set_expired_flow_cb(time_tcp_session);

  Thread.thread_create(setup_time_report);

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
  else 
    // We're only interested in TCP session setup.
    cap->set_filter("tcp");
  cap->set_promisc(1);
  if (args->threads) {
    for (int i=0; i < args->threads; i++) {
      Thread.thread_create(dequeue, queue);
    }
    Thread.thread_create(dispatch, cap, queue, fe);
  }
  else {
    werror("Can't run with no threads, for now.\n\n");
    return 1;
    dispatch(cap,queue,fe);
  }

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
  catch(IP.Flow.DNSCache->lookup_ip((string)flow->dst));
#endif
}

void log(object flow, object queue, object logfile, int dns) {
#ifdef ENABLE_THREADS
  queue->write(({ lambda() { catch(logfile->write("%s\n", flow->english(dns, 1))); } }));
  // queue->write(({ lambda() { time_tcp_session(flow); }}));
  time_tcp_session(flow);
#else
  catch(logfile->write("%s\n", flow->english(dns, 1)));
  time_tcp_session(flow);
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

void time_tcp_session(object flow) {
  if (sizeof(flow->conversation) > 1) {
    // If we started capturing in the middle of a flow then just ignore it.
    if (flow->conversation[0]->packet->flags["SYN"]) {
      float first = flow->conversation[0]->time;
      float second;
      for (int i=1; i < sizeof(flow->conversation); i++) {
	if (flow->conversation[i]->packet->flags["ACK"]) {
	  second = flow->conversation[i]->time;
	  break;
	}
      }
      if (second > first) {
	// * 100 to get ms instead of s.
	float setup_time = (second - first) * 100;
	one_month_avg->add(setup_time);
	one_day_avg->add(setup_time);
	one_hour_avg->add(setup_time);
	five_minute_avg->add(setup_time);
      }
      // else just discard this session, it ain't much
      // use to us.
    }
  }
}

void setup_time_report() {
  write("[time]: [sample length]([min] ms, [max] ms, [avg] ms, [count])\n");
  while (1) {
    write("%s: 5m (%f ms, %f ms, %f ms, %d), 1h (%f ms, %f ms, %f ms, %d), 1d (%f ms, %f ms, %f ms, %d), 1M (%f ms, %f ms, %f ms, %d)\n",
	Calendar.now()->format_time(), 
	five_minute_avg->min(), five_minute_avg->max(), five_minute_avg->avg(), five_minute_avg->count(),
	one_hour_avg->min(), one_hour_avg->max(), one_hour_avg->avg(), one_hour_avg->count(),
	one_day_avg->min(), one_day_avg->max(), one_day_avg->avg(), one_day_avg->count(), 
	one_month_avg->min(), one_month_avg->max(), one_month_avg->avg(), one_month_avg->count()
	);
    sleep(2);
  }
}

class SampleJar {
  int age_limit;
  array samples;
  int start_time;
  object lock = Thread.Mutex();
  void create(int limit) {
    // Not sure about passing Calendar.Hour, etc, so let's just work
    // in integer seconds. Easier.
    object key = lock->lock();
    age_limit = limit;
    samples = ({});
    start_time = time();
  }

  int add(float sample) {
    // Add a sample to the sample pool.
    object key = lock->lock();
    samples += ({ ([ "time" : (start_time + time(start_time)), "sample" : sample ]) });
    destruct(key);
    return sizeof(samples);
  }
  
  int clean() {
    // Removes too old samples from the jar.
    // We can safely assume that older samples
    // are at the beginning of the array.
    int culled;
    if (sizeof(samples) > 0) {
      mapping sample = samples[0];
      while (sample->time < (start_time + time(start_time) - age_limit)) {
	// remove.
	culled++;
	object key = lock->lock();
	samples = samples[1..];
	destruct(key);
	// Escape hatch for accidentally empty sample jars.
	if (sizeof(samples) > 0) 
	  sample = samples[0];
	else
	  sample = ([ "time" : 0 ]);
      }
    }
    return culled;
  }

  float min() {
    clean();
    if (sizeof(samples)) {
      array x = samples->sample;
      return sort(x)[0];
    }
    else {
      return 0.0;
    }
  }

  float max() {
    clean();
    if (sizeof(samples)) {
      array x = samples->sample;
      return reverse(sort(x))[0];
    }
    else {
      return 0.0;
    }
  }

  float avg() {
    clean();
    if (sizeof(samples)) {
      array x = samples->sample;
      return `+(@x) / sizeof(x);
    }
    else {
      return 0.0;
    }
  }

  int count() {
    return sizeof(samples);
  }

  string _sprintf() {
    return sprintf("SampleJar(/* %d seconds */)", age_limit);
  }
}
