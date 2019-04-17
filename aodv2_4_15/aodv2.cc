/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved. 

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The AODV2 code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

*/

//#include <ip.h>

#include <aodv2/aodv2.h>
#include <aodv2/aodv2_packet.h>
#include <random.h>
#include <stdlib.h>
#include <time.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define min(a,b)        ( (a) > (b) ? (b) : (a) )
#define CURRENT_TIME    Scheduler::instance().clock()

#define THRESHOLD 0.6
#define PATH_THRESHOLD 0.5
//#define DEBUG
//#define ERROR

#ifdef DEBUG
static int route_request = 0;
#endif


/*
  TCL Hooks
*/



int hdr_aodv2::offset_;
static class AODV2HeaderClass : public PacketHeaderClass {
public:
        AODV2HeaderClass() : PacketHeaderClass("PacketHeader/AODV2",
                                              sizeof(hdr_all_aodv2)) {
	  bind_offset(&hdr_aodv2::offset_);
	} 
} class_rtProtoAODV2_hdr;

static class AODV2class : public TclClass {
public:
        AODV2class() : TclClass("Agent/AODV2") {}
        TclObject* create(int argc, const char*const* argv) {
          assert(argc == 5);
          //return (new AODV2((nsaddr_t) atoi(argv[4])));
	  return (new AODV2((nsaddr_t) Address::instance().str2addr(argv[4])));
        }
} class_rtProtoAODV2;


int
AODV2::command(int argc, const char*const* argv) {
  if(argc == 2) {
  Tcl& tcl = Tcl::instance();
    
    if(strncasecmp(argv[1], "id", 2) == 0) {
      tcl.resultf("%d", index);
      return TCL_OK;
    }
    
    if(strncasecmp(argv[1], "start", 2) == 0) {
      btimer.handle((Event*) 0);

#ifndef AODV2_LINK_LAYER_DETECTION
      htimer.handle((Event*) 0);
      ntimer.handle((Event*) 0);
#endif // LINK LAYER DETECTION

      rtimer.handle((Event*) 0);
      return TCL_OK;
     }
    if(strncasecmp(argv[1], "start", 2) == 0) {
    	btimer.handle((Event*) 0);
    	ttimer.sched(double(TRUST_TIME));
    }
  }
  else if(argc == 3) {
    if(strcmp(argv[1], "index") == 0) {
      index = atoi(argv[2]);
      return TCL_OK;
    }

    else if(strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
      logtarget = (Trace*) TclObject::lookup(argv[2]);
      if(logtarget == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if(strcmp(argv[1], "drop-target") == 0) {
    int stat = rqueue.command(argc,argv);
      if (stat != TCL_OK) return stat;
      return Agent::command(argc, argv);
    }
    else if(strcmp(argv[1], "if-queue") == 0) {
    ifqueue = (PriQueue*) TclObject::lookup(argv[2]);
      
      if(ifqueue == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if (strcmp(argv[1], "port-dmux") == 0) {
    	dmux_ = (PortClassifier *)TclObject::lookup(argv[2]);
	if (dmux_ == 0) {
		fprintf (stderr, "%s: %s lookup of %s failed\n", __FILE__,
		argv[1], argv[2]);
		return TCL_ERROR;
	}
	return TCL_OK;
    }
    else if (strcmp(argv[1], "black-hole") == 0) {
    	//printf("black-hole exists\n");
    	blackhole = 1;
    	return TCL_OK;
    }
    else if (strcmp(argv[1], "gray-hole") == 0) {
    	//printf("gray-hole exists\n");
    	grayhole = 1;
    	return TCL_OK;
    }
    else if (strcmp(argv[1], "bad-mouth") == 0) {
    	//printf("bad-mouth exists\n");
    	badmouth = 1;
    	return TCL_OK;
    }
    else if (strcmp(argv[1], "ballot-stuffing") == 0){
    	ballot = 1;
    	return TCL_OK;
    }
    else if (strcmp(argv[1], "self-promoting") == 0){
    	selfpromoting = 1;
    	return TCL_OK;
    }
    else if (strcmp(argv[1], "install-tap") == 0) {
    	mac_ = (Mac*)TclObject::lookup(argv[2]);
    	if (mac_ == 0) return TCL_ERROR;
    	mac_->installTap(this);
    	return TCL_OK;
    }
  }
  return Agent::command(argc, argv);
}


/* 
   Constructor
*/

AODV2::AODV2(nsaddr_t id) : Agent(PT_AODV2),
			  btimer(this), ttimer(this), htimer(this), ntimer(this),
			  rtimer(this), lrtimer(this), rqueue() {
 
                
  index = id;
  seqno = 2;
  bid = 1;

  LIST_INIT(&nbhead);
  LIST_INIT(&bihead);

  logtarget = 0;
  ifqueue = 0;
}

/*
  Timers
*/
/*
 * 02/24/2019*/

void
AODV2BroadcastTimer::handle(Event*) {
  agent->id_purge();
  Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
}

void
AODV2HelloTimer::handle(Event*) {
   agent->sendHello();
   double interval = MinHelloInterval + 
                 ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
   assert(interval >= 0);
   Scheduler::instance().schedule(this, &intr, interval);
}

void
AODV2NeighborTimer::handle(Event*) {
  agent->nb_purge();
  Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
}

void
AODV2TrustTimer::expire(Event* ){
	agent->setTrust();
	double t = 0.01 * Random::uniform();
	int x = 100000 * t;
	if(x & 1)
		agent->ttimer.resched((double)TRUST_TIME+t);
	else
		agent->ttimer.resched((double)TRUST_TIME-t);
}
void
AODV2RouteCacheTimer::handle(Event*) {
  agent->rt_purge();
#define FREQUENCY 0.5 // sec
  Scheduler::instance().schedule(this, &intr, FREQUENCY);
}

void
AODV2LocalRepairTimer::handle(Event* p)  {  // SRD: 5/4/99
aodv2_rt_entry *rt;
struct hdr_ip *ih = HDR_IP( (Packet *)p);

   /* you get here after the timeout in a local repair attempt */
   /*	fprintf(stderr, "%s\n", __FUNCTION__); */

/*
 * 02/24/2019*/

    rt = agent->rtable.rt_lookup(ih->daddr());
	
    if (rt && rt->rt_flags != RTF_UP) {
    // route is yet to be repaired
    // I will be conservative and bring down the route
    // and send route errors upstream.
    /* The following assert fails, not sure why */
    /* assert (rt->rt_flags == RTF_IN_REPAIR); */

/* 02/24/2019*/
      //rt->rt_seqno++;
      agent->rt_down(rt);
      // send RERR
#ifdef DEBUG
      fprintf(stderr,"Dst - %d, failed local repair\n", rt->rt_dst);
#endif      
    }
    Packet::free((Packet *)p);
}

/* 02/24/2019 */

/*
   Broadcast ID Management  Functions
*/


void
AODV2::id_insert(nsaddr_t id, u_int32_t bid) {
AODV2BroadcastID *b = new AODV2BroadcastID(id, bid);

 assert(b);
 b->expire = CURRENT_TIME + BCAST_ID_SAVE;
 LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool
AODV2::id_lookup(nsaddr_t id, u_int32_t bid) {
AODV2BroadcastID *b = bihead.lh_first;
 
 // Search the list for a match of source and bid
 for( ; b; b = b->link.le_next) {
   if ((b->src == id) && (b->id == bid))
     return true;     
 }
 return false;
}

void
AODV2::id_purge() {
AODV2BroadcastID *b = bihead.lh_first;
AODV2BroadcastID *bn;
double now = CURRENT_TIME;

 for(; b; b = bn) {
   bn = b->link.le_next;
   if(b->expire <= now) {
     LIST_REMOVE(b,link);
     delete b;
   }
 }
}

/*
  Helper Functions
*/

double
AODV2::PerHopTime(aodv2_rt_entry *rt) {
int num_non_zero = 0, i;
double total_latency = 0.0;

 if (!rt)
   return ((double) NODE_TRAVERSAL_TIME );
	
 for (i=0; i < MAX_HISTORY; i++) {
   if (rt->rt_disc_latency[i] > 0.0) {
      num_non_zero++;
      total_latency += rt->rt_disc_latency[i];
   }
 }
 if (num_non_zero > 0)
   return(total_latency / (double) num_non_zero);
 else
   return((double) NODE_TRAVERSAL_TIME);

}

/*
  Link Failure Management Functions
*/

static void
aodv2_rt_failed_callback(Packet *p, void *arg) {
  ((AODV2*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
AODV2::rt_ll_failed(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv2_rt_entry *rt;
nsaddr_t broken_nbr = ch->next_hop_;

#ifndef AODV2_LINK_LAYER_DETECTION
 drop(p, DROP_RTR_MAC_CALLBACK);
#else 

 /*
  * Non-data packets and Broadcast Packets can be dropped.
  */
  if(! DATA_PACKET(ch->ptype()) ||
     (u_int32_t) ih->daddr() == IP_BROADCAST) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_broke(p);
	if((rt = rtable.rt_lookup(ih->daddr())) == 0) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_del(ch->next_hop_);

#ifdef AODV2_LOCAL_REPAIR
  /* if the broken link is closer to the dest than source, 
     attempt a local repair. Otherwise, bring down the route. */


  if (ch->num_forwards() > rt->rt_hops) {
    local_rt_repair(rt, p); // local repair
    // retrieve all the packets in the ifq using this link,
    // queue the packets for which local repair is done, 
    return;
  }
  else	
#endif // LOCAL REPAIR	

  {
    drop(p, DROP_RTR_MAC_CALLBACK);
    // Do the same thing for other packets in the interface queue using the
    // broken link -Mahesh
while((p = ifqueue->filter(broken_nbr))) {
     drop(p, DROP_RTR_MAC_CALLBACK);
    }	
    nb_delete(broken_nbr);
  }

#endif // LINK LAYER DETECTION
}

void
AODV2::handle_link_failure(nsaddr_t id) {
aodv2_rt_entry *rt, *rtn;
Packet *rerr = Packet::alloc();
struct hdr_aodv2_error *re = HDR_AODV2_ERROR(rerr);

 re->DestCount = 0;
 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next; 
   if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id) ) {
     assert (rt->rt_flags == RTF_UP);
     assert((rt->rt_seqno%2) == 0);
     rt->rt_seqno++;
     re->unreachable_dst[re->DestCount] = rt->rt_dst;
     re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
		     index, re->unreachable_dst[re->DestCount],
		     re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
     re->DestCount += 1;
     rt_down(rt);
   }
   // remove the lost neighbor from all the precursor lists
   rt->pc_delete(id);
 }   

 if (re->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr, false);
 }
 else {
   Packet::free(rerr);
 }
}

void
AODV2::local_rt_repair(aodv2_rt_entry *rt, Packet *p) {
#ifdef DEBUG
  fprintf(stderr,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst); 
#endif  
  // Buffer the packet 
  rqueue.enque(p);

  // mark the route as under repair 
  rt->rt_flags = RTF_IN_REPAIR;

  sendRequest(rt->rt_dst);

  // set up a timer interrupt
  Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);
}

void
AODV2::rt_update(aodv2_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
	       	nsaddr_t nexthop, double expire_time) {

     rt->rt_seqno = seqnum;
     rt->rt_hops = metric;
     rt->rt_flags = RTF_UP;
     rt->rt_nexthop = nexthop;
     rt->rt_expire = expire_time;
}

void
AODV2::rt_down(aodv2_rt_entry *rt) {
  /*
   *  Make sure that you don't "down" a route more than once.
   */

  if(rt->rt_flags == RTF_DOWN) {
    return;
  }

  // assert (rt->rt_seqno%2); // is the seqno odd?
  rt->rt_last_hop_count = rt->rt_hops;
  rt->rt_hops = INFINITY2;
  rt->rt_flags = RTF_DOWN;
  rt->rt_nexthop = 0;
  rt->rt_expire = 0;

} /* rt_down function */

/*
  Route Handling Functions
*/

void
AODV2::rt_resolve(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv2_rt_entry *rt;
srand(unsigned(time(NULL)));
 /*
  *  Set the transmit failure callback.  That
  *  won't change.
  */
 ch->xmit_failure_ = aodv2_rt_failed_callback;
 ch->xmit_failure_data_ = (void*) this;
	rt = rtable.rt_lookup(ih->daddr());
 if(rt == 0) {
	  rt = rtable.rt_add(ih->daddr());
 }
 ch->pprev_hop_ = ch->prev_hop_;
 ch->prev_hop_ = this->index;
 /*
  * If the route is up, forward the packet 
  */
	
 if(rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   forward(rt, p, NO_DELAY);
 }
 /*
  *  if I am the source of the packet, then do a Route Request.
  */
	else if(ih->saddr() == index) {
   rqueue.enque(p);
   sendRequest(rt->rt_dst);
 }
 /*
  *	A local repair is in progress. Buffer the packet. 
  */
 else if (rt->rt_flags == RTF_IN_REPAIR) {
   rqueue.enque(p);
 }

 else if ((blackhole == 1 || (grayhole == 1 && rand() % 100 < 85)) && ih->daddr() != index){
	 drop(p, DROP_IFQ_FILTER);
 }

 /*
  * I am trying to forward a packet for someone else to which
  * I don't have a route.
  */
 else {
 Packet *rerr = Packet::alloc();
 struct hdr_aodv2_error *re = HDR_AODV2_ERROR(rerr);
 /* 
  * For now, drop the packet and send error upstream.
  * Now the route errors are broadcast to upstream
  * neighbors - Mahesh 09/11/99
  */	
 
   assert (rt->rt_flags == RTF_DOWN);
   re->DestCount = 0;
   re->unreachable_dst[re->DestCount] = rt->rt_dst;
   re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
   re->DestCount += 1;
#ifdef DEBUG
   fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
   sendError(rerr, false);

   drop(p, DROP_RTR_NO_ROUTE);
 }

}

void
AODV2::rt_purge() {
aodv2_rt_entry *rt, *rtn;
double now = CURRENT_TIME;
double delay = 0.0;
Packet *p;

 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next;
   if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
   // if a valid route has expired, purge all packets from 
   // send buffer and invalidate the route.                    
	assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
       fprintf(stderr, "%s: calling drop()\n",
                       __FUNCTION__);
#endif // DEBUG
       drop(p, DROP_RTR_NO_ROUTE);
     }
     rt->rt_seqno++;
     assert (rt->rt_seqno%2);
     rt_down(rt);
   }
   else if (rt->rt_flags == RTF_UP) {
   // If the route is not expired,
   // and there are packets in the sendbuffer waiting,
   // forward them. This should not be needed, but this extra 
   // check does no harm.
     assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
       forward (rt, p, delay);
       delay += ARP_DELAY;
     }
   } 
   else if (rqueue.find(rt->rt_dst))
   // If the route is down and 
   // if there is a packet for this destination waiting in
   // the sendbuffer, then send out route request. sendRequest
   // will check whether it is time to really send out request
   // or not.
   // This may not be crucial to do it here, as each generated 
   // packet will do a sendRequest anyway.

     sendRequest(rt->rt_dst); 
   }

}

/*
  Packet Reception Routines
*/

void
AODV2::recv(Packet *p, Handler*) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(initialized());
 //assert(p->incoming == 0);
 // XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

 if(ch->ptype() == PT_AODV2) {
   ih->ttl_ -= 1;
   recvAODV2(p);
   return;
 }


 /*
  *  Must be a packet I'm originating...
  */
if((ih->saddr() == index) && (ch->num_forwards() == 0)) {
 /*
  * Add the IP Header.  
  * TCP adds the IP header too, so to avoid setting it twice, we check if
  * this packet is not a TCP or ACK segment.
  */
  if (ch->ptype() != PT_TCP && ch->ptype() != PT_ACK) {
    ch->size() += IP_HDR_LEN;
  }
   // Added by Parag Dadhania && John Novatnack to handle broadcasting
  if ( (u_int32_t)ih->daddr() != IP_BROADCAST) {
    ih->ttl_ = NETWORK_DIAMETER;
  }
}
 /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
else if(ih->saddr() == index) {
   drop(p, DROP_RTR_ROUTE_LOOP);
   return;
 }
 /*
  *  Packet I'm forwarding...
  */
 else {
 /*
  *  Check the TTL.  If it is zero, then discard.
  */
   if(--ih->ttl_ == 0) {
     drop(p, DROP_RTR_TTL);
     return;
   }
 }
// Added by Parag Dadhania && John Novatnack to handle broadcasting
 if ( (u_int32_t)ih->daddr() != IP_BROADCAST)
   rt_resolve(p);
 else
   forward((aodv2_rt_entry*) 0, p, NO_DELAY);
}


void
AODV2::recvAODV2(Packet *p) {
 struct hdr_aodv2 *ah = HDR_AODV2(p);

 assert(HDR_IP (p)->sport() == RT_PORT);
 assert(HDR_IP (p)->dport() == RT_PORT);

 /*
  * Incoming Packets.
  */
 switch(ah->ah_type) {

 case AODV2TYPE_RREQ:
   recvRequest(p);
   break;

 case AODV2TYPE_RREP:
   recvReply(p);
   break;

 case AODV2TYPE_RERR:
   recvError(p);
   break;

 case AODV2TYPE_HELLO:
   recvHello(p);
   break;
 case AODV2TYPE_RCMD:
	 recvRecommend(p);
	 break;
 default:
   fprintf(stderr, "Invalid AODV2 type (%x)\n", ah->ah_type);
   exit(1);
 }

}


void
AODV2::recvRequest(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_request *rq = HDR_AODV2_REQUEST(p);
aodv2_rt_entry *rt;

  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this request.
   */

  if(rq->rq_src == index) {
#ifdef DEBUG
    fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  } 

 if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
   fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG
 
   Packet::free(p);
   return;
 }
 if (nb_lookup(ch->prev_hop_)->nb_comprehensive_trust < PATH_THRESHOLD){
	 Packet::free(p);
	 return;
 }

 /*
  * Cache the broadcast ID
  */
 id_insert(rq->rq_src, rq->rq_bcast_id);



 /* 
  * We are either going to forward the REQUEST or generate a
  * REPLY. Before we do anything, we make sure that the REVERSE
  * route is in the route table.
  */
 aodv2_rt_entry *rt0; // rt0 is the reverse route
   
   rt0 = rtable.rt_lookup(rq->rq_src);
   if(rt0 == 0) { /* if not in the route table */
   // create an entry for the reverse route.
     rt0 = rtable.rt_add(rq->rq_src);
   }
  
   rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));
//I don't think several RREOs can be received simultaneously
   rt0->rt_path_trust = min(rt0->rt_path_trust, nb_lookup(ch->prev_hop_)->nb_comprehensive_trust);
   //when path trust needs to be considered, so just reserve it.
   if ( (rq->rq_src_seqno > rt0->rt_seqno ) ||
    	((rq->rq_src_seqno == rt0->rt_seqno) && 
	 (rq->rq_hop_count < rt0->rt_hops)) ) {
   // If we have a fresher seq no. or lesser #hops for the 
   // same seq no., update the rt entry. Else don't bother.
rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
     	       max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)) );
     if (rt0->rt_req_timeout > 0.0) {
     // Reset the soft state and 
     // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
     // This is because route is used in the forward direction,
     // but only sources get benefited by this change
       rt0->rt_req_cnt = 0;
       rt0->rt_req_timeout = 0.0; 
       rt0->rt_req_last_ttl = rq->rq_hop_count;
       rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
     }

     /* Find out whether any buffered packet can benefit from the 
      * reverse route.
      * May need some change in the following code - Mahesh 09/11/99
      */
     assert (rt0->rt_flags == RTF_UP);
     Packet *buffered_pkt;
     while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
       if (rt0 && (rt0->rt_flags == RTF_UP)) {
	assert(rt0->rt_hops != INFINITY2);
         forward(rt0, buffered_pkt, NO_DELAY);
       }
     }
   } 
   // End for putting reverse route in rt table


 /*
  * We have taken care of the reverse route stuff.
  * Now see whether we can send a route reply. 
  */

 rt = rtable.rt_lookup(rq->rq_dst);

 // First check if I am the destination ..

 if(rq->rq_dst == index) {

#ifdef DEBUG
   fprintf(stderr, "%d - %s: destination sending reply\n",
                   index, __FUNCTION__);
#endif // DEBUG

               
   // Just to be safe, I use the max. Somebody may have
   // incremented the dst seqno.
   seqno = max(seqno, rq->rq_dst_seqno)+1;
   if (seqno%2) seqno++;

   sendReply(rq->rq_src,           // IP Destination
             1,                    // Hop Count
             index,                // Dest IP Address
             seqno,                // Dest Sequence Num
             MY_ROUTE_TIMEOUT,     // Lifetime
             rq->rq_timestamp);    // timestamp
 
   Packet::free(p);
 }

else if (rt && (blackhole == 1 || grayhole == 1)) {
	assert(rq->rq_dst == rt->rt_dst);
	sendReply(rq->rq_src,
			  1,
			  rq->rq_dst,
			  4294967295,
			  (u_int32_t) (rt->rt_expire - CURRENT_TIME),
			  rq->rq_timestamp);
	rt->pc_insert(rt0->rt_nexthop);
	rt->pc_insert(rt->rt_nexthop);

	Packet::free(p);
}

 // I am not the destination, but I may have a fresh enough route.
 else if (rt && (rt->rt_hops != INFINITY2) && 
	  	(rt->rt_seqno >= rq->rq_dst_seqno) ) {

   //assert (rt->rt_flags == RTF_UP);
   assert(rq->rq_dst == rt->rt_dst);
   //assert ((rt->rt_seqno%2) == 0);	// is the seqno even?
   sendReply(rq->rq_src,
             rt->rt_hops + 1,
             rq->rq_dst,
             rt->rt_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);
   // Insert nexthops to RREQ source and RREQ destination in the
   // precursor lists of destination and source respectively
   rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
   rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination

#ifdef RREQ_GRAT_RREP  

   sendReply(rq->rq_dst,
             rq->rq_hop_count,
             rq->rq_src,
             rq->rq_src_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);
#endif
   
// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT
   
// DONE: Included gratuitous replies to be sent as per IETF aodv2 draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv2-packet.h --- Anant Utgikar, 09/16/02.

	Packet::free(p);
 }
 /*
  * Can't reply. So forward the  Route Request
  */
 else if (blackhole == 1 || grayhole == 1){
	sendReply(rq->rq_src,
			  1,
			  rq->rq_dst,
			  4294967295,
			  MY_ROUTE_TIMEOUT,
			  rq->rq_timestamp);
	Packet::free(p);
 }
 else {
   ih->saddr() = index;
   ih->daddr() = IP_BROADCAST;
   rq->rq_hop_count += 1;
   // Maximum sequence number seen en route
   if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
   forward((aodv2_rt_entry*) 0, p, DELAY);
 }

}


void
AODV2::recvReply(Packet *p) {
//struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_reply *rp = HDR_AODV2_REPLY(p);
aodv2_rt_entry *rt;
char suppress_reply = 0;
double delay = 0.0;
	
#ifdef DEBUG
 fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG


 /*
  *  Got a reply. So reset the "soft state" maintained for 
  *  route requests in the request table. We don't really have
  *  have a separate request table. It is just a part of the
  *  routing table itself. 
  */
 // Note that rp_dst is the dest of the data packets, not the
 // the dest of the reply, which is the src of the data packets.

 rt = rtable.rt_lookup(rp->rp_dst);
        
 /*
  *  If I don't have a rt entry to this host... adding
  */
 if(rt == 0) {
   rt = rtable.rt_add(rp->rp_dst);
 }

 /*
  * Add a forward route table entry... here I am following 
  * Perkins-Royer AODV2 paper almost literally - SRD 5/99
  */

 if ( (rt->rt_seqno < rp->rp_dst_seqno) ||   // newer route 
      ((rt->rt_seqno == rp->rp_dst_seqno) &&  
       (rt->rt_hops > rp->rp_hop_count)) ) { // shorter or better route
	
  // Update the rt entry 
  rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
		rp->rp_src, CURRENT_TIME + rp->rp_lifetime);

  // reset the soft state
  rt->rt_req_cnt = 0;
  rt->rt_req_timeout = 0.0; 
  rt->rt_req_last_ttl = rp->rp_hop_count;
  
if (ih->daddr() == index) { // If I am the original source
  // Update the route discovery latency statistics
  // rp->rp_timestamp is the time of request origination
		
    rt->rt_disc_latency[(unsigned char)rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
                                         / (double) rp->rp_hop_count;
    // increment indx for next time
    rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
  }	

  /*
   * Send all packets queued in the sendbuffer destined for
   * this destination. 
   * XXX - observe the "second" use of p.
   */
  Packet *buf_pkt;
  while((buf_pkt = rqueue.deque(rt->rt_dst))) {
    if(rt->rt_hops != INFINITY2) {
          assert (rt->rt_flags == RTF_UP);
    // Delay them a little to help ARP. Otherwise ARP 
    // may drop packets. -SRD 5/23/99
      forward(rt, buf_pkt, delay);
      delay += ARP_DELAY;
    }
  }
 }
 else {
  suppress_reply = 1;
 }

 /*
  * If reply is for me, discard it.
  */

if(ih->daddr() == index || suppress_reply) {
   Packet::free(p);
 }
 /*
  * Otherwise, forward the Route Reply.
  */
 else {
 // Find the rt entry
aodv2_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
   // If the rt is up, forward
   if(rt0 && (rt0->rt_hops != INFINITY2)) {
        assert (rt0->rt_flags == RTF_UP);
     rp->rp_hop_count += 1;
     rp->rp_src = index;
     forward(rt0, p, NO_DELAY);
     // Insert the nexthop towards the RREQ source to 
     // the precursor list of the RREQ destination
     rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
     
   }
   else {
   // I don't know how to forward .. drop the reply. 
#ifdef DEBUG
     fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
     drop(p, DROP_RTR_NO_ROUTE);
   }
 }
}

void
AODV2::setTrust(){
	AODV2_Neighbor *nb;
	for (nb = nbhead.lh_first; nb; nb = nb->nb_link.le_next){
		nb->set_nb_trust();
		bool ok = false;
		for (int i = 0; i < nb->n_d_trustlist_size; i++){
			if (nb->n_d_trustlist[i].addr == index){
				nb->n_d_trustlist[i].d_trust = nb->nb_trust;
				ok = true;
				break;
			}
		}
		if (!ok){
			nb->n_d_trustlist[nb->n_d_trustlist_size].addr = index;
			nb->n_d_trustlist[nb->n_d_trustlist_size++].d_trust = nb->nb_trust;
		}
		sendRecommend(nb);
		nb->set_nb_indirect_trust(index);
		nb->set_nb_comprehensive_trust();
		nb->reliab = nb->nb_reliability(index);
		nb->set_nb_internal_state();
	}
}

/*
void
AODV2::setTrust() {
	AODV2_Neighbor *nb;
	//Packet *p = Packet::alloc();
	//struct hdr_aodv2_rcmd *rd = HDR_AODV2_RCMD(p);
	for (nb = nbhead.lh_first; nb; nb = nb->nb_link.le_next){
		nb->set_nb_trust();
		bool ok = true;
		for (int i = 0; i < nb->trustlist_size; i++){
			if (nb->trustlist[i].addr == index){
				nb->trustlist[i].d_trust = nb->nb_trust;
				ok = false;
				break;
			}
		}
		if (ok == true){
			nb->trustlist[nb->trustlist_size].addr = index;
			nb->trustlist[nb->trustlist_size++].d_trust = nb->nb_trust;
		}
		sendRecommend(nb->trustlist, nb->trustlist_size);
	}
}
*/


void
AODV2::recvError(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_error *re = HDR_AODV2_ERROR(p);
aodv2_rt_entry *rt;
u_int8_t i;
Packet *rerr = Packet::alloc();
struct hdr_aodv2_error *nre = HDR_AODV2_ERROR(rerr);

 nre->DestCount = 0;

 for (i=0; i<re->DestCount; i++) {
 // For each unreachable destination
   rt = rtable.rt_lookup(re->unreachable_dst[i]);
   if ( rt && (rt->rt_hops != INFINITY2) &&
	(rt->rt_nexthop == ih->saddr()) &&
     	(rt->rt_seqno <= re->unreachable_dst_seqno[i]) ) {
	assert(rt->rt_flags == RTF_UP);
	assert((rt->rt_seqno%2) == 0); // is the seqno even?
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__,CURRENT_TIME,
		     index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
		     re->unreachable_dst[i],re->unreachable_dst_seqno[i],
	             ih->saddr());
#endif // DEBUG
     	rt->rt_seqno = re->unreachable_dst_seqno[i];
     	rt_down(rt);

   // Not sure whether this is the right thing to do
   Packet *pkt;
	while((pkt = ifqueue->filter(ih->saddr()))) {
        	drop(pkt, DROP_RTR_MAC_CALLBACK);
     	}

     // if precursor list non-empty add to RERR and delete the precursor list
     	if (!rt->pc_empty()) {
     		nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
     		nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
     		nre->DestCount += 1;
		rt->pc_delete();
     	}
   }
 } 

 if (nre->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr);
 }
 else {
   Packet::free(rerr);
 }

 Packet::free(p);
}


/*
   Packet Transmission Routines
*/

void
AODV2::forward(aodv2_rt_entry *rt, Packet *p, double delay) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 if(ih->ttl_ == 0) {

#ifdef DEBUG
  fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG
 
  drop(p, DROP_RTR_TTL);
  return;
 }

 if ((( ch->ptype() != PT_AODV2 && ch->direction() == hdr_cmn::UP ) &&
	((u_int32_t)ih->daddr() == IP_BROADCAST))
		|| (ih->daddr() == here_.addr_)) {
	dmux_->recv(p,0);
	return;
 }

 if (rt) {
   assert(rt->rt_flags == RTF_UP);
   rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
   ch->next_hop_ = rt->rt_nexthop;
   ch->addr_type() = NS_AF_INET;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
   AODV2_Neighbor *nb = nb_lookup(ch->prev_hop_);
   if (ch->ptype() == PT_CBR) {
	   if (nb) {
		   nb->inc_nb_send();
		   if (ch->next_hop_ == ih->daddr()){
			   nb->inc_nb_retrans();
		   }
	   }
   }
 }
 else { // if it is a broadcast packet
   // assert(ch->ptype() == PT_AODV2); // maybe a diff pkt type like gaf
   assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
   ch->addr_type() = NS_AF_NONE;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }

if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
 // If it is a broadcast packet
   assert(rt == 0);
   if (ch->ptype() == PT_AODV2) {
     /*
      *  Jitter the sending of AODV2 broadcast packets by 10ms
      */
     Scheduler::instance().schedule(target_, p,
      				   0.01 * Random::uniform());
   } else {
     Scheduler::instance().schedule(target_, p, 0.);  // No jitter
   }
 }
 else { // Not a broadcast packet 
   if(delay > 0.0) {
     Scheduler::instance().schedule(target_, p, delay);
   }
   else {
   // Not a broadcast packet, no delay, send immediately
     Scheduler::instance().schedule(target_, p, 0.);
   }
 }

}

/*
void
AODV2::sendRecommend(Packet* p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv2_rcmd *rc = HDR_AODV2_RCMD(p);
}*/

void
AODV2::sendRequest(nsaddr_t dst) {
// Allocate a RREQ packet 
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_request *rq = HDR_AODV2_REQUEST(p);
aodv2_rt_entry *rt = rtable.rt_lookup(dst);

 assert(rt);

 /*
  *  Rate limit sending of Route Requests. We are very conservative
  *  about sending out route requests. 
  */

 if (rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   Packet::free((Packet *)p);
   return;
 }

 if (rt->rt_req_timeout > CURRENT_TIME) {
   Packet::free((Packet *)p);
   return;
 }

 // rt_req_cnt is the no. of times we did network-wide broadcast
 // RREQ_RETRIES is the maximum number we will allow before 
 // going to a long timeout.

 if (rt->rt_req_cnt > RREQ_RETRIES) {
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
   rt->rt_req_cnt = 0;
 Packet *buf_pkt;
   while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
       drop(buf_pkt, DROP_RTR_NO_ROUTE);
   }
   Packet::free((Packet *)p);
   return;
 }

#ifdef DEBUG
   fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d\n",
                    ++route_request, index, rt->rt_dst);
#endif // DEBUG

 // Determine the TTL to be used this time. 
 // Dynamic TTL evaluation - SRD

 rt->rt_req_last_ttl = max(rt->rt_req_last_ttl,rt->rt_last_hop_count);

 if (0 == rt->rt_req_last_ttl) {
 // first time query broadcast
   ih->ttl_ = TTL_START;
 }
 else {
 // Expanding ring search.
   if (rt->rt_req_last_ttl < TTL_THRESHOLD)
     ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
   else {
   // network-wide broadcast
     ih->ttl_ = NETWORK_DIAMETER;
     rt->rt_req_cnt += 1;
   }
 }

 // remember the TTL used  for the next time
 rt->rt_req_last_ttl = ih->ttl_;

 // PerHopTime is the roundtrip time per hop for route requests.
 // The factor 2.0 is just to be safe .. SRD 5/22/99
 // Also note that we are making timeouts to be larger if we have 
 // done network wide broadcast before. 

 rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt); 
 if (rt->rt_req_cnt > 0)
   rt->rt_req_timeout *= rt->rt_req_cnt;
 rt->rt_req_timeout += CURRENT_TIME;

 // Don't let the timeout to be too large, however .. SRD 6/8/99
 if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
 rt->rt_expire = 0;

#ifdef DEBUG
 fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
	         ++route_request, 
		 index, rt->rt_dst, 
		 rt->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG
	

 // Fill out the RREQ packet 
 // ch->uid() = 0;
 ch->ptype() = PT_AODV2;
 ch->size() = IP_HDR_LEN + rq->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->pprev_hop_ = ch->prev_hop_; //02/25/2019
 ch->prev_hop_ = index;          // AODV2 hack


 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;

 // Fill up some more fields. 
 rq->rq_type = AODV2TYPE_RREQ;
 rq->rq_hop_count = 1;
 rq->rq_bcast_id = bid++;
 rq->rq_dst = dst;
 rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
 rq->rq_src = index;
 seqno += 2;
 assert ((seqno%2) == 0);
 rq->rq_src_seqno = seqno;
 rq->rq_timestamp = CURRENT_TIME;

 Scheduler::instance().schedule(target_, p, 0.);

}

void
AODV2::tap(const Packet *p){
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	if (ch->ptype() == PT_CBR){
		AODV2_Neighbor *nb = nb_lookup(ch->pprev_hop_);
		if (nb && index == ch->pprev_hop_) {
			nb->inc_nb_retrans();
		}
		if (ih->saddr() == index && ch->num_forwards() == 0){
			for (nb = nbhead.lh_first; nb; nb = nb->nb_link.le_next){
				nb->inc_nb_domin();
			}
		}
		else if (ch->prev_hop_ == index){
			for (nb = nbhead.lh_first; nb; nb = nb->nb_link.le_next){
				nb->inc_nb_reces();
			}
		}
	}

}

void
AODV2::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
                u_int32_t rpseq, u_int32_t lifetime, double timestamp) {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_reply *rp = HDR_AODV2_REPLY(p);
aodv2_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
fprintf(stderr, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
 assert(rt);

 rp->rp_type = AODV2TYPE_RREP;
 //rp->rp_flags = 0x00;
 rp->rp_hop_count = hop_count;
 rp->rp_dst = rpdst;
 rp->rp_dst_seqno = rpseq;
 rp->rp_src = index;
 rp->rp_lifetime = lifetime;
 rp->rp_timestamp = timestamp;
   
 // ch->uid() = 0;
 ch->ptype() = PT_AODV2;
 ch->size() = IP_HDR_LEN + rp->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_INET;
 ch->next_hop_ = rt->rt_nexthop;
 ch->prev_hop_ = index;          // AODV2 hack
 ch->direction() = hdr_cmn::DOWN;

 ih->saddr() = index;
 ih->daddr() = ipdst;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = NETWORK_DIAMETER;

 Scheduler::instance().schedule(target_, p, 0.);

}

void
AODV2::sendError(Packet *p, bool jitter) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_error *re = HDR_AODV2_ERROR(p);
    
#ifdef ERROR
fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 re->re_type = AODV2TYPE_RERR;
 //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
 // DestCount and list of unreachable destinations are already filled

 // ch->uid() = 0;
 ch->ptype() = PT_AODV2;
 ch->size() = IP_HDR_LEN + re->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->next_hop_ = 0;
 ch->prev_hop_ = index;          // AODV2 hack
 ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 // Do we need any jitter? Yes
 if (jitter)
 	Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());
 else
 	Scheduler::instance().schedule(target_, p, 0.0);

}

void
AODV2::sendRecommend(AODV2_Neighbor *nb) {
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv2_rcmd *rd = HDR_AODV2_RCMD(p);

	#ifdef DEBUG
	fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
	#endif // DEBUG

	 rd->rc_type = AODV2TYPE_RCMD;
	 rd->nb_num = nb->n_d_trustlist_size;
	 for (int i = 0; i < rd->nb_num; i++){
		 rd->nbr[i] = nb->n_d_trustlist[i].addr;
		 rd->trust[i] = nb->n_d_trustlist[i].d_trust;
	 }
	 //rh->rp_flags = 0x00;


	 // ch->uid() = 0;
	 ch->ptype() = PT_AODV2;
	 ch->size() = IP_HDR_LEN + rd->size();
	 ch->iface() = -2;
	 ch->error() = 0;
	 ch->addr_type() = NS_AF_NONE;
	 ch->prev_hop_ = index;          // AODV2 hack

	 ih->saddr() = nb->nb_addr;
	 ih->daddr() = IP_BROADCAST;
	 ih->sport() = RT_PORT;
	 ih->dport() = RT_PORT;
	 ih->ttl_ = 1; //Neighbor

	 Scheduler::instance().schedule(target_, p, 0.1*Random::uniform());

}

void
AODV2::recvRecommend(Packet *p){
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv2_rcmd *rd = HDR_AODV2_RCMD(p);
	bool ok_i = false;
	for (int i = 0; i < MAPP.map_num; i++){
		if (MAPP.mapTrust[i].nb_addr == index){
			bool ok_j = false;
			for (int j = 0; j < MAPP.mapTrust[i].i_trustlist_readdr_size; j++){
				if (MAPP.mapTrust[i].i_trustlist[j].recom_addr == ih->saddr()){
					MAPP.mapTrust[i].i_trustlist[j].addr_size = rd->nb_num;
					for (int k = 0; k < rd->nb_num; k++){
						MAPP.mapTrust[i].i_trustlist[j].recom_trust[k].addr = rd->nbr[k];
						MAPP.mapTrust[i].i_trustlist[j].recom_trust[k].d_trust = rd->trust[k];
					}
					ok_j = true;
					break;
				}
			}
			if (!ok_j){
				MAPP.mapTrust[i].i_trustlist[MAPP.mapTrust[i].i_trustlist_readdr_size].recom_addr = ih->saddr();
				MAPP.mapTrust[i].i_trustlist[MAPP.mapTrust[i].i_trustlist_readdr_size].addr_size = rd->nb_num;
				for (int k = 0; k < rd->nb_num; k++){
					MAPP.mapTrust[i].i_trustlist[MAPP.mapTrust[i].i_trustlist_readdr_size].recom_trust[k].addr = rd->nbr[k];
					MAPP.mapTrust[i].i_trustlist[MAPP.mapTrust[i].i_trustlist_readdr_size].recom_trust[k].d_trust = rd->trust[k];
				}
				MAPP.mapTrust[i].i_trustlist_readdr_size++;
			}
			ok_i = true;
			break;
		}
	}
	if (!ok_i){
		MAPP.mapTrust[MAPP.map_num].nb_addr = index;
		MAPP.mapTrust[MAPP.map_num].i_trustlist_readdr_size = 1;
		MAPP.mapTrust[MAPP.map_num].i_trustlist[0].recom_addr = ih->saddr();
		MAPP.mapTrust[MAPP.map_num].i_trustlist[0].addr_size = rd->nb_num;
		for (int k = 0; k < rd->nb_num; k++){
			MAPP.mapTrust[MAPP.map_num].i_trustlist[0].recom_trust[k].addr = rd->nbr[k];
			MAPP.mapTrust[MAPP.map_num].i_trustlist[0].recom_trust[k].d_trust = rd->trust[k];
		}
		MAPP.map_num++;
	}
	if (badmouth == 1 or ballot == 1){
		for (int i = 0; i < MAPP.map_num; i++){
			if (MAPP.mapTrust[i].nb_addr == index){
				for (int j = 0; j < MAPP.mapTrust[i].d_trustlist_size; j++){
					if (badmouth == 1 && MAPP.mapTrust[i].d_trustlist[j].d_trust >= THRESHOLD){
						(MAPP.mapTrust[i].d_trustlist[j].d_trust -= THRESHOLD) *= (THRESHOLD / (1 - THRESHOLD));
					}
					if (ballot == 1 && MAPP.mapTrust[i].d_trustlist[j].d_trust < THRESHOLD){
						(MAPP.mapTrust[i].d_trustlist[j].d_trust *= ((1 - THRESHOLD) / THRESHOLD)) += THRESHOLD;
					}
				}
			}
		}
	}
	if (selfpromoting == 1){
		for (int i = 0; i < MAPP.map_num; i++){
			if (MAPP.mapTrust[i].nb_addr == index){
				bool self_ok = false;
				for (int j = 0; j < MAPP.mapTrust[i].d_trustlist_size; j++){
					if (MAPP.mapTrust[i].d_trustlist[j].addr == index){
						MAPP.mapTrust[i].d_trustlist[j].d_trust = 1.0;
						self_ok = true;
						break;
					}
				}
				if (!self_ok){
					MAPP.mapTrust[i].d_trustlist[MAPP.mapTrust[i].d_trustlist_size].addr = index;
					MAPP.mapTrust[i].d_trustlist[MAPP.mapTrust[i].d_trustlist_size++].d_trust = 1.0;
				}
			}
		}
	}
}
/*
   Neighbor Management Functions
*/

void
AODV2::sendHello() {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_reply *rh = HDR_AODV2_REPLY(p);

#ifdef DEBUG
fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 rh->rp_type = AODV2TYPE_HELLO;
 //rh->rp_flags = 0x00;
 rh->rp_hop_count = 1;
 rh->rp_dst = index;
 rh->rp_dst_seqno = seqno;
 rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

 // ch->uid() = 0;
 ch->ptype() = PT_AODV2;
 ch->size() = IP_HDR_LEN + rh->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV2 hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 Scheduler::instance().schedule(target_, p, 0.0);
}


void
AODV2::recvHello(Packet *p) {
//struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv2_reply *rp = HDR_AODV2_REPLY(p);
AODV2_Neighbor *nb;

 nb = nb_lookup(rp->rp_dst);
 if(nb == 0) {
   nb_insert(rp->rp_dst);
 }
 else {
   nb->nb_expire = CURRENT_TIME +
                   (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 }

 Packet::free(p);
}


void
AODV2::nb_insert(nsaddr_t id) {
AODV2_Neighbor *nb = new AODV2_Neighbor(id);

 assert(nb);
 nb->nb_expire = CURRENT_TIME +
                (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 LIST_INSERT_HEAD(&nbhead, nb, nb_link);
 seqno += 2;             // set of neighbors changed
 assert ((seqno%2) == 0);
}


AODV2_Neighbor*
AODV2::nb_lookup(nsaddr_t id) {
AODV2_Neighbor *nb = nbhead.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) break;
 }
 return nb;
}


/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void
AODV2::nb_delete(nsaddr_t id) {
AODV2_Neighbor *nb = nbhead.lh_first;

 log_link_del(id);
 seqno += 2;     // Set of neighbors changed
 assert ((seqno%2) == 0);

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) {
     LIST_REMOVE(nb,nb_link);
     delete nb;
     break;
   }
 }

 handle_link_failure(id);

}


/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void
AODV2::nb_purge() {
AODV2_Neighbor *nb = nbhead.lh_first;
AODV2_Neighbor *nbn;
double now = CURRENT_TIME;

 for(; nb; nb = nbn) {
   nbn = nb->nb_link.le_next;
   if(nb->nb_expire <= now || nb->nb_trust < THRESHOLD) {
     nb_delete(nb->nb_addr);
   }
 }
}
