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

The AODV2 code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems.
*/


#include <assert.h>

#include <cmu-trace.h>
#include <aodv2/aodv2_rqueue.h>

#define CURRENT_TIME    Scheduler::instance().clock()
#define QDEBUG

/*
  Packet Queue used by AODV2.
*/

aodv2_rqueue::aodv2_rqueue() {
  head_ = tail_ = 0;
  len_ = 0;
  limit_ = AODV2_RTQ_MAX_LEN;
  timeout_ = AODV2_RTQ_TIMEOUT;
}

void
aodv2_rqueue::enque(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);

 /*
  * Purge any packets that have timed out.
  */
 purge();
 
 p->next_ = 0;
 ch->ts_ = CURRENT_TIME + timeout_;

 if (len_ == limit_) {
 Packet *p0 = remove_head();	// decrements len_

   assert(p0);
   if(HDR_CMN(p0)->ts_ > CURRENT_TIME) {
     drop(p0, DROP_RTR_QFULL);
   }
   else {
     drop(p0, DROP_RTR_QTIMEOUT);
   }
 }
 
 if(head_ == 0) {
   head_ = tail_ = p;
 }
 else {
   tail_->next_ = p;
   tail_ = p;
 }
 len_++;
#ifdef QDEBUG
   verifyQueue();
#endif // QDEBUG
}
                

Packet*
aodv2_rqueue::deque() {
Packet *p;

 /*
  * Purge any packets that have timed out.
  */
 purge();

 p = remove_head();
#ifdef QDEBUG
 verifyQueue();
#endif // QDEBUG
 return p;

}


Packet*
aodv2_rqueue::deque(nsaddr_t dst) {
Packet *p, *prev;

 /*
  * Purge any packets that have timed out.
  */
 purge();

 findPacketWithDst(dst, p, prev);
 assert(p == 0 || (p == head_ && prev == 0) || (prev->next_ == p));

 if(p == 0) return 0;

 if (p == head_) {
   p = remove_head();
 }
 else if (p == tail_) {
   prev->next_ = 0;
   tail_ = prev;
   len_--;
 }
 else {
   prev->next_ = p->next_;
   len_--;
 }

#ifdef QDEBUG
 verifyQueue();
#endif // QDEBUG
 return p;

}

char 
aodv2_rqueue::find(nsaddr_t dst) {
Packet *p, *prev;  
	
 findPacketWithDst(dst, p, prev);
 if (0 == p)
   return 0;
 else
   return 1;

}

	
	

/*
  Private Routines
*/

Packet*
aodv2_rqueue::remove_head() {
Packet *p = head_;
        
 if(head_ == tail_) {
   head_ = tail_ = 0;
 }
 else {
   head_ = head_->next_;
 }

 if(p) len_--;

 return p;

}

void
aodv2_rqueue::findPacketWithDst(nsaddr_t dst, Packet*& p, Packet*& prev) {
  
  p = prev = 0;
  for(p = head_; p; p = p->next_) {
	  //		if(HDR_IP(p)->dst() == dst) {
	       if(HDR_IP(p)->daddr() == dst) {
      return;
    }
    prev = p;
  }
}


void
aodv2_rqueue::verifyQueue() {
Packet *p, *prev = 0;
int cnt = 0;

 for(p = head_; p; p = p->next_) {
   cnt++;
   prev = p;
 }
 assert(cnt == len_);
 assert(prev == tail_);

}


/*
void
aodv2_rqueue::purge() {
Packet *p;

 while((p = head_) && HDR_CMN(p)->ts_ < CURRENT_TIME) {
   // assert(p == remove_head());     
   p = remove_head();     
   drop(p, DROP_RTR_QTIMEOUT);
 }

}
*/

bool
aodv2_rqueue::findAgedPacket(Packet*& p, Packet*& prev) {
  
  p = prev = 0;
  for(p = head_; p; p = p->next_) {
    if(HDR_CMN(p)->ts_ < CURRENT_TIME) {
      return true;
    }
    prev = p;
  }
  return false;
}

void
aodv2_rqueue::purge() {
Packet *p, *prev;

 while ( findAgedPacket(p, prev) ) {
 	assert(p == 0 || (p == head_ && prev == 0) || (prev->next_ == p));

 	if(p == 0) return;

 	if (p == head_) {
   		p = remove_head();
 	}
 	else if (p == tail_) {
   		prev->next_ = 0;
   		tail_ = prev;
   		len_--;
 	}
 	else {
   		prev->next_ = p->next_;
   		len_--;
 	}
#ifdef QDEBUG
 	verifyQueue();
#endif // QDEBUG

	p = prev = 0;
 }

}

