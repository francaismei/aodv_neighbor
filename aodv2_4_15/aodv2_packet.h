/*
 * aodv2_packet.h
 *
 *  Created on: Feb 22, 2019
 *      Author: root
 */
//#include <vector>
//using namespace std;
#ifndef __aodv2_packet_h__
#define __aodv2_packet_h__
#define AODV2_MAX_ERRORS 100


/* =====================================================================
   Packet Formats...
   ===================================================================== */
#define AODV2TYPE_HELLO  	0x01
#define AODV2TYPE_RREQ   	0x02
#define AODV2TYPE_RREP   	0x04
#define AODV2TYPE_RERR   	0x08
#define AODV2TYPE_RREP_ACK  	0x10
// new packet 03/09/2019
#define AODV2TYPE_RCMD	0x03


/*
 * aodv2 Routing Protocol Header Macros
 */
#define HDR_AODV2(p)		((struct hdr_aodv2*)hdr_aodv2::access(p))
#define HDR_AODV2_REQUEST(p)  	((struct hdr_aodv2_request*)hdr_aodv2::access(p))
#define HDR_AODV2_REPLY(p)	((struct hdr_aodv2_reply*)hdr_aodv2::access(p))
#define HDR_AODV2_ERROR(p)	((struct hdr_aodv2_error*)hdr_aodv2::access(p))
#define HDR_AODV2_RREP_ACK(p)	((struct hdr_aodv2_rrep_ack*)hdr_aodv2::access(p))

#define HDR_AODV2_RCMD(p)	((struct hdr_aodv2_rcmd*)hdr_aodv2::access(p))
/*
 * General aodv2 Header - shared by all formats
 */

#define MAX_NEIGHBOR	50

struct hdr_aodv2 {
        u_int8_t        ah_type;
	/*
        u_int8_t        ah_reserved[2];
        u_int8_t        ah_hopcount;
	*/
		// Header access methods
	static int offset_; // required by PacketHeaderManager
	inline static int& offset() { return offset_; }
	inline static hdr_aodv2* access(const Packet* p) {
		return (hdr_aodv2*) p->access(offset_);
	}
};

struct hdr_aodv2_request {
        u_int8_t        rq_type;	// Packet Type
        u_int8_t        reserved[2];
        u_int8_t        rq_hop_count;   // Hop Count
        u_int32_t       rq_bcast_id;    // Broadcast ID

        nsaddr_t        rq_dst;         // Destination IP Address
        u_int32_t       rq_dst_seqno;   // Destination Sequence Number
        nsaddr_t        rq_src;         // Source IP Address
        u_int32_t       rq_src_seqno;   // Source Sequence Number

        double          rq_timestamp;   // when REQUEST sent;
					// used to compute route discovery latency

  // This define turns on gratuitous replies- see aodv2.cc for implementation contributed by
  // Anant Utgikar, 09/16/02.
  //#define RREQ_GRAT_RREP	0x80

  inline int size() {
  int sz = 0;
  /*
  	sz = sizeof(u_int8_t)		// rq_type
	     + 2*sizeof(u_int8_t) 	// reserved
	     + sizeof(u_int8_t)		// rq_hop_count
	     + sizeof(double)		// rq_timestamp
	     + sizeof(u_int32_t)	// rq_bcast_id
	     + sizeof(nsaddr_t)		// rq_dst
	     + sizeof(u_int32_t)	// rq_dst_seqno
	     + sizeof(nsaddr_t)		// rq_src
	     + sizeof(u_int32_t);	// rq_src_seqno
  */
  	sz = 7*sizeof(u_int32_t);
  	assert (sz >= 0);
	return sz;
  }
};

struct hdr_aodv2_reply {
        u_int8_t        rp_type;        // Packet Type
        u_int8_t        reserved[2];
        u_int8_t        rp_hop_count;           // Hop Count
        nsaddr_t        rp_dst;                 // Destination IP Address
        u_int32_t       rp_dst_seqno;           // Destination Sequence Number
        nsaddr_t        rp_src;                 // Source IP Address
        double	        rp_lifetime;            // Lifetime

        double          rp_timestamp;           // when corresponding REQ sent;
						// used to compute route discovery latency

  inline int size() {
  int sz = 0;
  /*
  	sz = sizeof(u_int8_t)		// rp_type
	     + 2*sizeof(u_int8_t) 	// rp_flags + reserved
	     + sizeof(u_int8_t)		// rp_hop_count
	     + sizeof(double)		// rp_timestamp
	     + sizeof(nsaddr_t)		// rp_dst
	     + sizeof(u_int32_t)	// rp_dst_seqno
	     + sizeof(nsaddr_t)		// rp_src
	     + sizeof(u_int32_t);	// rp_lifetime
  */
  	sz = 6*sizeof(u_int32_t);
  	assert (sz >= 0);
	return sz;
  }

};

struct hdr_aodv2_error {
        u_int8_t        re_type;                // Type
        u_int8_t        reserved[2];            // Reserved
        u_int8_t        DestCount;                 // DestCount
        // List of Unreachable destination IP addresses and sequence numbers
        nsaddr_t        unreachable_dst[AODV2_MAX_ERRORS];
        u_int32_t       unreachable_dst_seqno[AODV2_MAX_ERRORS];

  inline int size() {
  int sz = 0;
  /*
  	sz = sizeof(u_int8_t)		// type
	     + 2*sizeof(u_int8_t) 	// reserved
	     + sizeof(u_int8_t)		// length
	     + length*sizeof(nsaddr_t); // unreachable destinations
  */
  	sz = (DestCount*2 + 1)*sizeof(u_int32_t);
	assert(sz);
        return sz;
  }

};

struct hdr_aodv2_rrep_ack {
	u_int8_t	rpack_type;
	u_int8_t	reserved;
};

struct hdr_aodv2_rcmd {
	u_int8_t	rc_type;
	u_int8_t    reserved[2];
	nsaddr_t	nbr[MAX_NEIGHBOR];
	double		trust[MAX_NEIGHBOR];
	u_int8_t 	nb_num;

	inline int size(){
	int sz = 0;
	/*
	 * sz = sizeof(u_int8_t)
	 * + nb_num *sizeof(u_int32_t)
	 * + sizeof(u_int8_t)
	 * + 2* sizeof(u_int8_t);
	 */
	sz = (nb_num * 2 + 1) * sizeof(u_int32_t);
	assert(sz);
		return sz;
	}

};

// for size calculation of header-space reservation
union hdr_all_aodv2 {
  hdr_aodv2          ah;
  hdr_aodv2_request  rreq;
  hdr_aodv2_reply    rrep;
  hdr_aodv2_error    rerr;
  hdr_aodv2_rrep_ack rrep_ack;
  hdr_aodv2_rcmd	 rcmd;
};



#endif /* __aodv2_packet_h__ */
