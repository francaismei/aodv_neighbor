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


#ifndef __aodv2_rtable_h__
#define __aodv2_rtable_h__

#include <assert.h>
#include <sys/types.h>
#include <config.h>
#include <lib/bsd-list.h>
#include <scheduler.h>
//using namespace std;
#define CURRENT_TIME    Scheduler::instance().clock()
#define INFINITY2        0xff

#define MAXNEIGHBOR	50
struct setDT{
	nsaddr_t addr;
	double d_trust;
};
struct setIT{
	nsaddr_t recom_addr;
	setDT recom_trust[MAXNEIGHBOR];
	int addr_size;
};
/*
   AODV2 Neighbor Cache Entry
*/

class AODV2_Trust{
	friend class AODV2;
	friend class AODV2_Neighbor;
	friend class aodv2_rt_entry;
public:
	AODV2_Trust(u_int32_t a);
	AODV2_Trust();
protected:
	u_int32_t nb_addr;
	setDT d_trustlist[MAXNEIGHBOR];
	int	d_trustlist_size;
	setIT i_trustlist[MAXNEIGHBOR];
	int i_trustlist_readdr_size;
};

//AODV2_Trust mapTrust[MAXNEIGHBOR];

class AODV2_Trust_Map{
	friend class AODV2;
	friend class AODV2_Neighbor;
	friend class aodv2_rt_entry;
public:
	AODV2_Trust_Map(){map_num = 0;}
protected:
	AODV2_Trust mapTrust[MAXNEIGHBOR];
	int map_num;
};


class AODV2_Neighbor {
        friend class AODV2;
        friend class aodv2_rt_entry;
        friend class AODV2_Trust_Map;
 public:
        AODV2_Neighbor(u_int32_t a);
        void set_nb_trust();
        double nb_reliability(nsaddr_t nb_id);
        void inc_nb_send() {
        	nb_trust++;
        }
        void inc_nb_retrans(){
        	nb_retrans++;
        }
        void inc_nb_domin(){
        	nb_domin++;
        }
        void inc_nb_reces(){
        	nb_reces++;
        }
        void set_nb_indirect_trust(nsaddr_t ind);
        void set_nb_comprehensive_trust();
        void set_nb_internal_state();
 protected:
        LIST_ENTRY(AODV2_Neighbor) nb_link;
        nsaddr_t        nb_addr;
        double			nb_trust;
        double			nb_indirect_trust;
        double			nb_comprehensive_trust;
        int			nb_send;
        int			nb_retrans;
        int			nb_domin;
        int			nb_reces;
        int			nb_internal_state;
        double		reliab;
        //int				nb_num;
        double          nb_expire;      // ALLOWED_HELLO_LOSS * HELLO_INTERVAL

        setDT n_d_trustlist[MAXNEIGHBOR];
		int	n_d_trustlist_size;
		setIT n_i_trustlist[MAXNEIGHBOR];
		int n_i_trustlist_readdr_size;
};

LIST_HEAD(aodv2_ncache, AODV2_Neighbor);

/*
   AODV2 Precursor list data structure
*/
class AODV2_Precursor {
        friend class AODV2;
        friend class aodv2_rt_entry;
 public:
        AODV2_Precursor(u_int32_t a) { pc_addr = a; }

 protected:
        LIST_ENTRY(AODV2_Precursor) pc_link;
        nsaddr_t        pc_addr;	// precursor address
};

LIST_HEAD(aodv2_precursors, AODV2_Precursor);


/*
  Route Table Entry
*/

class aodv2_rt_entry {
        friend class aodv2_rtable;
        friend class AODV2;
	friend class AODV2LocalRepairTimer;
 public:
        aodv2_rt_entry();
        ~aodv2_rt_entry();

        void            nb_insert(nsaddr_t id);
        AODV2_Neighbor*  nb_lookup(nsaddr_t id);
        //int				nb_num();
        void            pc_insert(nsaddr_t id);
        AODV2_Precursor* pc_lookup(nsaddr_t id);
        void 		pc_delete(nsaddr_t id);
        void 		pc_delete(void);
        bool 		pc_empty(void);

        double          rt_req_timeout;         // when I can send another req
        u_int8_t        rt_req_cnt;             // number of route requests

 protected:
        LIST_ENTRY(aodv2_rt_entry) rt_link;

        nsaddr_t        rt_dst;
        u_int32_t       rt_seqno;
	/* u_int8_t 	rt_interface; */
        u_int16_t       rt_hops;       		// hop count
	int 		rt_last_hop_count;	// last valid hop count
        nsaddr_t        rt_nexthop;    		// next hop IP address
	/* list of precursors */ 
        aodv2_precursors rt_pclist;
        double          rt_expire;     		// when entry expires
        u_int8_t        rt_flags;
        double  rt_path_trust;

#define RTF_DOWN 0
#define RTF_UP 1
#define RTF_IN_REPAIR 2

        /*
         *  Must receive 4 errors within 3 seconds in order to mark
         *  the route down.
        u_int8_t        rt_errors;      // error count
        double          rt_error_time;
#define MAX_RT_ERROR            4       // errors
#define MAX_RT_ERROR_TIME       3       // seconds
         */

#define MAX_HISTORY	3
	double 		rt_disc_latency[MAX_HISTORY];
	char 		hist_indx;
        int 		rt_req_last_ttl;        // last ttl value used
	// last few route discovery latencies
	// double 		rt_length [MAX_HISTORY];
	// last few route lengths

        /*
         * a list of neighbors that are using this route.
         */
        aodv2_ncache          rt_nblist;
};


/*
  The Routing Table
*/

class aodv2_rtable {
 public:
	aodv2_rtable() { LIST_INIT(&rthead); }

        aodv2_rt_entry*       head() { return rthead.lh_first; }

        aodv2_rt_entry*       rt_add(nsaddr_t id);
        void                 rt_delete(nsaddr_t id);
        aodv2_rt_entry*       rt_lookup(nsaddr_t id);

 private:
        LIST_HEAD(aodv2_rthead, aodv2_rt_entry) rthead;
};

#endif /* _aodv2__rtable_h__ */
