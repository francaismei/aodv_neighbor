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


#include <aodv2/aodv2_rtable.h>
//#include <cmu/aodv2/aodv2.h>
#include <math.h>
/*
  The Routing Table
*/
#define WEIGHT_OF_DIRECT_TRUST 0.7
#define WEIGHT_OF_FORMER 0.3
#define WEIGHT_OF_ALTERATION 0.7
#define WEIGHT_OF_SELF 0.6
#define WEIGHT_OF_B 0.3
#define WEIGHT_OF_R 0.1
//#define fabs(A-B) (A)-(B)<0?(B)-(A):(A)-(B)
/*
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
*/
AODV2_Trust_Map MAPP;


AODV2_Neighbor::AODV2_Neighbor(u_int32_t a){
	nb_addr = a;
	nb_trust = 0.5;
	nb_comprehensive_trust = 0.5;
	nb_send = 0;
	nb_retrans = 0;
	nb_indirect_trust = 0.0;
	nb_domin = 0;
	nb_reces = 0;
	nb_internal_state = 1;
	for (int i = 0; i < MAPP.map_num; i++){
		if (MAPP.mapTrust[i].nb_addr == a){
			n_d_trustlist_size = MAPP.mapTrust[i].d_trustlist_size;
			for (int j = 0; j < n_d_trustlist_size; j++){
				if (MAPP.mapTrust[i].d_trustlist[j].addr == a) continue;	//deal with self-promoting attack
				n_d_trustlist[j].addr = MAPP.mapTrust[i].d_trustlist[j].addr;
				n_d_trustlist[j].d_trust = MAPP.mapTrust[i].d_trustlist[j].d_trust;
			}
			n_i_trustlist_readdr_size = MAPP.mapTrust[i].i_trustlist_readdr_size;
			for (int j = 0; j < n_i_trustlist_readdr_size; j++){
				n_i_trustlist[j].recom_addr = MAPP.mapTrust[i].i_trustlist[j].recom_addr;
				n_i_trustlist[j].addr_size = MAPP.mapTrust[i].i_trustlist[j].addr_size;
				//if (n_i_trustlist[j][0].recom_addr = MAPP.mapTrust[i].i_trustlist[j].recom_addr)
				for (int k = 0; k < n_i_trustlist[j].addr_size; k++){
					n_i_trustlist[j].recom_trust[k].addr = MAPP.mapTrust[i].i_trustlist[j].recom_trust[k].addr;
					n_i_trustlist[j].recom_trust[k].d_trust = MAPP.mapTrust[i].i_trustlist[j].recom_trust[k].d_trust;
				}
			}
		}
	}
}

AODV2_Trust::AODV2_Trust(u_int32_t a){
	nb_addr = a;
	d_trustlist_size = 0;
	i_trustlist_readdr_size = 0;
}
AODV2_Trust::AODV2_Trust(){
	nb_addr = 0;
	d_trustlist_size = 0;
	i_trustlist_readdr_size = 0;
}
aodv2_rt_entry::aodv2_rt_entry()
{
int i;

 rt_req_timeout = 0.0;
 rt_req_cnt = 0;

 rt_dst = 0;
 rt_seqno = 0;
 rt_hops = rt_last_hop_count = INFINITY2;
 rt_nexthop = 0;
 LIST_INIT(&rt_pclist);
 rt_expire = 0.0;
 rt_flags = RTF_DOWN;
 rt_path_trust = 0.5;
 /*
 rt_errors = 0;
 rt_error_time = 0.0;
 */


 for (i=0; i < MAX_HISTORY; i++) {
   rt_disc_latency[i] = 0.0;
 }
 hist_indx = 0;
 rt_req_last_ttl = 0;

 LIST_INIT(&rt_nblist);

}


aodv2_rt_entry::~aodv2_rt_entry()
{
AODV2_Neighbor *nb;

 while((nb = rt_nblist.lh_first)) {
   LIST_REMOVE(nb, nb_link);
   delete nb;
 }

AODV2_Precursor *pc;

 while((pc = rt_pclist.lh_first)) {
   LIST_REMOVE(pc, pc_link);
   delete pc;
 }

}



void
AODV2_Neighbor::set_nb_trust(){
	assert(nb_send);
	nb_trust = WEIGHT_OF_FORMER * nb_trust + WEIGHT_OF_ALTERATION * (nb_retrans * 1.0 / nb_send);
	//return nb_trust;
}

void
AODV2_Neighbor::set_nb_indirect_trust(nsaddr_t ind){
	double recom = 0.0;
	int recom_cnt = 0;
	for (int i = 0; i < n_i_trustlist_readdr_size; i++){
		for (int j = 0; j < n_i_trustlist[i].addr_size; j++){
			if (n_i_trustlist[i].recom_trust[j].addr == ind){
				recom = n_i_trustlist[i].recom_trust[j].d_trust;
				nb_indirect_trust += recom * nb_reliability(n_i_trustlist[i].recom_addr);
				recom_cnt++;
			}
		}
	}
	nb_indirect_trust /= recom_cnt;
}

double
AODV2_Neighbor::nb_reliability(nsaddr_t nb_id){
	double s_r = 0.0, b_r = 0.0, r_r = 0.0;
	for (int i = 0; i < n_i_trustlist_readdr_size; i++){
		if (n_i_trustlist[i].recom_addr == nb_id){
			for (int j = 0; j < n_i_trustlist[i].addr_size; j++){
				if (n_i_trustlist[i].recom_trust[j].addr == nb_addr){
					s_r = WEIGHT_OF_SELF * n_i_trustlist[i].recom_trust[j].d_trust;
				}
			}
		}
	}
	int b_r_cnt = 0, r_r_cnt = 0;
	for (int i = 0; i < n_d_trustlist_size; i++){
		for (int j = 0; j < n_i_trustlist_readdr_size; j++){
			if (n_i_trustlist[j].recom_addr == nb_id){
				for (int k = 0; k < n_i_trustlist[j].addr_size; k++){
					if (n_i_trustlist[j].recom_trust[k].addr == n_d_trustlist[i].addr){
						b_r += 1 - fabs(n_d_trustlist[i].d_trust - n_i_trustlist[j].recom_trust[k].d_trust);
						b_r_cnt++;
					}
				}
			}
		}
	}
	b_r = WEIGHT_OF_B * b_r / b_r_cnt;
	for (int i = 0; i < n_i_trustlist_readdr_size; i++){
		if (n_i_trustlist[i].recom_addr == nb_id){
			for (int j = 0; j < n_i_trustlist[i].addr_size; j++){
				for (int k = 0; k < n_i_trustlist_readdr_size; k++){
					if (n_i_trustlist[k].recom_addr == nb_id) continue;
					for (int m = 0; m < n_i_trustlist[k].addr_size; m++){
						if (n_i_trustlist[i].recom_trust[j].addr == n_i_trustlist[k].recom_trust[m].addr){
							r_r += 1 - fabs(n_i_trustlist[i].recom_trust[j].d_trust - n_i_trustlist[k].recom_trust[m].d_trust);
							r_r_cnt++;
						}
					}
				}
			}
		}
	}
	r_r = WEIGHT_OF_R * r_r / r_r_cnt;
	return s_r + b_r + r_r;
}
void
AODV2_Neighbor::set_nb_comprehensive_trust(){
	nb_comprehensive_trust = WEIGHT_OF_DIRECT_TRUST * nb_trust
										+ (1 - WEIGHT_OF_DIRECT_TRUST) * nb_indirect_trust;
}
void
AODV2_Neighbor::set_nb_internal_state(){
	if (nb_domin >= nb_reces){
		nb_internal_state = 1;
	}
	else{
		nb_internal_state = 0;
	}
}
void
aodv2_rt_entry::nb_insert(nsaddr_t id)
{
AODV2_Neighbor *nb = new AODV2_Neighbor(id);
        
 assert(nb);
 nb->nb_expire = 0;
 LIST_INSERT_HEAD(&rt_nblist, nb, nb_link);

}
/*
int
aodv_rt_entry::nb_num()
{
	int num = 0;
	AODV2_Neighbor *nb = rt_nblist.lh_first;
	for (; nb; nb = nb->nb_link.le_next) {
		num++;
	}
	return num;
}
//03/10/2019
*/

AODV2_Neighbor*
aodv2_rt_entry::nb_lookup(nsaddr_t id)
{
AODV2_Neighbor *nb = rt_nblist.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id)
     break;
 }
 return nb;

}


void
aodv2_rt_entry::pc_insert(nsaddr_t id)
{
	if (pc_lookup(id) == NULL) {
	AODV2_Precursor *pc = new AODV2_Precursor(id);
        
 		assert(pc);
 		LIST_INSERT_HEAD(&rt_pclist, pc, pc_link);
	}
}


AODV2_Precursor*
aodv2_rt_entry::pc_lookup(nsaddr_t id)
{
AODV2_Precursor *pc = rt_pclist.lh_first;

 for(; pc; pc = pc->pc_link.le_next) {
   if(pc->pc_addr == id)
   	return pc;
 }
 return NULL;

}

void
aodv2_rt_entry::pc_delete(nsaddr_t id) {
AODV2_Precursor *pc = rt_pclist.lh_first;

 for(; pc; pc = pc->pc_link.le_next) {
   if(pc->pc_addr == id) {
     LIST_REMOVE(pc,pc_link);
     delete pc;
     break;
   }
 }

}

void
aodv2_rt_entry::pc_delete(void) {
AODV2_Precursor *pc;

 while((pc = rt_pclist.lh_first)) {
   LIST_REMOVE(pc, pc_link);
   delete pc;
 }
}	

bool
aodv2_rt_entry::pc_empty(void) {
AODV2_Precursor *pc;

 if ((pc = rt_pclist.lh_first)) return false;
 else return true;
}	

/*
  The Routing Table
*/

aodv2_rt_entry*
aodv2_rtable::rt_lookup(nsaddr_t id)
{
aodv2_rt_entry *rt = rthead.lh_first;

 for(; rt; rt = rt->rt_link.le_next) {
   if(rt->rt_dst == id)
     break;
 }
 return rt;

}

void
aodv2_rtable::rt_delete(nsaddr_t id)
{
aodv2_rt_entry *rt = rt_lookup(id);

 if(rt) {
   LIST_REMOVE(rt, rt_link);
   delete rt;
 }

}

aodv2_rt_entry*
aodv2_rtable::rt_add(nsaddr_t id)
{
aodv2_rt_entry *rt;

 assert(rt_lookup(id) == 0);
 rt = new aodv2_rt_entry;
 assert(rt);
 rt->rt_dst = id;
 LIST_INSERT_HEAD(&rthead, rt, rt_link);
 return rt;
}
