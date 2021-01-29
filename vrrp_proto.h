/*
 * Copyright (c) 2001,2002 Sebastien Petit <spe@bsdfr.org>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: vrrp_proto.h,v 1.14 2004/03/30 23:45:28 rival Exp $
 */

#ifndef _VRRP_PROTO_H
#define _VRRP_PROTO_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef __FreeBSD__
#include <net/ethernet.h>
#endif
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif
#ifdef __OpenBSD__
#include <netinet/if_ether.h>
#endif
#include "vrrp_define.h"

/* RFC 2338 vrrp header */
struct vrrp_hdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int           vrrp_t:4, vrrp_v:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int           vrrp_v:4, vrrp_t:4;
#endif
	u_char          vr_id;
	u_char          priority;
	u_char          cnt_ip;
	u_char          auth_type;
	u_char          adv_int;
	u_short         csum;
	/* Some IP adresses, number are not defined */
	/*
	 * After IP adresses, we can found Authentification Data 1 & 2 (total
	 * of 8 bytes)
	 */
};

struct vrrp_if {
	char            if_name[IFNAMSIZ];
	u_char          nb_ip;
	int		alive;
	int		nberrors;
	int		checksok;
	int		reportsyslog;
	struct in_addr  ip_addrs[MAX_IP_ALIAS];
	struct ether_addr ethaddr;
	struct ether_addr actualethaddr;
	struct vrrp_ethaddr_list *p, *d;
	struct vrrp_vlan_list *vlanp, *vland;
	int		carrier_timeout;
};

struct vrrp_vip {
	struct in_addr  addr;
	u_char          owner;
};

/* Timers RFC2338-6.2 */
struct vrrp_timer {
	struct timeval  master_down_tm;
	struct timeval  adv_tm;
};

/*
 * Parameters per Virtual Router RFC2338-6.1.2 and
 * draft-ietf-vrrp-spec-v2-05.txt
 */
struct vrrp_vr {
	u_char          vr_id;
	u_char          priority;
	int             sd;
	int		ioctl_sd;			/* socket used to pass ioctl */
	struct ether_addr ethaddr;
	struct ether_addr backupethaddr;
	u_char          cnt_ip;
	struct vrrp_vip *vr_ip;
	u_int          *vr_netmask;
	u_char          adv_int;
	u_int           master_down_int;
	u_int           skew_time;
	struct vrrp_timer tm;
	u_char          preempt_mode;	/* False = 0, True = 1 */
	u_char          state;	/* 0 = INITIALIZE, 1 = MASTER, 2 = BACKUP */
	u_char          auth_type;
	u_char          auth_data[VRRP_AUTH_DATA_LEN];
	struct vrrp_if *vr_if;
	char		viface_name[IFNAMSIZ]; /* Real interface name for vrrp announces */
	char		bridgeif_name[IFNAMSIZ]; /* Bridge interface name passed to script */
	int		bridge_link_number;
#ifdef ENABLE_VRRP_AH
	struct ah_header *ahctx;
#endif
	char           *password;
	char           *master_script;
	char           *backup_script;
	char           *state_script;
	int	       *vridsdeps;
	int		fault;
	int		useIKE;
	int		useMonitoredCircuits;
	int		AHencryption;
	int		sendGratuitousArp;
	int		spanningTreeLatency;
	int		monitoredCircuitsClearErrorsCount;
};

struct vrrp_ethaddr_list {
	struct ether_addr ethaddr;
	struct vrrp_ethaddr_list *next;
	struct vrrp_ethaddr_list *previous;
};

struct vrrp_vlan_list {
	char vlan_ifname[IFNAMSIZ];
	struct vrrp_vlan_list *next;
	struct vrrp_vlan_list *previous;
};

#endif
