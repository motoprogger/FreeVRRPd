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
 * $Id: vrrp_functions.h,v 1.8 2004/04/02 11:04:46 spe Exp $
 */

#include <net/route.h>
#include <stdio.h>

/* vrrp_state.c functions */
char            vrrp_state_initialize(struct vrrp_vr *);
char            vrrp_state_set_master(struct vrrp_vr *);
char            vrrp_state_set_backup(struct vrrp_vr *);
char            vrrp_state_check_priority(struct vrrp_hdr *, struct vrrp_vr *, struct in_addr);
char            vrrp_state_master(struct vrrp_vr *);
char            vrrp_state_backup(struct vrrp_vr *);

/* vrrp_network.c functions */
char            vrrp_network_open_socket(struct vrrp_vr *);
ssize_t         vrrp_network_send_packet(char *, int, int, int);
u_int           vrrp_network_vrrphdr_len(struct vrrp_vr *);
void            vrrp_network_init_ethhdr(char *, struct vrrp_vr *);
void            vrrp_network_init_iphdr(char *, struct vrrp_vr *);
void            vrrp_network_init_vrrphdr(char *, struct vrrp_vr *);
char            vrrp_network_send_advertisement(struct vrrp_vr *);
int		vrrp_network_send_gratuitous_arp(char *, struct ether_addr *, struct in_addr);
int             vrrp_network_send_gratuitous_arp_ips(struct vrrp_vr *, struct ether_addr *);
int             vrrp_network_send_gratuitous_arp_ipaddrs(struct vrrp_vr *, struct ether_addr *);
char            vrrp_network_delete_local_route(struct in_addr);

/* vrrp_misc.c functions */
void            rt_xaddrs(caddr_t, caddr_t, struct rt_addrinfo *);
char            vrrp_misc_get_if_infos(char *, struct ether_addr *, struct in_addr *, int *);
char            vrrp_misc_get_vlan_infos(struct vrrp_vr *);
int             vrrp_misc_get_priority(struct vrrp_vr *);
u_int16_t       vrrp_misc_compute_checksum(u_int16_t *, int);
char            vrrp_misc_calcul_tminterval(struct timeval *, u_int);
char            vrrp_misc_calcul_tmrelease(struct timeval *, struct timeval *);
char            vrrp_misc_check_vrrp_packet(struct vrrp_vr *, char *, ssize_t);
void            vrrp_misc_quit(int);
struct vrrp_if *vrrp_misc_search_if_entry(char *);

/* vrrp_conf.c functions */
int             vrrp_conf_ident_option_arg(char *, char *, char *);
char          **vrrp_conf_split_args(char *, char);
void            vrrp_conf_freeargs(char **);
char            vrrp_conf_lecture_fichier(struct vrrp_vr *, FILE *);
FILE           *vrrp_conf_open_file(char *);

/* vrrp_multicast.c functions */
char            vrrp_multicast_join_group(int, u_char *, struct in_addr *);
char            vrrp_multicast_set_ttl(int, u_char);
char            vrrp_multicast_set_if(int, struct in_addr *, char *);
char            vrrp_multicast_set_socket(struct vrrp_vr *);
char            vrrp_multicast_open_socket(struct vrrp_vr *);

/* vrrp_signal.c functions */
void            vrrp_signal_initialize(void);
void            vrrp_signal_quit(int);
void            vrrp_signal_shutdown(int);

/* vrrp_list.c functions */
char            vrrp_list_initialize(struct vrrp_vr *, struct ether_addr *);
char            vrrp_list_add(struct vrrp_vr *, struct ether_addr *);
char            vrrp_list_delete(struct vrrp_vr *, struct ether_addr);
struct ether_addr vrrp_list_get_last(struct vrrp_vr *);
struct ether_addr vrrp_list_get_first(struct vrrp_vr *);

/* vrrp_vlanlist.c functions */
char            vrrp_vlanlist_initialize(struct vrrp_vr *);
char            vrrp_vlanlist_add(struct vrrp_vr *, char *);
char            vrrp_vlanlist_delete(struct vrrp_vr *, char *);
char *vrrp_vlanlist_get_last(struct vrrp_vr *);
char *vrrp_vlanlist_get_first(struct vrrp_vr *);

/* vrrp_thread.c functions */
void            vrrp_thread_mutex_lock(void);
void            vrrp_thread_mutex_unlock(void);
void            *vrrp_thread_launch_vrrprouter(void *);
char            vrrp_thread_initialize(void);
char            vrrp_thread_create_vrid(struct vrrp_vr *);

/* vrrp_script functions */
int		vrrp_script_run(struct vrrp_vr * vr, const char* verb);

