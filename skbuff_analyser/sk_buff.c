#include <linux/kernel.h>
#include <linux/module.h>
#include <uapi/linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h> // for mac header
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h> //  for inet_select_addr()
#include <linux/if.h>

#define AUTHOR_NAME "ABHISHEK_SAGAR"
#define MODULE_DESC "TCP_STACK_WALK_THROUGH"

MODULE_AUTHOR(AUTHOR_NAME); /* Who wrote this module? */
MODULE_DESCRIPTION(MODULE_DESC); /* What does this module do */

int init_module(void);
void cleanup_module(void);

/*struct nf_hook_ops defined in linux/netfilter.h*/
static struct nf_hook_ops netfilter_ops_pre_routing; /* NF_IP_PRE_ROUTING , defined in uapi/linux/netfilter_ipv4.h*/
static struct nf_hook_ops netfilter_ops_post_routing; /* NF_IP_POST_ROUTING */
static struct nf_hook_ops netfilter_ops_local_in;
static struct nf_hook_ops netfilter_ops_forward;
static struct nf_hook_ops netfilter_ops_localout;


#if 1
/* Not able to include from header file for some reason */
#define NF_IP_PRE_ROUTING  	0
#define NF_IP_LOCAL_IN 	   	1
#define NF_IP_FORWARD      	2
#define NF_IP_LOCAL_OUT    	3
#define NF_IP_POST_ROUTING 	4
#endif


#define UDP_PROTO 17
#define TCP_PROTO  6
#define ICMP_PROTO 1
#define IPPROTO_IGMP 140
#define IPPROTO_PIM 141
#define SSH_DEF_PORT_NO 22


typedef enum{
        IGMP_REPORTS = 0,
        IGMP_QUERY,
        IGMP_LEAVE,
        PIM_HELLO,
        PIM_JOIN,
        PIM_REGISTER
} pkt_type;

typedef struct igmp_hdr{
        pkt_type type;
        unsigned int seqno;
        char rawdata[32];
} igmp_hdr_t;;


#define IGMP_TP_HEADER_SIZE     (sizeof(igmp_hdr_t))

typedef struct pim_hdr{
        pkt_type type;
        unsigned int seqno;
        char rawdata[32];
} pim_hdr_t;;

#define PIM_TP_HEADER_SIZE      (sizeof(pim_hdr_t))



static 
char *getDotDecimalIpV4(unsigned long int ip, char *buffer)
{
	unsigned char bytes[4];
	memset(buffer, 0, 16);
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	sprintf(buffer, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	return buffer;
}


static 
void net_device_analyser(const struct net_device *iif){

	/* http://codingforpleasure.blogspot.com/2012/10/netdevice-who-are-you.html*/
	struct net_device_stats ifstats; // linux/netdevice.h
	unsigned long net_device_addr = 0; // ip address of device
	struct netdev_hw_addr *ha;  // mac address of device
	char ipv4_str[16];	
	struct net *net = NULL;
	struct in_device *indev = NULL; // ipv4 related config on this device
	net = dev_net(iif);  // linux/netdevice.h
	indev = in_dev_get(iif);   /* pg 440, christian*/
	/* When we are done with the indev, call in_dev_put(indev) to releae indev*/
	in_dev_put(indev);
	/* page 441, christian, the netdevice L4 checksum capabilities*/
	netdev_features_t features;
	features = iif->features;

	
	printk(KERN_ALERT "	net_device analyser:\n");
	printk(KERN_ALERT "	Recieving Interface Information\n");	
        printk(KERN_ALERT "		ifname  = %s\n", iif->name);
	printk(KERN_ALERT "		ifindex = %d\n", iif->ifindex);
	printk(KERN_ALERT "		mtu     = %d\n", iif->mtu);

	ifstats = iif->stats;
	printk(KERN_ALERT "		statistics:\n");
	printk(KERN_ALERT "			rx_packets		= %lu\n", ifstats.rx_packets);
        printk(KERN_ALERT "			tx_packets		= %lu\n", ifstats.tx_packets);
        printk(KERN_ALERT "			rx_bytes		= %lu\n", ifstats.rx_bytes);
        printk(KERN_ALERT "			tx_bytes		= %lu\n", ifstats.tx_bytes);
        printk(KERN_ALERT "			rx_errors		= %lu\n", ifstats.rx_errors);
        printk(KERN_ALERT "			tx_errors		= %lu\n", ifstats.tx_errors);
	printk(KERN_ALERT "			rx_dropped		= %lu\n", ifstats.rx_dropped);
	printk(KERN_ALERT "			tx_dropped		= %lu\n", ifstats.tx_dropped);
//        printk(KERN_ALERT "			multicast		= %lu\n", ifstats.multicast);
        printk(KERN_ALERT "			collisions		= %lu\n", ifstats.collisions);
        printk(KERN_ALERT "			rx_errors		= %lu\n", ifstats.rx_errors);
        printk(KERN_ALERT "			tx_errors		= %lu\n", ifstats.tx_errors);
//        printk(KERN_ALERT "			rx_length_errors 	= %lu\n", ifstats.rx_length_errors);

//        printk(KERN_ALERT "			rx_over_errors		= %lu\n", ifstats.rx_over_errors);
        printk(KERN_ALERT "			rx_crc_errors		= %lu\n", ifstats.rx_crc_errors);
//        printk(KERN_ALERT "			rx_frame_errors		= %lu\n", ifstats.rx_frame_errors);
//        printk(KERN_ALERT "			rx_missed_errors	= %lu\n", ifstats.rx_missed_errors);

	printk(KERN_ALERT "		Hardware type =	%d\n", iif->type); 
	/* Most utilities related to manipulating mac addresses are in linux/etherdevice.h*/
#if 0
	for_each_dev_addr(iif, ha){
		printk(KERN_ALERT "		Mac Addr      = %s\n", ha->addr); 
	}
#endif

	printk(KERN_ALERT "		Mac Addr	     = %pMF\n", iif->dev_addr); 
	printk(KERN_ALERT "		Broadcast  Addr      = %pMF\n", iif->broadcast);	
	net_device_addr = inet_select_addr(iif, 0, 0);
	printk(KERN_ALERT "		ip address = %s\n", getDotDecimalIpV4(htonl(net_device_addr), ipv4_str)); 

	printk(KERN_ALERT "	Interface State\n");
	if(iif->flags | IFF_UP)  //  these flags are defined in linux/if.h
		printk(KERN_ALERT "		If is up\n");
	else
		printk(KERN_ALERT "		If is down\n");

	if(iif->flags | IFF_LOOPBACK)
		printk(KERN_ALERT "		If is loopback\n");
	else
		printk(KERN_ALERT "		If is not loopback\n");

	 if(iif->flags | IFF_MULTICAST)
		printk(KERN_ALERT "		if support multicast\n");
	 else
		printk(KERN_ALERT " 		if do not support multicast\n");
	
	 if(iif->flags | IFF_RUNNING)
		printk(KERN_ALERT "		if is up and running\n");
	 else
		printk(KERN_ALERT "		if is not running\n");
	
	return;

}

char*
get_string(unsigned int arg){
        switch(arg){
                case IPPROTO_IGMP:
                        return "_IPPROTO_IGMP";
                case IPPROTO_PIM:
                        return "_IPPROTO_PIM";
                case IGMP_REPORTS:
                        return "IGMP_REPORTS";
                case IGMP_QUERY:
                        return "IGMP_QUERY";
                case IGMP_LEAVE:
                        return "IGMP_LEAVE";
                case PIM_HELLO:
                        return "PIM_HELLO";
                case  PIM_JOIN:
                        return "PIM_JOIN";
                case PIM_REGISTER:
                        return "PIM_REGISTER";
                default:
                        break;
        }
        return NULL;
}


unsigned int
ignore_ssh_pkts(struct sk_buff *skb){
	struct iphdr  *ip_header = NULL; 
	unsigned long int src_port = 0, dst_port = 0;
	unsigned char* tphdr_ptr = NULL;
	struct udphdr *udp_header = NULL;
	struct tcphdr *tcp_header = NULL;

	if(skb == NULL){
                printk(KERN_ALERT "     skb is NULL\n");
                return 0;
        }

	ip_header = (struct iphdr *)skb_network_header(skb);
	tphdr_ptr = skb_transport_header(skb);

	if(ip_header == NULL)
		return 0;
	
	switch(ip_header->protocol){
		case UDP_PROTO:
			udp_header = (struct udphdr *)tphdr_ptr;
			src_port  = (unsigned int)ntohs(udp_header->source);
                        dst_port = (unsigned int)ntohs(udp_header->dest);
		break;
		case TCP_PROTO:
			tcp_header = (struct tcphdr *)tphdr_ptr;
			src_port   = (unsigned int)ntohs(tcp_header->source);
                        dst_port  = (unsigned int)ntohs(tcp_header->dest);
		break;
		default:
		break;
	}// switch ends		

	if(src_port == SSH_DEF_PORT_NO || dst_port == SSH_DEF_PORT_NO)
		return NF_ACCEPT;
	
	return 0;
}


static
void skb_analyser(struct sk_buff *skb){
	/* Nice info is here : http://vger.kernel.org/~davem/skb.html
	and here : 
	http://amsekharkernel.blogspot.in/2014/08/what-is-skb-in-linux-kernel-what-are.html
	*/
	
	char ipv4_str[16];
	unsigned char* tphdr_ptr = NULL; // transport layer header ptr
	struct ethhdr *machdr_ptr = NULL;// mac hdr pntr

	struct iphdr  *ip_header = NULL;  /* Network layer header pointer, uapi/linux/ip.h */
	struct udphdr *udp_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct icmphdr *icmp_header = NULL;
	igmp_hdr_t *igmphdr = NULL;
	pim_hdr_t *pimhdr = NULL;

	unsigned long int src_ip , dst_ip = 0, src_port = 0, dst_port = 0;

	struct timeval *stamp = NULL;   // timestamp of recieving the pkt


	printk(KERN_ALERT "skb_analyser():\n");
	if(skb == NULL){
		printk(KERN_ALERT "	skb is NULL\n");
		return;
	}

/*kernel crashing while fetching the timestamp of the pkt, hence comment out as of now*/		
#if 0
	skb_get_timestamp(skb, stamp);  // fill stamp with the timestamp
	if(stamp){
		printk(KERN_ALERT "	pkt recieve timestamp is fetched\n"); // will print later
	}
	else{
		printk(KERN_ALERT "     pkt recieve timestamp could not be fetched\n");
	}
#endif
/* Note that the value assigned to the protocol field of the IPv4 header when it encapsulates an IP datagram has nothing to do with the value
used to initialize the protocol field of an Ethernet header when the Ethernet payload is an IPdatagram. Even though the two fields refer to the same protocol (IPv4), they belong to two different domains: one is an L3 protocol identifier, whereas the other is an L4 protocol identifier.*/

	if(skb->protocol == htons(ETH_P_IP)){
		 printk(KERN_ALERT " Recieved IPv4 packet\n");
	}
	else if(skb->protocol == htons(ETH_P_IPV6)){
		printk(KERN_ALERT " Recieved IPv6 packet\n");
		return;
	}

	/* refer to chapter 18, and 19 , christian*/
	printk(KERN_ALERT " 	skb->csum (L4 checksum)	= %d\n", skb->csum);
	printk(KERN_ALERT "     skb->ip_summed (L4 checksum status) = %d\n", skb->ip_summed);

	if(skb_mac_header_was_set(skb)){
		printk(KERN_ALERT "     Mac header is set\n");
		machdr_ptr = (struct ethhdr *)skb_mac_header(skb);
		/*Alternatively : machdr_ptr = eth_hdr(skb)*/	
		printk(KERN_ALERT "		Source MAC = %x:%x:%x:%x:%x:%x\n", 
			(machdr_ptr->h_source[0]),
			(machdr_ptr->h_source[1]),
			(machdr_ptr->h_source[2]),
			(machdr_ptr->h_source[3]),
			(machdr_ptr->h_source[4]),
			(machdr_ptr->h_source[5]));	
		
		printk(KERN_ALERT "		Dest MAC = %x:%x:%x:%x:%x:%x\n", 
			machdr_ptr->h_dest[0],
			machdr_ptr->h_dest[1],
			machdr_ptr->h_dest[2],
			machdr_ptr->h_dest[3],
			machdr_ptr->h_dest[4],
			machdr_ptr->h_dest[5]);	
	}
	else{
		printk(KERN_ALERT "     Mac header was not set\n");
	}
	
		printk(KERN_ALERT "		h_proto = %u\n", machdr_ptr->h_proto);
	ip_header = (struct iphdr *)skb_network_header(skb); 
	/* Alternatively : nwhdr_ptr = ip_hdr(skb)*/

	if(ip_header == NULL){
		printk(KERN_ALERT "     Error: Could not fetch L3 header\n");
	}
	else{
		 printk(KERN_ALERT "     Network Header is set\n");
		 src_ip    = (unsigned long int)ip_header->saddr; 
		 printk(KERN_ALERT "		Src Address = %s\n", getDotDecimalIpV4(htonl(src_ip), ipv4_str)); 
		 /* Or you can use */
		 /*   printk(KERN_ALERT "            Src Address = %pI4\n", &ip_header->saddr) 
		*/
		 dst_ip   = (unsigned long int)ip_header->daddr;
		 printk(KERN_ALERT "		Dst Address = %s\n", getDotDecimalIpV4(htonl(dst_ip), ipv4_str));
		 printk(KERN_ALERT "		protocol = %d\n", ip_header->protocol);
	}

	if(skb_transport_header_was_set(skb)){
		printk(KERN_ALERT "	Tansport header is set\n");
		tphdr_ptr = skb_transport_header(skb); 
		
		/* this tphdr_ptr could be struct tcphdr *tcp_header Or struct udphdr *udp_header depending on the value of protocol in L3 header. 
	           iF protocol = 17 its udp header, else if protocol = 6, its tcp header*/

		switch(ip_header->protocol){
			case UDP_PROTO:
			{
				printk(KERN_ALERT "     	Layer 4 protocol type : UDP_PROTO(17)\n");
				udp_header = (struct udphdr *)tphdr_ptr;
				/*Alternatively : udp_header = udp_hdr(skb)*/
				src_port  = (unsigned int)ntohs(udp_header->source);
				dst_port = (unsigned int)ntohs(udp_header->dest);
				printk(KERN_ALERT "     	src portno = %lu, dst portno = %lu\n", src_port, dst_port);
			}
			break;
			case TCP_PROTO: 
			{
				printk(KERN_ALERT "     	Layer 4 protocol type : TCP_PROTO(6)\n");
				tcp_header = (struct tcphdr *)tphdr_ptr;
				src_port   = (unsigned int)ntohs(tcp_header->source);
				dst_port  = (unsigned int)ntohs(tcp_header->dest);
				printk(KERN_ALERT "     	src portno = %lu, dst portno = %lu\n", src_port, dst_port);
			}
			break;
			case ICMP_PROTO: 
			{
				printk(KERN_ALERT "     	Layer 4 protocol type : ICMP_PROTO(1)\n");
				icmp_header = (struct icmphdr *)tphdr_ptr;
				if(icmp_header->type == ICMP_ECHO){             /*defined in uapi/linux/icmp.h*/
					printk(KERN_ALERT "			ICMP type = ECHO_REQUEST\n");
				}
				else if(icmp_header->type == ICMP_ECHOREPLY){
					printk(KERN_ALERT "			ICMP type = ECHO_REPLY\n");
				}
				printk(KERN_ALERT "			ICMP code = %d\n", icmp_header->code);
				printk(KERN_ALERT "			ICMP echo id = %d\n", icmp_header->un.echo.id);
			}
			break;
			case IPPROTO_IGMP:
			{
				printk(KERN_ALERT "             Layer 4 protocol type : IGMP_PROTO(%d)\n", ip_header->protocol);
				igmphdr = (igmp_hdr_t *)tphdr_ptr;
				printk(KERN_ALERT "protocol = %-15s  pkt_type = %-15s  seqno = %d\n",  get_string(IPPROTO_IGMP), get_string(igmphdr->type), igmphdr->seqno);	
			}

			case IPPROTO_PIM:
			{
				printk(KERN_ALERT "             Layer 4 protocol type : PIM_PROTO(%d)\n", ip_header->protocol);
				pimhdr = (pim_hdr_t *)tphdr_ptr;
				printk(KERN_ALERT "protocol = %-15s  pkt_type = %-15s  seqno = %d\n",  get_string(IPPROTO_PIM), get_string(pimhdr->type), pimhdr->seqno);	
			}
			break;
			default:
				printk(KERN_ALERT "     	Unknown protocol type in Transport Header\n");

		}

	}
	else{
		printk(KERN_ALERT "	Tansport header is not set\n");
	}
	
		printk(KERN_ALERT "     skb->pkt_type		= %u\n",  skb->pkt_type);
		/* By looking at the mac address of the dst in l2 header, NIC device driver sets 
		this field. page 447, christian*/
		switch(skb->pkt_type){
			case PACKET_HOST:// if dst mac addr == mac addr of the ingress interface
				printk(KERN_ALERT "	PACKET_HOST\n");
				break;
			case PACKET_BROADCAST: // if dst mac is the broadcase mac
				printk(KERN_ALERT "     PACKET_BROADCAST\n");
				break;
			case PACKET_MULTICAST: // if dst mac is the multicast mac
				printk(KERN_ALERT "     PACKET_MULTICAST\n");
				break;
			case PACKET_OTHERHOST: // if dst mac != mac of ingress interface , we allow such ip packets to traverse to the entry fn of IP layer (ip_rcv()) where it is then dropped
				printk(KERN_ALERT "     PACKET_OTHERHOST\n");
				break;
			case PACKET_OUTGOING: // 
				printk(KERN_ALERT "     PACKET_OUTGOING\n");
				break;
			default:
				printk(KERN_ALERT "     Unknown\n");
				break;
		}

	return;
}

static 
char* hook_number_as_str(char num){
	switch(num){
		case NF_IP_PRE_ROUTING:
			return "NF_IP_PRE_ROUTING";
		case NF_IP_LOCAL_IN:
			return "NF_IP_LOCAL_IN";
		case NF_IP_FORWARD:
			return "NF_IP_FORWARD";
		case NF_IP_LOCAL_OUT:
			return "NF_IP_LOCAL_OUT";
		case NF_IP_POST_ROUTING:
			return "NF_IP_POST_ROUTING";
	}
	return NULL;
}

/* Function prototype in <linux/netfilteri.h> */
unsigned int my_packet_dropper_hook(const struct nf_hook_ops *ops,  
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	printk(KERN_ALERT "Congrats! my_packet_dropper_hook() is called at HOOK : %s\n", hook_number_as_str(ops->hooknum));
	return NF_DROP; /* Drop ALL Packets , defined in /uapi/linux/netfilter.h*/
}

/* Function prototype in <linux/netfilter> */
unsigned int 
my_packet_pass_through_hook(const struct nf_hook_ops *ops,  
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	/*Let us investigate the sk_buff  structure while packet is on its journey 
	  through different [hases of linux ip stack*/

	if(NF_ACCEPT == ignore_ssh_pkts(skb))
		return NF_ACCEPT;

	if(skb == NULL){
		printk(KERN_ALERT "	skb is NULL\n");
		return NF_ACCEPT;
	}		
	switch(ops->hooknum){
		case NF_IP_POST_ROUTING:{
			printk(KERN_ALERT "Hook name : NF_IP_POST_ROUTING\n");
		
			if(skb == NULL){
				printk(KERN_ALERT "	skb is NULL\n");
				return NF_ACCEPT;
			}		
			skb_analyser(skb);
			net_device_analyser(out);
			
	/*
	   Since, in NF_IP_POST_ROUTING, the pkt is about to hit the wire, i am expecting that packet generated locally by a socket and transmitted outside would have the following: 
	   1. Transport Layer header Or L4 header (UDP/TCP/ICMP header etc) - 8 bytes
	   2. Network Layer Header Or L3 header (can also be ARP header) [20,60] bytes (When adding IP options, the IPv4 header size can be up to 60 bytes, chapter 4)
	   3. L2 header Or ethernet header - 14 bytes

		Note that : In this phse, the packet has old mac header , and has not been updated yet, It continue to contains the last pair of src - mac address.

	   +-------------+--------------------+--------------+-------------+
	   |             |                    |              |             |
	   | L2 header   |  L3 header         |  TCP/UDP hdr | payload     |
	   |   14 bytes  |     20-60 bytes    |     8 bytes  |             |
	   +-------------+--------------------+--------------+-------------+
	 */
		//skb_analyser(skb);	
	        //net_device_analyser(skb->dev);	
		
	}
	break;

		case NF_IP_PRE_ROUTING:{
			printk(KERN_ALERT "Hook name : NF_IP_PRE_ROUTING\n");
			skb_analyser(skb);
			//net_device_analyser(skb->dev);
			net_device_analyser(in);
		}
		break;

	} // switch ends
	return NF_ACCEPT; /* Accept ALL Packets , defined in /uapi/linux/netfilter.h*/
}

int init_module(void)
{
	netfilter_ops_pre_routing.hook                   =       my_packet_pass_through_hook;
	netfilter_ops_pre_routing.pf                     =       PF_INET; /* for IPv4*/
	netfilter_ops_pre_routing.hooknum                =       NF_IP_PRE_ROUTING;
	netfilter_ops_pre_routing.priority               =       NF_IP_PRI_FIRST;
	netfilter_ops_pre_routing.priv			 = 	NULL;

	netfilter_ops_post_routing.hook                  =       my_packet_pass_through_hook;
	netfilter_ops_post_routing.pf                    =       PF_INET;
	netfilter_ops_post_routing.hooknum               =       NF_IP_POST_ROUTING;
	netfilter_ops_post_routing.priority              =       NF_IP_PRI_FIRST;
	netfilter_ops_post_routing.priv			 = 	NULL;
	
	netfilter_ops_local_in.hook                      =       my_packet_pass_through_hook;
	netfilter_ops_local_in.pf                   	 =       PF_INET;
	netfilter_ops_local_in.hooknum              	 =       NF_IP_LOCAL_IN;
	netfilter_ops_local_in.priority              	 =       NF_IP_PRI_FIRST;
	netfilter_ops_local_in.priv			 = 	NULL;

	netfilter_ops_forward.hook                       =       my_packet_pass_through_hook;
	netfilter_ops_forward.pf                   	 =       PF_INET;
	netfilter_ops_forward.hooknum               	 =       NF_IP_FORWARD;
	netfilter_ops_forward.priority             	 =       NF_IP_PRI_FIRST;
	netfilter_ops_forward.priv			 = 	NULL;

	netfilter_ops_localout.hook                      =       my_packet_pass_through_hook;
	netfilter_ops_localout.pf                    	 =       PF_INET;
	netfilter_ops_localout.hooknum               	 =       NF_IP_LOCAL_OUT;
	netfilter_ops_localout.priority              	 =       NF_IP_PRI_FIRST;
	netfilter_ops_localout.priv			 = 	NULL;
	
	printk(KERN_ALERT "register hook:netfilter_ops_pre_routing\n");
        nf_register_hook(&netfilter_ops_pre_routing); /* register NF_IP_PRE_ROUTING hook */
#if 1
	printk(KERN_ALERT "register hook:netfilter_ops_post_routing\n");
	nf_register_hook(&netfilter_ops_post_routing); /* register NF_IP_POST_ROUTING hook */
	printk(KERN_ALERT "register hook:netfilter_ops_local_in\n");
	nf_register_hook(&netfilter_ops_local_in);
	printk(KERN_ALERT "register hook:netfilter_ops_forward\n");
	nf_register_hook(&netfilter_ops_forward);
	printk(KERN_ALERT "register hook:netfilter_ops_localout\n");
	nf_register_hook(&netfilter_ops_localout);
#endif

return 0;
}

void cleanup_module(void)
{
	printk(KERN_ALERT "unregister hook:netfilter_ops_pre_routing\n");
	nf_unregister_hook(&netfilter_ops_pre_routing); /*unregister NF_IP_PRE_ROUTING hook*/
	printk(KERN_ALERT "unregister hook:netfilter_ops_post_routing\n");
	nf_unregister_hook(&netfilter_ops_post_routing); /*unregister NF_IP_POST_ROUTING hook*/
	printk(KERN_ALERT "unregister hook:netfilter_ops_local_in\n");
	nf_unregister_hook(&netfilter_ops_local_in);
	printk(KERN_ALERT "unregister hook:netfilter_ops_forward\n");
	nf_unregister_hook(&netfilter_ops_forward);
	printk(KERN_ALERT "unregister hook:netfilter_ops_localout\n");
	nf_unregister_hook(&netfilter_ops_localout);
}

MODULE_LICENSE("GPL");

