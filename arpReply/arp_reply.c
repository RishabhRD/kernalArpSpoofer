#include <linux/init.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_arp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#define BUFFER 60
#define ETH_LEN 14
static struct nf_hook_ops* hookOps;
static char* data = 0;
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    uint32_t sender_ip;
    unsigned char target_mac[6];
    uint32_t target_ip;
};
static unsigned int hookFunction(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff*)){
	struct sk_buff* sendSkb;
	struct ethhdr* ethernet;
	struct ethhdr* sendEthernet;
	struct arp_header* sendHeader;
	char* tmp;
	char* data;
	struct arp_header* inHeader;
	if(!skb){
		return NF_ACCEPT;
	}
	ethernet = eth_hdr(skb);
	tmp = (char*) ethernet;
	tmp = tmp+ETH_LEN;
	inHeader = (struct arp_header*) tmp;
	if(inHeader->hardware_len !=6 || inHeader->protocol_len !=4){
		return NF_ACCEPT;
	}
	if(inHeader->opcode != __constant_htons(ARPOP_REQUEST)){ 
		return NF_ACCEPT;
	}
	if(((in->ip_ptr)->ifa_list)->ifa_address == inHeader->target_ip){
		return NF_ACCEPT;
	}
	sendSkb = alloc_skb(sizeof(struct ethhdr)+sizeof(struct arp_header), GFP_ATOMIC);
	sendSkb->dev = out;
	sendSkb->pkt_type = PACKET_OUTGOING;
	skb_reserve(sendSkb,sizeof(struct ethhdr)+sizeof(struct arp_header));
	data = (char*) skb_push(sendSkb,sizeof(struct ethhdr)+sizeof(struct arp_header));
	sendEthernet = (struct ethhdr*) data;
	sendEthernet->h_dest[0] = ethernet->h_source[0];
	sendEthernet->h_dest[1] = ethernet->h_source[1];
	sendEthernet->h_dest[2] = ethernet->h_source[2];
	sendEthernet->h_dest[3] = ethernet->h_source[3];
	sendEthernet->h_dest[4] = ethernet->h_source[4];
	sendEthernet->h_dest[5] = ethernet->h_source[5];
	sendEthernet->h_source[0] = in->dev_addr[0];
	sendEthernet->h_source[1] = in->dev_addr[1];
	sendEthernet->h_source[2] = in->dev_addr[2];
	sendEthernet->h_source[3] = in->dev_addr[3];
	sendEthernet->h_source[4] = in->dev_addr[4];
	sendEthernet->h_source[5] = in->dev_addr[5];
	sendEthernet->h_proto = ethernet->h_proto;
	sendHeader = (struct arp_header*) (data+ETH_LEN);
	sendHeader->hardware_len = inHeader->hardware_len;
	sendHeader->hardware_type = inHeader->hardware_type;
	sendHeader->protocol_len = inHeader->protocol_len;
	sendHeader->protocol_type = inHeader->protocol_type;
	sendHeader->sender_ip = inHeader->target_ip;
	sendHeader->target_ip = inHeader->sender_ip;
	sendHeader->target_mac[0] = inHeader->sender_mac[0];
	sendHeader->target_mac[1] = inHeader->sender_mac[1];
	sendHeader->target_mac[2] = inHeader->sender_mac[2];
	sendHeader->target_mac[3] = inHeader->sender_mac[3];
	sendHeader->target_mac[4] = inHeader->sender_mac[3];
	sendHeader->target_mac[5] = inHeader->sender_mac[5];
	sendHeader->sender_mac[0] = in->dev_addr[0];
	sendHeader->sender_mac[1] = in->dev_addr[1];
	sendHeader->sender_mac[2] = in->dev_addr[2];
	sendHeader->sender_mac[3] = in->dev_addr[3];
	sendHeader->sender_mac[4] = in->dev_addr[4];
	sendHeader->sender_mac[5] = in->dev_addr[5];
	sendHeader->opcode = __constant_htons(ARPOP_REPLY);
	sendSkb->protocol = __constant_htons(sendEthernet->h_proto);
	sendSkb->no_fcs = 1;
	dev_queue_xmit(skb);
	return 0;
}

static int __init init(void){
	hookOps = (struct nf_hook_ops*) kcalloc(1,sizeof(struct nf_hook_ops),GFP_KERNEL);
	hookOps->hook = (nf_hookfn*) hookFunction;
	hookOps->pf = NFPROTO_ARP;
	hookOps->hooknum = NF_ARP_IN;
	hookOps->priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net,hookOps);
	return 0;
}
static void __exit cleanup(void){
	nf_unregister_net_hook(&init_net,hookOps);
	kfree(data);
	kfree(hookOps);
}

module_init(init);
module_exit(cleanup);
MODULE_LICENSE("GPL");
