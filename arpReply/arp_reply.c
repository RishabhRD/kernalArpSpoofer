#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_arp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/ether.h>
#define BUFFER 60
#define ETH_LEN 14
static int sendData(struct net_device* dev,uint8_t dest_addr[ETH_ALEN],uint16_t proto);
static struct nf_hook_ops* hookOps;
static struct net_device* dev = 0;
static char* data = 0;
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};
static int pton(const char* src,unsigned char* dst){
	int saw_digit,octets,ch;
	unsigned char* tp;
	tp = dst;
	*tp = 0;
	saw_digit = 0;
	octets = 0;
	while(*src != 0){
		ch = *src++;
		if(ch>='0' && ch<='9'){
			unsigned int nowNum = *tp*10 + (ch-'0');
			if(saw_digit && *tp == 0) return 0;
			if(nowNum>255) return 0;
			*tp = nowNum;
			if(!saw_digit){
				if(++octets > 4 ) return 0;
				saw_digit = 1;
			}
		}
		else if(ch=='.' && saw_digit){
			if(octets == 4) return 0;
			*++tp = 0;
			saw_digit = 0;
		}
		else return 0;
	}
	if(octets<4) return 0;
	return 1;
}
static unsigned int hookFunction(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff*)){
	struct ethhdr* ethernet;
	char* tmp;
	struct arp_header* inHeader;
	if(!skb){
		return NF_ACCEPT;
	}
	tmp = (char*) ethernet;
	tmp = tmp+ETH_LEN;
	inHeader = (struct arp_header*) tmp;
	if(inHeader->ar_op != __constant_htons(ARPOP_REQUEST)){ 
		return NF_ACCEPT;
	}
	if(((in->ip_ptr)->ifa_list)->ifa_address == myIP){
		return NF_ACCEPT;
	}

}

static int init(void){
	data = (char*) kcalloc(1,sizeof(struct ethhdr) + sizeof(struct arpreq),GFP_KERNEL);
	hookOps = (struct nf_hook_ops*) kcalloc(1,sizeof(struct nf_hook_ops),GFP_KERNEL);
	hookOps->hook = (nf_hookfn*) hook_function;
	hookOps->pf = NFPROTO_ARP;
	hookOps->hooknum = NF_ARP_IN;
	hookOps->priority = NF_IP_PRI_FIRST;
	dev = &init_net;
	nf_register_net_hook(&init_net,hookOps);
}
static void exit(void){
	nf_unregister_net_hook(&init_net,hookOps);
	kfree(data);
	kfree(hookOps);
}

module_init(init);
module_exit(exit);
