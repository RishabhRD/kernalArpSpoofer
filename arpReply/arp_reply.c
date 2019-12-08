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

static int sendData(struct net_device* dev,uint8_t dest_addr[ETH_ALEN],uint16_t proto);
static struct nf_hook_ops* hookOps;
static struct net_device* dev = 0;
static char* srcIp = 0;
static char* myIp = 0;
module_param(myIp, charp ,0000);
module_param(srcIp, charp ,0000);
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
static unsigned int hookFunction(void* priv,struct sk_buff* skf,const struct nf_hook_state* state){
	struct iphdr* iph;
	struct sockaddr_in saMy;
	struct sockaddr_in saBroadcast;
	if(!skf) return NF_ACCEPT;
	iph = ip_hdr(skf);
	pton(myIp,(unsigned char*)&(saMy.sin_addr.s_addr));
	pton("255.255.255.255",(unsigned char*)&(saBroadcast.sin_addr.s_addr));
	if(iph->daddr != saMy.sin_addr.s_addr && iph->daddr != saBroadcast.sin_addr.s_addr){
		return NF_DROP;
	}
	return NF_ACCEPT;
}
static int init(void){
	hookOps = (struct nf_hook_ops*) kcalloc(1,sizeof(struct nf_hook_ops),GFP_KERNEL);
	hookOps->hook = (nf_hookfn*)hook_function;
	hookOps->hooknum = NF_ARP_IN;
	hookOps->pf = 0;
	hookOps->priority = INT_MIN;
	dev = &init_net;
	nf_register_net_hook(&init_net,hookOps);
}
static void exit(void){
	nf_unregister_net_hook(&init_net,hookOps);
	kfree(hookOps);
}

module_init(init);
module_exit(exit);
