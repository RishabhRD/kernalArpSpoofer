#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops *preRouting = 0;
static char* myIp  = 0;
module_param(myIp, charp ,0000);
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
static int __init init(void){
	preRouting = (struct nf_hook_ops*) kcalloc(1,sizeof(struct nf_hook_ops), GFP_KERNEL);
	preRouting->hook = (nf_hookfn*) hookFunction;
	preRouting->hooknum = NF_INET_PRE_ROUTING;
	preRouting->pf = PF_INET;
	preRouting->priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net,preRouting);
	return 0 ;
}
static void __exit cleanup(void){
	nf_unregister_net_hook(&init_net,preRouting);
	kfree(preRouting);
}
module_init(init);
module_exit(cleanup);
