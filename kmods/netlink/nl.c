#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h>
#define NETLINK_TEST 25
#define MAX_MSGSIZE 1024
int stringlength(char *s);
int err;
struct sock *nl_sk = NULL;
int flag = 0;

static void nl_data_ready(struct sk_buff *__skb);
struct netlink_kernel_cfg nkc = {.input = nl_data_ready};

// Send to user space.
void sendnlmsg(char *message, int portid)
{
    struct sk_buff *skb_1;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;
    if(!message || !nl_sk)
    {
        return ;
    }
    printk(KERN_ERR "portid:%d\n",portid);
    skb_1 = alloc_skb(len,GFP_KERNEL);
    if(!skb_1)
    {
        printk(KERN_ERR "my_net_link:alloc_skb error\n");
	return ;
    }
    slen = stringlength(message);
    nlh = nlmsg_put(skb_1,0,0,0,MAX_MSGSIZE,0);
    if (!nlh) {
	pr_warn("It's not succeded nhl");
        return ;
    }
    NETLINK_CB(skb_1).portid = 0;
    NETLINK_CB(skb_1).dst_group = 0;
    memcpy(NLMSG_DATA(nlh),message,slen);
    *((char*)NLMSG_DATA(nlh) + 1 + slen) = '\0';
    printk("my_net_link:send message '%s'.\n",(char *)NLMSG_DATA(nlh));
    netlink_unicast(nl_sk,skb_1,portid,MSG_DONTWAIT);
}
int stringlength(char *s)
{
    int slen = 0;
    for(; *s; s++)
    {
        slen++;
    }
    return slen;
}
//接收用户态发来的消息
void nl_data_ready(struct sk_buff *__skb)
 {
     struct sk_buff *skb;
     struct nlmsghdr *nlh;
     struct completion cmpl;
     int i=2;
     int portid;
     printk("begin data_ready\n");
     skb = skb_get (__skb);
     if(skb->len >= NLMSG_SPACE(0))
     {
         nlh = nlmsg_hdr(skb);
         pr_info("data = %x\n", NLMSG_DATA(nlh));
         portid = nlh->nlmsg_pid;
         printk("Message received:%s, %d\n", NLMSG_DATA(nlh), portid);
         while(i--)
         {
            init_completion(&cmpl);
            msleep(20);
            //wait_for_completion_timeout(&cmpl,3 * HZ);
            sendnlmsg("I am from kernel!", portid);
         }
         flag = 1;
         kfree_skb(skb);
     }
 }

int netlink_init(void)
{
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nkc);
    if(!nl_sk){
        printk(KERN_ERR "my_net_link: create netlink socket error.\n");
        return 1;
    }
    printk("create netlink socket ok.\n");
    return 0;
}
static void netlink_exit(void)
{
    if(nl_sk != NULL){
        sock_release(nl_sk->sk_socket);
    }
    printk("my_net_link: self module exited\n");
}
module_init(netlink_init);
module_exit(netlink_exit);
MODULE_LICENSE("GPL");
