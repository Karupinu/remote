//ヘッダファイルの読み込み
#include<stdio.h>
#include<stdlib.h>

#include<sys/types.h>
#include<sys/time.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/ip6.h>
#include<netinet/if_ether.h>

#include<pcap.h> //pcapライブラリ

#define DEFAULT_SNAPLEN 68
char * convmac_tostr(u_char *,char *,size_t);
void print_type(u_short mactype);
void print_csv(u_short type);
void print_IPtype(u_char iptype);
void print_IPtypecsv(u_char iptype);
FILE *fi;

//MACアドレス(hardware address)の表示
void print_hwadd(u_char *hwadd)
{
    int i;
    for(i=0;i<5;i++)//48bit 6桁のMACアドレスを表示
    printf("%2x:",hwadd[i]);
    printf("%2x",hwadd[i]);
}

void print_IPv6(struct in6_addr ip6h)
{
    char str[40];
    struct in6_addr* addr;
    addr = &ip6h;
    int size = sizeof((int)addr->s6_addr);

    /*
    int i;
    for(i=0;i<size;i+=2)
    {
        printf("%02x",(int)addr->s6_addr[i]);
        printf("%02x:",(int)addr->s6_addr[i+1]);
    }
    */
    
    sprintf(str,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)addr->s6_addr[0], (int)addr->s6_addr[1],
            (int)addr->s6_addr[2], (int)addr->s6_addr[3],
            (int)addr->s6_addr[4], (int)addr->s6_addr[5],
            (int)addr->s6_addr[6], (int)addr->s6_addr[7],
            (int)addr->s6_addr[8], (int)addr->s6_addr[9],
            (int)addr->s6_addr[10], (int)addr->s6_addr[11],
            (int)addr->s6_addr[12], (int)addr->s6_addr[13],
            (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
    printf(" %s",str);
}
void print_IPv6csv(struct in6_addr ip6h)
{
    char str[40];
    struct in6_addr* addr;
    addr = &ip6h;
    int size = sizeof((int)addr->s6_addr);

    sprintf(str,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)addr->s6_addr[0], (int)addr->s6_addr[1],
            (int)addr->s6_addr[2], (int)addr->s6_addr[3],
            (int)addr->s6_addr[4], (int)addr->s6_addr[5],
            (int)addr->s6_addr[6], (int)addr->s6_addr[7],
            (int)addr->s6_addr[8], (int)addr->s6_addr[9],
            (int)addr->s6_addr[10], (int)addr->s6_addr[11],
            (int)addr->s6_addr[12], (int)addr->s6_addr[13],
            (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
    fprintf(fi,"%s",str);  
}

void print_arp(u_short arppro)
{
    printf(" TYPE: ");
    switch (arppro)
    {
    case ARPOP_REQUEST: /* request to resolve address */
        printf("REQ");
        break;
    case ARPOP_REPLY : /* response to previous request */
        printf("REP");
        break;
    case ARPOP_RREQUEST: /* request protocol address given hardware */
        printf("REV_REQ");
        break;
    case ARPOP_RREPLY: /* response giving protocol address */
        printf("REV_REP");
        break;
    case ARPOP_InREQUEST: /* request to identify peer */
        printf("INV_REQ");
        break;
    case ARPOP_InREPLY: /* response identifying peer */
        printf("INV_REP");
        break;
    default:
        printf("その他");
        break;
    }
}
void print_arpcsv(u_short arppro)
{
  //  printf(" TYPE: ");
    switch (arppro)
    {
    case ARPOP_REQUEST: /* request to resolve address */
        fprintf(fi,"REQ");
        break;
    case ARPOP_REPLY : /* response to previous request */
        fprintf(fi,"REP");
        break;
    case ARPOP_RREQUEST: /* request protocol address given hardware */
        fprintf(fi,"REV_REQ");
        break;
    case ARPOP_RREPLY: /* response giving protocol address */
        fprintf(fi,"REV_REP");
        break;
    case ARPOP_InREQUEST: /* request to identify peer */
        fprintf(fi,"INV_REQ");
        break;
    case ARPOP_InREPLY: /* response identifying peer */
        fprintf(fi,"INV_REP");
        break;
    default:
        fprintf(fi,"その他");
        break;
    }
}
//パケットデータの表示
void
packet_print(u_char *user,const struct pcap_pkthdr *h,
const u_char *p)
{
    struct ether_header *eth ;  //イーサネットヘッダを格納する構造体へのポインタ
    int i;
    char dmac[18] = {0};
    char smac[18] = {0};
    char filename[50] = "result.csv";

    
    /* イーサネットヘッダの取り出し */
    eth =(struct ether_header *) p ;
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct ether_arp *arp;
    fclose(fi);
    fi=fopen(filename,"a");
    /* パケットに対する処理 */
    printf("source: ");
    print_hwadd(eth->ether_shost);//発信元のMACアドレス
    printf("->");
    printf("dest: ");
    print_hwadd(eth->ether_dhost);//受信元(宛先)のMACアドレス
    printf(" type: ");
    print_type(eth->ether_type);//パケットの種類
    if(ntohs(eth->ether_type)== ETHERTYPE_IP)
    {
        iph =(struct ip*)(p + sizeof(struct ether_header));
        /*パケットに対する処理*/
        printf(" ip_src = %s", inet_ntoa(iph->ip_src));
        printf("->");
        printf(" ip_dst = %s", inet_ntoa(iph->ip_dst));
        print_IPtype(iph->ip_p);
    }
   else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6)
    {
        ip6h = (struct ip6_hdr*)(p + sizeof(struct ether_header));
        print_IPv6(ip6h->ip6_src);
        printf("->");
        print_IPv6(ip6h->ip6_dst);
    }
    else if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
    {
        arp = (struct ether_arp*)(p + sizeof(struct ether_header));
        printf(" arp_spa: ");
        int sizes = sizeof(arp->arp_spa);
        for(i=0;i<sizes;i++)
        {
            if(i!=sizes-1)printf("%d.",arp->arp_spa[i]);
            else printf("%d",arp->arp_spa[i]);
        }
        printf("->");
        printf(" arp_tpa: ");
        int sizet = sizeof(arp->arp_tpa);
        for(i=0;i<sizet;i++)
        {
            if(i!=sizet-1)printf("%u.",arp->arp_tpa[i]);
            else printf("%u",arp->arp_tpa[i]);
        }
        print_arp(arp->ea_hdr.ar_pro);
        
    }
    printf("\n");
    fprintf(fi,"%s",convmac_tostr(eth->ether_shost,smac,sizeof(smac)));
    fprintf(fi,",");
    fprintf(fi,"%s",convmac_tostr(eth->ether_dhost,dmac,sizeof(dmac)));
    fprintf(fi,",");
    print_csv(eth->ether_type);
    fprintf(fi,",");
    if(ntohs(((struct ether_header *)p)->ether_type)== ETHERTYPE_IP){
        iph =(struct ip*)(p + sizeof(struct ether_header));
        /*パケットに対する処理*/
        fprintf(fi,"%s", inet_ntoa(iph->ip_src));
        fprintf(fi,",");
        fprintf(fi,"%s", inet_ntoa(iph->ip_dst));
        fprintf(fi,",");
        print_IPtypecsv(iph->ip_p);
    }
    else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6)
    {
        ip6h = (struct ip6_hdr*)(p + sizeof(struct ether_header));
        print_IPv6csv(ip6h->ip6_src);
        fprintf(fi,",");
        print_IPv6csv(ip6h->ip6_dst);
    }
    else if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
    {
        arp = (struct ether_arp*)(p + sizeof(struct ether_header));
        int sizes = sizeof(arp->arp_spa);
        for(i=0;i<sizes;i++)
        {
            if(i!=sizes-1)fprintf(fi,"%d.",arp->arp_spa[i]);
            else fprintf(fi,"%d",arp->arp_spa[i]);
        }
        fprintf(fi,",");
        int sizet = sizeof(arp->arp_tpa);
        for(i=0;i<sizet;i++)
        {
            if(i!=sizet-1)fprintf(fi,"%u.",arp->arp_tpa[i]);
            else fprintf(fi,"%d",arp->arp_tpa[i]);
        }
        fprintf(fi,",");
        print_arpcsv(arp->ea_hdr.ar_pro);
        
    }

    fprintf(fi,"\n");
}
void print_csv(u_short type)
{
    switch (ntohs(type))
    {
    case ETHERTYPE_ARP:
        fprintf(fi,"ARP");
        break;
    case ETH_P_IEEE802154:
        fprintf(fi,"IEEE802154");
        break;
    case ETHERTYPE_IP:
        fprintf(fi,"IP");
        break;
    case ETHERTYPE_IPV6:
        fprintf(fi,"IPv6");
        break;
    case ETHERTYPE_LOOPBACK:
        fprintf(fi,"LOOPBACK");
        break;
    case ETHERTYPE_AT:
        fprintf(fi,"AT");
        break;
    case ETHERTYPE_PUP:
        fprintf(fi,"PUP");
        break;
    case ETHERTYPE_REVARP:
        fprintf(fi,"REVARP");
        break;
    case ETHERTYPE_SPRITE:
        fprintf(fi,"RSN_PREAUTH");
        break;
    case ETHERTYPE_TRAIL:
        fprintf(fi,"TRAIL");
        break;
    case ETHERTYPE_VLAN:
        fprintf(fi,"VLAN");
        break;
    default:
        fprintf(fi,"その他");
        break;
    }
}

void print_type(u_short mactype)
{
    switch (ntohs(mactype))
    {
    case ETHERTYPE_ARP:
        printf("ARP");
        break;
    case ETH_P_IEEE802154:
        printf("IEEE802154");
        break;
    case ETHERTYPE_IP:
        printf("IP");
        break;
    case ETHERTYPE_IPV6:
        printf("IPv6");
        break;
    case ETHERTYPE_LOOPBACK:
        printf("LOOPBACK");
        break;
    case ETHERTYPE_AT:
        printf("AT");
        break;
    case ETHERTYPE_PUP:
        printf("PUP");
        break;
    case ETHERTYPE_REVARP:
        printf("REVARP");
        break;
    case ETHERTYPE_SPRITE:
        printf("RSN_PREAUTH");
        break;
    case ETHERTYPE_TRAIL:
        printf("TRAIL");
        break;
    case ETHERTYPE_VLAN:
        printf("VLAN");
        break;
    default:
        printf("その他");
        break;
    }
}

void print_IPtype(u_char iptype)
{
    printf(" :IP_TYPE: ");
    switch(iptype)
    {
    case IPPROTO_UDP:
        printf("UDP");
        break;
    case IPPROTO_TCP:
        printf("TCP");
        break;
    case IPPROTO_ICMP:
        printf("ICMP");
        break;
    default:
        printf("%u",iptype);
        break;
    }
}
void print_IPtypecsv(u_char iptype)
{
    switch(iptype)
    {
    case IPPROTO_UDP:
        fprintf(fi,"UDP");
        break;
    case IPPROTO_TCP:
        fprintf(fi,"TCP");
        break;
    case IPPROTO_ICMP:
        fprintf(fi,"ICMP");
        break;
    default:
        fprintf(fi,"%u",iptype);
        break;
    }
}
//main
//パケット取得の設定と開始
int main(int argc,char **argv)
{
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pd;
    
    char filename[50];

    sprintf(filename,"result.csv");
    fi=fopen(filename,"w");
    if(fi==NULL)
    {

        printf("失敗");
    }
    fprintf(fi,"source,");
    fprintf(fi,"destination,");
    fprintf(fi,"type,");
    fprintf(fi,"ip_src,");
    fprintf(fi,"ip_dst,");
    fprintf(fi,"IP_TYPE\n");
    if(argc <=1) //引数のチェック
    {
        printf("usage : %s<network interface>\n",argv[0]);        
        fclose(fi);
        exit(0);
    }

    /* pcap利用の設定　*/
    if((pd=pcap_open_live(argv[1],DEFAULT_SNAPLEN,1,1000,ebuf)) ==NULL)
    {
        (void)fprintf(stderr,"%s",ebuf);    
        fclose(fi);
        exit(1);
    }
    /*pcap_loopによるパケットの取得*/
    /*無限ループを指定しているため、終了にはコントロールCを入力*/
    if(pcap_loop(pd,-1,packet_print,NULL)<0)
    {
        (void)fprintf(stderr,"pcap_loop:%s\n",pcap_geterr(pd));
        
        fclose(fi);
        exit(0);
    }
 
    fclose(fi);
    pcap_close(pd);

    exit(0);
}

char * convmac_tostr(u_char *hwaddr,char *mac,size_t size)
{
  snprintf(mac,size,"%02x:%02x:%02x:%02x:%02x:%02x",
                     hwaddr[0],hwaddr[1],hwaddr[2],
                     hwaddr[3],hwaddr[4],hwaddr[5]);
  return mac;
}