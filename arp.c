//ヘッダファイルの読み込み
#include<stdio.h>
#include<stdlib.h>

#include<sys/types.h>
#include<sys/time.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>

#include<pcap.h> //pcapライブラリ

#define DEFAULT_SNAPLEN 68
//MACアドレス(hardware address)の表示
void print_hwadd(u_char *hwadd)
{
    int i;
    for(i=0;i<5;i++)//48bit 6桁のMACアドレスを表示
    printf("%2x:",hwadd[i]);
    printf("%2x",hwadd[i]);
    
}
//IP addressの表示
void
print_ipadd(u_char *ipadd)
{
    int i;
    for(i=0;i<3;++i)
    printf("%d.",ipadd[i]);
    printf("%d",ipadd[i]);
}
//パケットデータの表示
void
packet_print(u_char *user,const struct pcap_pkthdr *h,const u_char *p)
{
    struct ether_arp *arppkt;
    unsigned int typeno;
    typeno=ntohs(((struct ether_header *)p)->ether_type);

    if((typeno == ETHERTYPE_ARP) || (typeno == ETHERTYPE_REVARP)){
       arppkt =(struct ether_arp *)(p + sizeof(struct ether_header));
        if(typeno == ETHERTYPE_ARP)printf("arp ");
        else printf("rarp ");
        print_hwadd((u_char *)&(arppkt->arp_sha));
        printf(",");
        print_ipadd((u_char *)&(arppkt->arp_spa));
        printf("->");
        print_hwadd((u_char *)&(arppkt->arp_tha));
        printf(",");
        print_ipadd((u_char *)&(arppkt->arp_tpa));
        printf("\n");
        fflush(stdout);
    }
}
//main
//パケット取得の設定と開始
int main(int argc,char **argv)
{
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pd;

    if(argc <=1){//引数のチェック
    printf("usage : %s<network interface>\n",argv[0]);
    exit(0);
}

/* pcap利用の設定　*/
if((pd = pcap_open_live(argv[1],DEFAULT_SNAPLEN,1,1000,ebuf)) ==NULL){
    (void)fprintf(stderr,"%s",ebuf);
    exit(1);
}
/*pcap_loopによるパケットの取得*/
/*無限ループを指定しているため、終了にはコントロールCを入力*/
if(pcap_loop(pd,-1,packet_print,NULL) < 0){
    (void)fprintf(stderr,"pcap_loop:%s\n",pcap_geterr(pd));
    exit(0);
}
pcap_close(pd);
exit(0);
}