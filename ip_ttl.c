
//ヘッダファイルの読み込み
#include<stdio.h>

#include<sys/types.h>
#include<sys/time.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>

#include<pcap.h> //pcapライブラリ

#define DEFAULT_SNAPLEN 68

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
packet_print(u_char *user,const struct pcap_pkthdr *h,
const u_char *p)
{
    struct ip *iph;

    if(ntohs(((struct ether_header *)p)->ether_type)== ETHERTYPE_IP){
        iph =(struct ip*)(p + sizeof(struct ether_header));
        /*パケットに対する処理*/
        print_ipadd((u_char *)&(iph->ip_src));
        printf("->");
        print_ipadd((u_char *)&(iph->ip_dst));
        printf("\t%d",iph->ip_ttl);
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