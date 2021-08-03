//eth_mac.c
//観測されたイーサネットフレームの大きさを表示します

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

//MAC
void print_hwadd(u_char *hwadd)
{
    int i;
    for(i=0;i<5;i++)//48bit 6桁のMACアドレスを表示
    pirntf("%2x:",hwadd[i]);
    printf("%2x",hwadd[i]);
}

//パケットデータの表示
void
packet_print(u_char *user,const struct pcap_pkthdr *h,
const u_char *p)
{
    struct ether_header *eth ;
    int i;

    /*イーサネットヘッダの取り出し*/
    eth =(struct ether_header *) p;
    /*パケットに対する処理*/
    print_hwadd(eth->ether_shost);//発信元のMACアドレス
    printf("->");
    print_hwadd(eth->ether_dhost);//受信先のMACアドレス
    printf("\n");
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