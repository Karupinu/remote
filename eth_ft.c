//eth_mac.c
//イーサネットフレームが観測されるたびにMACアドレスの組を表示します
//使い方
//eth_mac<ネットワークインタフェース名>
//使い方の例
//eth_mac le0
//終了方法
//コントロールCを入力して下さい

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
char * convmac_tostr(u_char *,char *,size_t);
FILE *fi;

//MACアドレス(hardware address)の表示
void print_hwadd(u_char *hwadd)
{
    int i;
    for(i=0;i<5;i++)//48bit 6桁のMACアドレスを表示
    printf("%2x:",hwadd[i]);
    printf("%2x",hwadd[i]);
}

//パケットデータの表示
void
packet_print(u_char *user,const struct pcap_pkthdr *h,
const u_char *p)
{
    struct ether_header *eth ;  //イーサネットヘッダを格納する構造体へのポインタ
    int i;

    /* イーサネットヘッダの取り出し */
    eth =(struct ether_header *) p ;

    /* パケットに対する処理 */
    printf("%d ",(h->ts).tv_sec);//時間の表示
    print_hwadd(eth->ether_shost);//発信元のMACアドレス
    printf("->");
    print_hwadd(eth->ether_dhost);//受信元のMACアドレス
    printf("\n");
    fflush(stdout);
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

        printf("aaa");
    }
    fprintf(fi,"source,");
    fprintf(fi,"destination\n");

    if(argc <=1) //引数のチェック
    {
        printf("usage : %s<network interface>\n",argv[0]);
        printf("1");
        fclose(fi);
        exit(0);
    }

    /* pcap利用の設定　*/
    if((pd=pcap_open_live(argv[1],DEFAULT_SNAPLEN,1,1000,ebuf)) ==NULL)
    {
        (void)fprintf(stderr,"%s",ebuf);
        printf("2");
        fclose(fi);
        exit(1);
    }
    /*pcap_loopによるパケットの取得*/
    /*無限ループを指定しているため、終了にはコントロールCを入力*/
    if(pcap_loop(pd,-1,packet_print,NULL)<0)
    {
        (void)fprintf(stderr,"pcap_loop:%s\n",pcap_geterr(pd));
        printf("3");
        fclose(fi);
        exit(0);
    }
 
    printf("4");
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