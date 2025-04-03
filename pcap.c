#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <ctype.h>

// ========== 이더넷 헤더 구조체 정의 ==========
struct ethheader {
  unsigned char  ether_dhost[6]; /* 목적지 MAC 주소 */
  unsigned char  ether_shost[6]; /* 출발지 MAC 주소 */
  
  unsigned short ether_type; 
};

// ========== IP 헤더 구조체 정의 ==========
struct ipheader {
  unsigned char      iph_ihl:4, // IP 헤더 길이 (4비트)
                     iph_ver:4; // IP 버전 (4비트)
  unsigned char      iph_tos; // 서비스 타입 (QoS 관련)
  unsigned short int iph_len; // 전체 IP 패킷 길이 (헤더 + 데이터)
  unsigned short int iph_ident; // 패킷 ID (재조립 용도)
  unsigned short int iph_flag:3, // 단편화 플래그 (Fragmentation flags)
                     iph_offset:13; // 조각화 오프셋 (Fragment offset)
  unsigned char      iph_ttl; // TTL (패킷 생존 시간)
  unsigned char      iph_protocol; // 상위 프로토콜 (TCP, UDP, ICMP 등)
  unsigned short int iph_chksum; // 오류 검출을 위한 체크섬
  struct  in_addr    iph_sourceip; // 출발지 IP 주소
  struct  in_addr    iph_destip;   // 목적지 IP 주소
};

// ========== TCP 헤더 구조체 정의 ==========
/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;               /* source port */
    unsigned short tcp_dport;               /* destination port */
    unsigned int   tcp_seq;                 /* sequence number */
    unsigned int   tcp_ack;                 /* acknowledgement number */
    unsigned char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    unsigned char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short tcp_win;                 /* window */
    unsigned short tcp_sum;                 /* checksum */
    unsigned short tcp_urp;                 /* urgent pointer */
};


// ========== 패킷을 처리하는 함수 ==========
void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
                              const unsigned char *packet)
{
  // 패킷의 첫 번째 부분을 이더넷 헤더로 변환
  // 이더넷 헤더 가져오기
  struct ethheader *eth = (struct ethheader *)packet;
  // ip 헤더 가져오기 
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  // tcp 헤더 가져오기(계산)
  struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
    
	// 이더넷 프레임에서 IP 패킷을 추출하는 과정
  // 이더넷 헤더에서 상위 프로토콜이 IPv4(0x0800)인지 확인(IP, ARP... 중에 IP만)
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IPv4의 EtherType 값

		// Ethernet 출력
    printf("\nSource MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Destination MAC: %s\n\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

	  // IP 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n\n", inet_ntoa(ip->iph_destip));
   
    // TCP 포트 출력
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    // 메시지 출력
    // TCP 데이터 (페이로드) 위치 찾기
    unsigned char *payload = (unsigned char *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + TH_OFF(tcp) * 4);

    if (ntohs(tcp->tcp_dport)==80 || ntohs(tcp->tcp_sport)==80) {
        printf("HTTP!!\n");
    }

    // 메시지 출력 (처음 100바이트만 출력)
    printf("Message:\n");
    for (int i = 0; i < 100 && payload[i] != '\0'; i++) {
        printf("%c", isprint(payload[i]) ? payload[i] : '.'); // 사람이 읽을 수 없는 문자는 .으로 출력
    }
    printf("\n");

    printf("==============================================");
    
    
  }
}

// ========== 프로그램 시작 ==========
int main()
{
  pcap_t *handle; // 패킷 캡처 핸들러
  char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지를 저장할 버퍼
  
  struct bpf_program fp; // 필터 설정 구조체
  char filter_exp[] = "tcp"; // 캡처할 패킷 필터 (tcp 패킷만 캡처)
  bpf_u_int32 net; // 네트워크 주소

  // ========== 네트워크 인터페이스 열기 ==========
  // enp0s3 인터페이스에서 실시간 패킷 캡처 시작
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "pcap_open_live 실패: %s\n", errbuf);
      return 1;
  }

  // ========== 필터 설정 ==========
  // 필터링이 커널에서 처리됨 
  // 필터 식(filter_exp, "tcp")을 BPF(Bytecode) 형태로 변환
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) { // 필터 적용
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // ========== 패킷 캡처 시작 ==========
  // 패킷을 계속해서 캡처하고, got_packet 함수를 호출함
  // 세션 핸들, 캡처할 패킷 개수(-1이면 무한정 캡처), 패킷을 처리할 함수, 추가 데이터(일반적으로 null)
  pcap_loop(handle, -1, got_packet, NULL);

  // ========== 패킷 캡처 시작 ==========
  // 캡처 종료 후, 사용한 리소스 정리
  pcap_close(handle);
  return 0;
}
