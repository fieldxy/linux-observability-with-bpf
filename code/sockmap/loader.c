#define _GNU_SOURCE /* POLLRDHUP */
#include <sys/socket.h>

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

// from sampbles/bpf
#include "bpf_load.h"
#include "sock_example.h"

#include <bpf/bpf.h>
#include <linux/bpf.h>

#include <sys/types.h>
// #include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <poll.h>

#define TCP_INFO		11

/* tcp_info */
struct xtcp_info {
	uint8_t tcpi_state;
	uint8_t tcpi_ca_state;
	uint8_t tcpi_retransmits;
	uint8_t tcpi_probes;
	uint8_t tcpi_backoff;
	uint8_t tcpi_options;
	uint8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	uint8_t tcpi_delivery_rate_app_limited : 1;

	uint32_t tcpi_rto;
	uint32_t tcpi_ato;
	uint32_t tcpi_snd_mss;
	uint32_t tcpi_rcv_mss;

	uint32_t tcpi_unacked;
	uint32_t tcpi_sacked;
	uint32_t tcpi_lost;
	uint32_t tcpi_retrans;
	uint32_t tcpi_fackets;

	/* Times. */
	uint32_t tcpi_last_data_sent;
	uint32_t tcpi_last_ack_sent; /* Not remembered, sorry. */
	uint32_t tcpi_last_data_recv;
	uint32_t tcpi_last_ack_recv;

	/* Metrics. */
	uint32_t tcpi_pmtu;
	uint32_t tcpi_rcv_ssthresh;
	uint32_t tcpi_rtt;
	uint32_t tcpi_rttvar;
	uint32_t tcpi_snd_ssthresh;
	uint32_t tcpi_snd_cwnd;
	uint32_t tcpi_advmss;
	uint32_t tcpi_reordering;

	uint32_t tcpi_rcv_rtt;
	uint32_t tcpi_rcv_space;

	uint32_t tcpi_total_retrans;

	uint64_t tcpi_pacing_rate;
	uint64_t tcpi_max_pacing_rate;
	uint64_t tcpi_bytes_acked; /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	uint64_t tcpi_bytes_received; /* RFC4898
					 tcpEStatsAppHCThruOctetsReceived */
	uint32_t tcpi_segs_out;       /* RFC4898 tcpEStatsPerfSegsOut */
	uint32_t tcpi_segs_in;	/* RFC4898 tcpEStatsPerfSegsIn */

	uint32_t tcpi_notsent_bytes;
	uint32_t tcpi_min_rtt;
	uint32_t tcpi_data_segs_in;  /* RFC4898 tcpEStatsDataSegsIn */
	uint32_t tcpi_data_segs_out; /* RFC4898 tcpEStatsDataSegsOut */

	uint64_t tcpi_delivery_rate;

	uint64_t tcpi_busy_time;    /* Time (usec) busy sending data */
	uint64_t tcpi_rwnd_limited; /* Time (usec) limited by receive window */
	uint64_t tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	uint32_t tcpi_delivered;
	uint32_t tcpi_delivered_ce;

	uint64_t tcpi_bytes_sent;    /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	uint64_t tcpi_bytes_retrans; /* RFC4898 tcpEStatsPerfOctetsRetrans */
	uint32_t tcpi_dsack_dups;    /* RFC4898 tcpEStatsStackDSACKDups */
	uint32_t tcpi_reord_seen;    /* reordering events seen */
};

char bpf_log_buf[BPF_LOG_BUF_SIZE];
int server_listen(short port);

/*loader bpf_prog*/
int main(int argc, char **argv)
{
    int server_fd = -1;
    char filename[256];
    int sockmap_fd = -1;

    snprintf(filename, sizeof(filename), "%s", argv[1]);

    if (load_bpf_file(filename))
    {
        printf("%s", bpf_log_buf);
        return 1;
    }

    sockmap_fd = map_fd[0];

    bpf_prog_attach(prog_fd[0], sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);
    bpf_prog_attach(prog_fd[1], sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);

    server_fd = server_listen(8000);

again_accept:;

    socklen_t sin_size;
    int client_fd = -1;

    client_fd = accept(server_fd, NULL, &sin_size);
    if (client_fd == -1)
    {
        perror("accept");
        exit(1);
    }

    {
        /* There is a bug in sockmap which prevents it from
     * working right when snd buffer is full. Set it to
     * gigantic value. */
        int val = 32 * 1024 * 1024;
        setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
    }

    /* [*] Perform ebpf socket magic */
    /* Add socket to SOCKMAP. Otherwise the ebpf won't work. */
    int idx = 0;
    int val = client_fd;
    int ret = -1;
    ret = bpf_map_update_elem(sockmap_fd, &idx, &val, BPF_ANY);
    if (ret != 0)
    {
        if (errno == EOPNOTSUPP)
        {
            perror("pushing closed socket to sockmap?");
            close(client_fd);
            goto again_accept;
        }
        perror("bpf(MAP_UPDATE_ELEM)");
    }

    /* [*] Wait for the socket to close. Let sockmap do the magic. */
    struct pollfd fds[1] = {
        {.fd = client_fd, .events = POLLRDHUP},
    };

    poll(fds, 1, -1);

    /* Was there a socket error? */
    {
        int err;
        socklen_t err_len = sizeof(err);
        int r = getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
        if (r < 0)
        {
            perror("getsockopt()");
        }

        errno = err;
        if (errno)
        {
            perror("sockmap fd");
        }
    }

    /* Get byte count from TCP_INFO */
    struct xtcp_info ta, ti = {};
    socklen_t ti_len = sizeof(ti);
    ret = getsockopt(client_fd, IPPROTO_TCP, TCP_INFO, &ta, &ti_len);
    if (ret < 0)
    {
        perror("getsockopt(TPC_INFO)");
    }

    /* Cleanup the entry from sockmap. */
    idx = 0;
    ret = bpf_map_delete_elem(sockmap_fd, &idx);
    if (ret != 0)
    {
        if (errno == EINVAL)
        {
            fprintf(stderr, "[-] Removing closed sock from sockmap\n");
        }
        else
        {
            perror("bpf(MAP_DELETE_ELEM, sock_map)");
        }
    }
    close(client_fd);

    fprintf(stderr, "[+] rx=%lu tx=%lu\n", ta.tcpi_bytes_received,
                                           ti.tcpi_bytes_sent - ti.tcpi_bytes_retrans);

    goto again_accept;
}

int server_listen(short port) {
    struct sockaddr_in server_sockaddr;
    int sockfd;

    if((sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
        perror("Socket");
        exit(1);
    }

    printf("Socket successful!,sockfd=%d\n",sockfd);

    server_sockaddr.sin_family 		= AF_INET;
    server_sockaddr.sin_port 		= htons(port);
    server_sockaddr.sin_addr.s_addr 	= INADDR_ANY;
    bzero(&(server_sockaddr.sin_zero),8);

    if((bind(sockfd,(struct sockaddr *)&server_sockaddr,sizeof(struct sockaddr))) < 0) {
        perror("bind");
        exit(-1);
    }
    printf("bind successful !\n");

    if( listen (sockfd, 1024) < 0) {
        perror("listen");
        exit(1);
    }

    printf("listening ... \n");
    return sockfd;
}
