/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <pthread.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

//#include <sys/time.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#define THREAD_NUM 1

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

int packet_num = 0;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

struct rx_customer_parameter
{
    Ring_Queue_RX *ring_queue_rx;
    sgx_enclave_id_t eid;
    Ring_Queue_TX *ring_queue_tx;
};

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH)
    {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    }
    else
    {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
    {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL)
    {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
        {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        if (fp != NULL)
            fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL)
    {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL)
            fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL)
        return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

payload_info tcp_handler(uint8_t *packet)
{
    payload_info payload_s;
    payload_s.header_ptr = NULL;
    payload_s.header_length = 0;
    payload_s.payload_ptr = NULL;
    payload_s.payload_length = 0;

    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        //printf("Not an IP packet. Skipping...\n\n");
        return payload_s;
    }
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
    int ethernet_header_length = 14;
    int ip_header_length;
    int ip_length;
    int tcp_header_length;
    int payload_length;
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    ip_length = (*(ip_header + 2) << 8) | (*(ip_header + 3))
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP)
    {
        //printf("Not a TCP packet. Skipping...\n\n");
        return payload_s;
    }
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    payload_length = ip_length -
                     ( ip_header_length + tcp_header_length);
    payload = packet + total_headers_size;
    payload_s.header_ptr = packet;
    payload_s.header_length = ethernet_header_length + ip_header_length + tcp_header_length;
    payload_s.payload_ptr = payload;
    payload_s.payload_length = payload_length;

    return payload_s;
}

void RX_Write(Ring_Queue_RX *ring_queue_rx)
{
    TAG *tag_p = 0;

    tag_p = (TAG *)RX_queue_ptr(ring_queue_rx->_queue_p, ring_queue_rx->_write_now, ring_queue_rx);
    if (tag_p->tag_value == CAN_WRITE)
    {
        tag_p->tag_value = WRITING;
    }
}

void RX_Write_Over(Ring_Queue_RX *ring_queue_rx, payload_info *payload_s)
{
    TAG *tag_p = 0;

    tag_p = (TAG *)RX_queue_ptr(ring_queue_rx->_queue_p, ring_queue_rx->_write_now, ring_queue_rx);
    if (tag_p->tag_value == WRITING)
    {
        tag_p->header_ptr = payload_s->header_ptr;
        tag_p->header_len = payload_s->header_length;
        tag_p->payload_ptr = payload_s->payload_ptr;
        tag_p->payload_len = payload_s->payload_length;
        tag_p->tag_value = CAN_READ;
        ring_queue_rx->_write_now = (ring_queue_rx->_write_now + 1) % ring_queue_rx->_nmemb;
    }
}

void packet_handler(u_char *args, const u_char *packet)
{
    rx_tx *rx_tx_s = (rx_tx *)args;
    Ring_Queue_RX *ring_queue_rx = rx_tx_s->ring_queue_rx;
    Ring_Queue_TX *ring_queue_tx = rx_tx_s->ring_queue_tx;

    payload_info payload_s;
    payload_s = tcp_handler(packet);
    if (payload_s.payload_ptr != NULL && payload_s.payload_length > 0)
    {
        RX_Write(ring_queue_rx);
        RX_Write_Over(ring_queue_rx, &payload_s);
    }
    return;
}

void *rx_customer(void *args)
{
    struct rx_customer_parameter *recv_para = (struct rx_customer_parameter *)args;
    Ring_Queue_RX *ring_queue_rx = recv_para->ring_queue_rx;
    Ring_Queue_TX *ring_queue_tx = recv_para->ring_queue_tx;
    sgx_enclave_id_t eid = recv_para->eid;
    read_buffer_inEncalve(eid, ring_queue_rx, ring_queue_tx);
    return 0;
}

static int lcore_main(u_char *arg)
{
    rx_tx *rx_tx_s = (rx_tx_s *)args;
    unsigned int lcore_id = rte_lcore_id();
    RTE_LOG(INFO, APP, "lcore %u running\n", lcore_id);
    number_of_valid_packets = 0;

    gettimeofday(&last_time, NULL);
    packet_num = 0;

    while (!force_quit)
    {
        bRunning = true;

        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx;
        uint16_t buf;

        // capture packets
        nb_rx = rte_eth_rx_burst(g_nCapPort, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        int i;
        for (i = 0; i < nb_rx; i++)
        {
            //struct timeval tv;
            //gettimeofday(&tv, NULL);

            uint8_t *packet_l2_ptr = rte_pktmbuf_mtod(bufs[i], uint8_t *);
            packet_handler(rx_tx_s, packet_l2_ptr);
        }

        for (buf = 0; buf < nb_rx; buf++)
            rte_pktmbuf_free(bufs[buf]); //Free a packet mbuf back into its original mempool.
    }

    RTE_LOG(INFO, APP, "lcore %u exiting\n", lcore_id);
    return 0;
}

void DPDK_init(u_char *args)
{
    rx_tx_dpdk *rx_tx_dpdk_s = (rx_tx_dpdk_s *)args;
    struct DPDK_parameter *DPDK_para = rx_tx_dpdk_s.dpdk_parameter;
    int argc = DPDK_para->argc;
    char **argv = DPDK_para->argv;
    rx_tx *rx_tx_s = &rx_tx_dpdk_s.rx_tx;

    int ret;
    struct rte_mempool *mbuf_pool;

    // DPDK rte init
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL Init failed\n");

    argc -= ret;
    argv += ret;

    // Register interrupt signal processing function
    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\n\n");
    uint8_t nb_ports = rte_eth_dev_count();
    int i;
    for (i = 0; i < nb_ports; i++)
    {
        char dev_name[RTE_DEV_NAME_MAX_LEN];
        rte_eth_dev_get_name_by_port(i, dev_name);
        printf("Device Number %d:%s ", i, dev_name);
        print_mac(i);
    }

    printf("Choose a port, enter the port number: \n");
    scanf("%d", &g_nCapPort);

    // create Mempool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id()); //Create a mbuf pool.

    if (mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "mbuf_pool create failed\n");
    }

    // port init
    if (port_init(g_nCapPort, mbuf_pool) != 0)
    {
        rte_exit(EXIT_FAILURE, "port init failed\n");
    }

    // Bind threads and cores, and process packets cyclically
    rte_eal_mp_remote_launch(lcore_main, rx_tx_s, SKIP_MASTER);
    rte_eal_mp_wait_lcore();

    exit(0);
}

void *rx_producer(void *args)
{
    rx_tx_dpdk *rx_tx_dpdk_s = (rx_tx_dpdk_s *)args;

    DPDK_init(&rx_tx_dpdk_s);

    return 0;
}

void TX_Read(Ring_Queue_TX *ring_queue_tx)
{
    TAG_TX *tag_p;
    tag_p = TX_queue_ptr(ring_queue_tx, ring_queue_tx->_read_now);
    if (tag_p->tag_value == CAN_READ)
    {
        tag_p->tag_value = READING;
    }
}

void TX_Read_Over(Ring_Queue_TX *ring_queue_tx)
{
    TAG_TX *tag_p;
    tag_p = TX_queue_ptr(ring_queue_tx, ring_queue_tx->_read_now);
    if (tag_p->tag_value == READING)
    {
        tag_p->tag_value = CAN_WRITE;
        ring_queue_tx->_read_now = (ring_queue_tx->_read_now + 1) % ring_queue_tx->_nmemb;

        if (tag_p->payload_len > 0)
        {
            char error_buffer[PCAP_ERRBUF_SIZE];
            pcap_t *send_handle;
            int timeout_limit = 1;
            send_handle = pcap_open_live("lo", BUFSIZ, 0, timeout_limit, error_buffer);
            int packet_len = tag_p->header_len + tag_p->payload_len;
            uint8_t *buf;
            buf = (uint8_t *)calloc(packet_len, sizeof(uint8_t));
            /*
            memcpy(buf, tag_p->header_ptr, tag_p->header_len);
            memcpy(buf + tag_p->header_len, tag_p->encrypted_payload_ptr, tag_p->payload_len);
            if (pcap_sendpacket(send_handle, buf, packet_len) != 0)
            {
                printf("wrong\n");
            }
            memset(buf, 0, packet_len);
            */

            static const unsigned char gcm_key[] = {
                0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
                0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
                0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f};
            static const unsigned char gcm_iv[] = {
                0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84};
            static const unsigned char gcm_aad[] = {
                0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
                0x7f, 0xec, 0x78, 0xde};
            uint8_t *decrypted_buf;
            decrypted_buf = (uint8_t *)calloc(tag_p->payload_len, sizeof(uint8_t));
            EVP_CIPHER_CTX *ctx;
            int outlen, tmplen;
            ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
            EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
            EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
            EVP_DecryptUpdate(ctx, decrypted_buf, &outlen, tag_p->encrypted_payload_ptr, tag_p->payload_len);
            memcpy(buf, tag_p->header_ptr, tag_p->header_len);
            memcpy(buf + tag_p->header_len, decrypted_buf, tag_p->payload_len);

            if (pcap_sendpacket(send_handle, buf, packet_len) != 0)
            {
                printf("wrong\n");
            }

            free(buf);

            pcap_close(send_handle);
        }
    }
}

void *tx_customer(void *args)
{
    Ring_Queue_TX *ring_queue_tx = (Ring_Queue_TX *)args;

    while (1)
    {
        TX_Read(ring_queue_tx);
        TX_Read_Over(ring_queue_tx);
    }
    return 0;
}

void Ring_Queue_RX_Init(Ring_Queue_RX *ring_queue_rx, int nmemb)
{
    if (nmemb <= 0)
    {
        assert(0);
    }
    ring_queue_rx->_nmemb = nmemb;
    ring_queue_rx->_read_now = 0;
    ring_queue_rx->_write_now = 0;
    ring_queue_rx->_queue_p = NULL;
    ring_queue_rx->_queue_p = (u_char *)calloc(nmemb, sizeof(TAG));
}

void Ring_Queue_TX_Init(Ring_Queue_TX *ring_queue_rx, int nmemb)
{
    if (nmemb <= 0)
    {
        assert(0);
    }
    ring_queue_rx->_nmemb = nmemb;
    ring_queue_rx->_read_now = 0;
    ring_queue_rx->_write_now = 0;
    int i;
    for (i = 0; i < nmemb; i++)
    {
        ring_queue_rx->_queue_p[i] = (TAG_TX *)calloc(1, sizeof(TAG_TX));
        if (ring_queue_rx->_queue_p[i])
            ring_queue_rx->_queue_p[i]->encrypted_payload_ptr = (u_char *)calloc(10000, sizeof(u_char));
    }
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    struct DPDK_parameter DPDK_para;
    DPDK_para.argc = argc;
    DPDK_para.argv = argv;

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    pthread_t tid_rx_customer[THREAD_NUM];
    pthread_t tid_rx_producer[THREAD_NUM];
    pthread_t tid_tx_customer[THREAD_NUM];

    Ring_Queue_RX ring_queue_rx;
    Ring_Queue_RX_Init(&ring_queue_rx, LOOP_SIZE);
    Ring_Queue_TX ring_queue_tx;
    Ring_Queue_TX_Init(&ring_queue_tx, LOOP_SIZE);

    struct rx_customer_parameter rx_customer_para;
    rx_customer_para.eid = global_eid;
    rx_customer_para.ring_queue_rx = &ring_queue_rx;
    rx_customer_para.ring_queue_tx = &ring_queue_tx;

    rx_tx_dpdk rx_tx_dpdk_s;
    rx_tx_dpdk_s.ring_queue_rx = &ring_queue_rx;
    rx_tx_dpdk_s.ring_queue_tx = &ring_queue_tx;
    rx_tx_dpdk_s.dpdk_parameter = &DPDK_para;

    pthread_create(&tid_rx_customer[0], NULL, &rx_customer, &rx_customer_para);
    pthread_create(&tid_rx_producer[0], NULL, &rx_producer, &rx_tx_dpdk_s);
    pthread_create(&tid_tx_customer[0], NULL, &tx_customer, &ring_queue_tx);

    for (int i = 0; i < THREAD_NUM; i++)
        pthread_join(tid_rx_customer[i], NULL);
    for (int i = 0; i < THREAD_NUM; i++)
        pthread_join(tid_rx_producer[i], NULL);
    for (int i = 0; i < THREAD_NUM; i++)
        pthread_join(tid_tx_customer[i], NULL);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
