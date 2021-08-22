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

#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */

#include <string.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid; /* global enclave id */

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(__cplusplus)
}
#endif

typedef unsigned char u_char;

#define LOOP_SIZE 32

#define CAN_WRITE 0x00
#define CAN_READ 0x01
#define READING 0x02
#define WRITING 0x03

typedef struct tag
{
    u_char tag_value;
    const u_char *header_ptr;
    int header_len;
    const u_char *payload_ptr;
    int payload_len;
} TAG;

typedef struct Ring_Queue_RX_
{
    u_char *_queue_p;
    int _nmemb;
    volatile int _read_now;
    volatile int _write_now;
} Ring_Queue_RX;

typedef struct _payload_info
{
    const u_char *header_ptr;
    int header_length;
    const u_char *payload_ptr;
    int payload_length;
} payload_info;

typedef struct tag_tx_
{
    u_char tag_value;
    const u_char *header_ptr;
    int header_len;
    const u_char *payload_ptr;
    int payload_len;
    u_char *encrypted_payload_ptr;
} TAG_TX;

typedef struct Ring_Queue_TX_
{
    TAG_TX *_queue_p[LOOP_SIZE];
    int _nmemb;
    volatile int _read_now;
    volatile int _write_now;
} Ring_Queue_TX;

typedef struct _rx_tx
{
    Ring_Queue_RX *ring_queue_rx;
    Ring_Queue_TX *ring_queue_tx;
} rx_tx;

u_char *RX_queue_ptr(u_char *queue_p, int pos, Ring_Queue_RX *ring_queue_rx)
{
    u_char *rst = 0;
    if (queue_p && pos < ring_queue_rx->_nmemb)
    {
        rst = queue_p + pos * sizeof(TAG);
    }
    return rst;
}

TAG_TX *TX_queue_ptr(Ring_Queue_TX *ring_queue_tx, int pos)
{
    TAG_TX *rst = 0;
    if (ring_queue_tx && pos < ring_queue_tx->_nmemb)
    {
        rst = ring_queue_tx->_queue_p[pos];
    }
    return rst;
}

#endif /* !_APP_H_ */