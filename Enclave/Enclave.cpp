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

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */

#include <stdlib.h>
#include <string.h>
#include <typeinfo> // for type_id

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <cstdio>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84};

static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde};

void TX_Write(Ring_Queue_TX *ring_queue_tx)
{
    TAG_TX *tag_p;
    tag_p = TX_queue_ptr(ring_queue_tx, ring_queue_tx->_write_now);
    if (tag_p->tag_value == CAN_WRITE)
    {
        tag_p->tag_value = WRITING;
    }
}

void TX_Write_Over(Ring_Queue_TX *ring_queue_tx, const u_char *header_ptr, int header_length, const u_char *payload_ptr, int payload_length)
{
    TAG_TX *tag_p;
    tag_p = TX_queue_ptr(ring_queue_tx, ring_queue_tx->_write_now);
    if (tag_p->tag_value == WRITING)
    {
        tag_p->header_ptr = header_ptr;
        tag_p->header_len = header_length;
        tag_p->payload_ptr = payload_ptr;
        tag_p->payload_len = payload_length;
        EVP_CIPHER_CTX *ctx;
        int outlen, tmplen;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        EVP_EncryptUpdate(ctx, tag_p->encrypted_payload_ptr, &outlen, payload_ptr, payload_length);
        tag_p->tag_value = CAN_READ;
        ring_queue_tx->_write_now = (ring_queue_tx->_write_now + 1) % ring_queue_tx->_nmemb;
    }
}

void RX_Read(Ring_Queue_RX *ring_queue_rx)
{
    TAG *tag_p = 0;

    tag_p = (TAG *)RX_queue_ptr(ring_queue_rx->_queue_p, ring_queue_rx->_read_now, ring_queue_rx);
    if (tag_p->tag_value == CAN_READ)
    {
        tag_p->tag_value = READING;
    }
}

void RX_Read_Over(Ring_Queue_RX *ring_queue_rx, Ring_Queue_TX *ring_queue_tx)
{
    TAG *tag_p = 0;

    tag_p = (TAG *)RX_queue_ptr(ring_queue_rx->_queue_p, ring_queue_rx->_read_now, ring_queue_rx);
    if (tag_p->tag_value == READING)
    {
        if (tag_p->payload_ptr != NULL)
        {
            TX_Write(ring_queue_tx);
            TX_Write_Over(ring_queue_tx, tag_p->header_ptr, tag_p->header_len, tag_p->payload_ptr, tag_p->payload_len);
            tag_p->tag_value = CAN_WRITE;
            ring_queue_rx->_read_now = (ring_queue_rx->_read_now + 1) % ring_queue_rx->_nmemb;
        }
    }
}

void read_buffer_inEncalve(Ring_Queue_RX *ring_queue_rx, Ring_Queue_TX *ring_queue_tx)
{
    while (1)
    {
        RX_Read(ring_queue_rx);
        RX_Read_Over(ring_queue_rx, ring_queue_tx);
    }
}