/*

Copyright 2019 Comcast Cable Communications Management, LLC 
Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at 
http://www.apache.org/licenses/LICENSE-2.0 
Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License. 
SPDX-License-Identifier: Apache-2.0

*/

#ifndef _COMMON_H_
#define _COMMON_H_
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define MAX_BLOCK_SIZE 1000
#define COUNT_AUXILARY_BYTES 6
#define MAX_PACK_SIZE (MAX_BLOCK_SIZE + COUNT_AUXILARY_BYTES)
#define CIPHER_ALGO EVP_aes_256_cbc

/*SMALL PROTOCOL*/

#define END_OF_TRANSMISSION 0
#define TRANSMISSION_CONTINUES 1
#define TRANSMISSION_ERROR 2

size_t base64_encode(const uint8_t *data, size_t data_size, uint8_t *buffer, size_t buffer_size);
size_t base64_decode(const uint8_t *b64_data, size_t b64_data_size, uint8_t *buffer, size_t buffer_size);
int read_block(int sock, uint8_t *buffer, size_t buffer_size);
int write_block(int sock, uint8_t *buffer, size_t buf_size);

void print_base64(const uint8_t *data, size_t dsize);

int aes_encrypt(
    const uint8_t *data,
    size_t data_size,
    uint8_t *buffer,
    size_t buffer_size,
    const uint8_t *key);

int aes_decrypt(
    const uint8_t *enc_data,
    size_t enc_data_size,
    uint8_t *buffer,
    size_t buffer_size,
    const uint8_t *key);

#endif
