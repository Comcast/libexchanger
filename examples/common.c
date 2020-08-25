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

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <common.h>
#include <spake2plus.h>

size_t base64_encode(const uint8_t *data, size_t data_size, uint8_t *buffer, size_t buffer_size)
{
    BIO *sink, *b64;
    BUF_MEM *bptr;
    size_t res_size;

    assert(buffer != NULL);
    assert(data != NULL);

    if (data_size == 0)
    {
        return 0;
    }

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    sink = BIO_new(BIO_s_mem());
    BIO_push(b64, sink);

    BIO_write(b64, data, data_size);
    (void) BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    res_size = bptr->length;
    if (res_size < buffer_size)
    {
        memcpy(buffer, bptr->data, res_size);
    }
    else
    {
        res_size = 0;
    }

    BIO_free_all(b64);

    return res_size;
}

size_t base64_decode(const uint8_t *b64_data, size_t b64_data_size, uint8_t *buffer, size_t buffer_size)
{
    BIO *source, *b64;
    size_t res_size;

    assert(buffer != NULL);
    assert(b64_data != NULL);
    assert(buffer_size > 0);

    if (b64_data_size == 0)
    {
        return 0;
    }

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    source = BIO_new_mem_buf(b64_data, -1); // read-only source
    BIO_push(b64, source);

    res_size = BIO_read(b64, buffer, buffer_size);

    BIO_free_all(b64);

    return res_size;
}

int read_block(int sock, uint8_t *buffer, size_t buffer_size)
{
    uint16_t block_size = 0;
    int was_read = 0, to_read = 0;

    was_read = read(sock, &block_size, 2);
    if (was_read != 2)
        return -1;

    printf("[DEBUG] block_size = %d\n", block_size);

    if (block_size > buffer_size)
    {
        printf("[FATAL] Too large data block received from peer. Disconnecting.\n");
        return -1;
    }

    to_read = block_size;
    while (to_read > 0 && was_read >= 0)
    {
        was_read = read(sock, buffer, to_read);
        if (was_read > 0)
        {
            buffer += was_read;
            assert(was_read <= to_read);
            to_read -= was_read;
        }
    }
    printf("[DEBUG] read %d bytes\n", block_size);
    return was_read < 0 ? -1 : block_size;
}

int write_block(int sock, uint8_t *buffer, size_t buf_size)
{
    assert(buf_size <= 0xFFFFUL);
    size_t number_of_bytes = write(sock, &buf_size, 2);
    if(2 != number_of_bytes)
        return -1;
    return write(sock, buffer, buf_size);
}

int aes_encrypt(
    const uint8_t *data,
    size_t data_size,
    uint8_t *buffer,
    size_t buffer_size,
    const uint8_t *key)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    //buffer_size is user for assertion only so it won't be used in Release
    (void)buffer_size;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("[FATAL] Can't create context for AES encryption\n");
        return 0;
    }

    if (1 == EVP_EncryptInit_ex(ctx, CIPHER_ALGO(), NULL, key, NULL))
    {
        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if (1 == EVP_EncryptUpdate(ctx, buffer, &len, data, data_size))
        {
            ciphertext_len = len;

            /*
            * Finalise the encryption. Further ciphertext bytes may be written at
            * this stage.
            */
            if (1 == EVP_EncryptFinal_ex(ctx, buffer + len, &len))
            {
                ciphertext_len += len;
                assert(ciphertext_len <= (int)buffer_size);
            }
            else
            {
                printf("[FATAL] Can't encrypt a message\n");
                ciphertext_len = 0;
            }
        }
        else
        {
            printf("[FATAL] Can't encrypt a message\n");
            ciphertext_len = 0;
        }
    }
    else
    {
        printf("[FATAL] Can't init AES encryption\n");
        ciphertext_len = 0;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(
    const uint8_t *enc_data,
    size_t enc_data_size,
    uint8_t *buffer,
    size_t buffer_size,
    const uint8_t *key)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    //buffer_size is user for assertion only so it won't be used in Release
    (void)buffer_size;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("[FATAL] Can't create context for AES decryption\n");
        return 0;
    }

    if (1 == EVP_DecryptInit_ex(ctx, CIPHER_ALGO(), NULL, key, NULL))
    {
        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if (1 == EVP_DecryptUpdate(ctx, buffer, &len, enc_data, enc_data_size))
        {
            plaintext_len = len;

            /*
            * Finalise the decryption. Further plaintext bytes may be written at
            * this stage.
            */
            if (1 == EVP_DecryptFinal_ex(ctx, buffer + len, &len))
            {
                plaintext_len += len;
                assert(plaintext_len <= (int)buffer_size);
            }
            else
            {
                printf("[FATAL] Can't decrypt a message\n");
                plaintext_len = 0;
            }
        }
        else
        {
            printf("[FATAL] Can't decrypt a message\n");
            plaintext_len = 0;
        }
    }
    else
    {
        printf("[FATAL] Can't init AES decryption\n");
        plaintext_len = 0;
    }


    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void print_base64(const uint8_t *data, size_t dsize)
{
    assert(dsize > 0);
    size_t res_size_max = dsize * 2 + 16;
    uint8_t *buf = NULL;
    buf = malloc(res_size_max);
    if (NULL == buf)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", res_size_max);
        return;
    }
    memset(buf, 0, res_size_max);
    size_t base_size = base64_encode(data, dsize, buf, res_size_max);
    assert(base_size > 0);
    assert(base_size <= res_size_max);
    buf[base_size >= res_size_max ? res_size_max - 1 : base_size] = 0;
    printf("%s\n", (const char *)buf);
    free(buf);
}
