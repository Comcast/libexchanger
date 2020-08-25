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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <spake2plus.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>

#include "common.h"

#define SERVER_DEFAULT_ID "server"
#define CLIENT_DEFAULT_ID "client"
#define AAD_DEFAULT "Use SPAKE2+ latest version."
#define PORT_DEFAULT 12345
#define MESSAGE_DEFAULT "Super secret data from client"

char *g_pw_ptr = NULL;
char *g_srv_id_ptr = SERVER_DEFAULT_ID;
char *g_client_id_ptr = CLIENT_DEFAULT_ID;
char *g_aad_ptr = AAD_DEFAULT;
char *g_addr_ptr = NULL;
uint16_t g_port = PORT_DEFAULT;
char *g_hash_ptr = SPAKE2PLUS_HASH_SHA256_SEARCH_NAME;
char *g_group_ptr = SPAKE2PLUS_GROUP_P256_SEARCH_NAME;
char *g_mac_ptr = SPAKE2PLUS_HMAC_SEARCH_NAME;
char *g_msg_ptr = NULL;
char *g_file_ptr = NULL;
uint8_t *pA = NULL;
size_t pA_len = 0;
static uint8_t g_complete_packet[MAX_PACK_SIZE];
static uint8_t g_file_buffer[MAX_BLOCK_SIZE];

SPAKE2PLUS *spake2_instance = NULL;

void usage(char *a_my_name)
{
    printf("%s usage:\n", a_my_name);
    printf("(version: %s)\n", spake2plus_version());
    printf("  %s <options>\n", a_my_name);
    printf("\t-p <password> - Password\n");
    printf("\t-A <Server address> - IP address to connect to\n");
    printf("\t[-P <server port>] - UDP port number to conect to, default is %d\n", PORT_DEFAULT);
    printf("\t[-s <server id>] - default is %s\n", SERVER_DEFAULT_ID);
    printf("\t[-c <client id>] - default is %s\n", CLIENT_DEFAULT_ID);
    printf("\t[-m <message>]   - message to be sent, default is '%s'\n", MESSAGE_DEFAULT);
    printf("\t[-f <path to file>] - file to be sent\n");
    printf("\t[-a <additional string>] - default is %s\n", AAD_DEFAULT);
    printf("\t[-G <EC group name>] - One of P-256, P-384, P-521, default is %s\n", SPAKE2PLUS_GROUP_P256_SEARCH_NAME);
    printf("\t[-H <hash function name>] - SHA256 or SHA512, default is %s\n", SPAKE2PLUS_HASH_SHA256_SEARCH_NAME);
    printf("\t[-M <MAC function name>] - HMAC or CMAC, default is %s\n", SPAKE2PLUS_HMAC_SEARCH_NAME);
    exit(1);
}

int open_socket(char *address, uint16_t port)
{
    int sock = 0;
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        return 0;

    //Open any local udp port
    struct sockaddr_in servaddr;
    struct sockaddr servaddr_raw;

    memset((char *)&servaddr_raw, 0, sizeof(servaddr_raw));
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_addr.s_addr = inet_addr(address);
    servaddr.sin_port = htons(port);
    servaddr.sin_family = AF_INET;

    assert(sizeof(servaddr_raw) == sizeof(servaddr));
    memcpy(&servaddr_raw, &servaddr, sizeof(servaddr));

    // connect to server
    if (connect(sock, &servaddr_raw, sizeof(servaddr)) < 0)
    {
        printf("\n Error : Connect Failed \n");
        int retval = close(sock);
        if ((retval != 0) && (retval != EBADF))
        {
            retval = shutdown(sock, 2);
            if (retval != 0)
                fprintf(stderr, "Failed to close the socket, exiting.\n");
        }
        return 0;
    }

    return sock;
}

void parse_command_line(int argc, char *argv[])
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "p:s:c:a:m:f:P:A:G:H:M:h?")) != -1)
    {
        switch (opt)
        {
        //New password was given.
        case 'p':
            g_pw_ptr = optarg;
            break;
        case 's':
            g_srv_id_ptr = optarg;
            break;
        case 'c':
            g_client_id_ptr = optarg;
            break;
        case 'a':
            g_aad_ptr = optarg;
            break;
        case 'm':
            g_msg_ptr = optarg;
            break;
        case 'f':
            g_file_ptr = optarg;
            break;
        case 'A':
            g_addr_ptr = optarg;
            break;
        case 'P':
            g_port = atoi(optarg);
            break;
        case 'G':
            g_group_ptr = optarg;
            break;
        case 'H':
            g_hash_ptr = optarg;
            break;
        case 'M':
            g_mac_ptr = optarg;
            break;
        case '?':
        case 'h':
            usage(argv[0]);
            break;
        }
    }
    if (g_pw_ptr == NULL)
    {
        printf("[FATAL] Password required!");
        usage(argv[0]);
    }

    if (g_addr_ptr == NULL)
    {
        printf("[FATAL] Server address required!");
        usage(argv[0]);
    }

    if (g_port == 0)
    {
        printf("[FATAL] Wrong port number!");
        usage(argv[0]);
    }

}

uint8_t prepare_client()
{
    int return_value;

    if (SPAKE2PLUS_OK != (return_value = spake2plus_init(
                              &spake2_instance,
                              g_client_id_ptr,
                              strlen(g_client_id_ptr),
                              g_srv_id_ptr,
                              strlen(g_srv_id_ptr),
                              g_aad_ptr,
                              strlen(g_aad_ptr),
                              g_group_ptr,
                              g_hash_ptr,
                              g_mac_ptr,
                              SPAKE2PLUS_CLIENT)))
    {
        printf("[FATAL] Failed to initialize SPAKE2+ client instance. Err = %d\n", return_value);
        return 0;
    }

    assert(NULL != spake2_instance);

    if (SPAKE2PLUS_OK != (return_value = spake2plus_pwd_init(
                              spake2_instance,
                              g_pw_ptr,
                              strlen(g_pw_ptr))))
    {
        printf("[FATAL] Failed to initialize SPAKE2+ client password. Err = %d\n", return_value);
        return 0;
    }

    if (SPAKE2PLUS_OK != (return_value = spake2plus_setup_protocol(
                              spake2_instance)))
    {
        printf("[FATAL] Failed to setup SPAKE2+ protocol from the client  side. Err = %d\n", return_value);
        return 0;
    }

    if (SPAKE2PLUS_OK != (return_value = spake2plus_get_own_pA_or_pB(
                              NULL,
                              &pA_len,
                              spake2_instance)))
    {
        printf("[FATAL] Failed to get SPAKE2+ setup protocol value length. Err = %d\n", return_value);
        return 0;
    }
    if (NULL == (pA = malloc(pA_len)))
    {
        printf("[FATAL] Failed to allocate %zu bytes.\n", pA_len);
        return 0;
    }

    if (SPAKE2PLUS_OK != (return_value = spake2plus_get_own_pA_or_pB(
                              pA,
                              &pA_len,
                              spake2_instance)))
    {
        printf("FATAL: Failed to get pB SPAKE2+ protocol value. Err = %d\n", return_value);
        return 0;
    }

    return 1;
}

int key_exchange(int sock)
{
    uint8_t Fa[EVP_MAX_MD_SIZE];
    size_t Fa_len = 0;
    int return_value = 0;

    //Read pB from server
    uint8_t buffer[2000];
    if (write_block(sock, pA, pA_len) <= 0)
        return 0;

    int data_size = read_block(sock, buffer, sizeof(buffer));
    if (data_size <= 0)
    {
        printf("[FATAL] Couldn't read date from server.\n");
        return 0;
    }

    if (SPAKE2PLUS_OK != (return_value = spake2plus_derive_confirmation_keys(
                              Fa,
                              &Fa_len,
                              spake2_instance,
                              buffer,
                              data_size)))
    {
        printf("[FATAL] Failed to calculate confirmation messages on the client side. Err = %d\n", return_value);
        return 0;
    }

    //Read Fb from server
    data_size = read_block(sock, buffer, sizeof(buffer));
    if (write_block(sock, Fa, Fa_len) <= 0)
        return 0;

    if (SPAKE2PLUS_OK != (return_value = spake2plus_verify(spake2_instance, buffer, data_size)))
    {
        printf("[INFO]  Can't derive common key, disconnecting...\n");
        return 0;
    }

    size_t Ke_len;
    uint8_t Ke[EVP_MAX_MD_SIZE];
    if (SPAKE2PLUS_OK != (return_value = spake2plus_get_key_Ke(Ke, &Ke_len, spake2_instance)))
    {
        printf("[FATAL] Failed to get Ke on the client side. Err = %d\n", return_value);
        return 0;
    }
    printf("[INFO]  Key exchange successfully finished\n");
    return 1;
}

int generate_packet(uint8_t *data, size_t data_len, uint8_t type_of_packet, uint8_t packets_left)
{
    memset(g_complete_packet, 0, MAX_PACK_SIZE);
    g_complete_packet[0] = type_of_packet;
    g_complete_packet[1] = packets_left;
    size_t tmp_data_len = 0;
    int i = 0;
    for (tmp_data_len = data_len, i = 2; tmp_data_len != 0; tmp_data_len >>= 8)
        g_complete_packet[i++] = (tmp_data_len & 0xFF);
    if(NULL != memcpy(g_complete_packet + COUNT_AUXILARY_BYTES,
            data,
            (data_len < MAX_BLOCK_SIZE) ? data_len : MAX_BLOCK_SIZE))
        return (((data_len < MAX_BLOCK_SIZE) ? data_len : MAX_BLOCK_SIZE) + COUNT_AUXILARY_BYTES);
    else
        return (-1);
}

int data_send_get_ack(int sock, uint8_t *complete_packet, size_t dsize, uint8_t *buffer1, uint8_t *buffer2, size_t packet_size)
{
    int enc_size = aes_encrypt(
        complete_packet,
        dsize,
        buffer1,
        packet_size,
        spake2_instance->Ke);

    if (enc_size <= 0)
    {
        printf("[FATAL] Can't encrypt a message.\n");
        return (0);
    }
    if (write_block(sock, buffer1, enc_size) <= 0)
    {
        printf("[FATAL] Can't send a message.\n");
        return (0);
    }
    enc_size = read_block(sock, buffer1, packet_size);
    if (enc_size > 0)
    {
        dsize = aes_decrypt(
            buffer1,
            enc_size,
            buffer2,
            packet_size,
            spake2_instance->Ke);
        if (dsize <= 0)
        {
            printf("[FATAL] Can't decrypt a message.\n");
            return (0);
        }
        else
            if ((buffer2[0] == 'a'))
                printf("--- Received Acknowledge from server.\n");
            else
                printf("--- Received something else: %s.\n", buffer2);
    }
    return (1);
}

void data_exchange(int sock)
{
    size_t packet_size = MAX_PACK_SIZE + EVP_CIPHER_block_size(CIPHER_ALGO()) - 1;
    uint8_t *buffer1 = NULL;
    uint8_t *buffer2 = NULL;
    const char str_to_send[] = MESSAGE_DEFAULT;
    int tries = 1;

    buffer1 = malloc(packet_size);
    if (NULL == buffer1)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", packet_size);
        return;
    }
    memset(buffer1, 0, packet_size);
    buffer2 = malloc(packet_size);
    if (NULL == buffer2)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", packet_size);
        free(buffer1);
        return;
    }
    memset(buffer2, 0, packet_size);
    while (tries-- > 0)
    {
        //get data from server
        size_t dsize;
        int enc_size = read_block(sock, buffer1, packet_size);
        if (enc_size > 0)
        {
            printf("--- Received from server (encrypted data):\n");
            print_base64(buffer1, enc_size);

            dsize = aes_decrypt(
                buffer1,
                enc_size,
                buffer2,
                packet_size,
                spake2_instance->Ke);
            if (dsize <= 0)
            {
                printf("[FATAL] Can't decrypt a message.\n");
                break;
            }
            else
            {
                printf("--- Received from server (decrypted data):\n");
                print_base64(buffer2, dsize);
                printf("%s\n", (const char *)buffer2);
            }
        }
        else
        {
            break;
        }

        //send data to a server
        uint8_t count_transmissions_left = (g_file_ptr == NULL) ? 0 : 1;
        count_transmissions_left += (g_msg_ptr == NULL) ? 0 : 1;

        if (NULL != g_msg_ptr)
        {
            dsize = strlen(g_msg_ptr) + 1;
            dsize = generate_packet((uint8_t *)g_msg_ptr, dsize, 'm',
                    (count_transmissions_left--) ? TRANSMISSION_CONTINUES : END_OF_TRANSMISSION);
            if (!data_send_get_ack(sock, g_complete_packet, dsize, buffer1, buffer2, packet_size))
                break;
        }
        else
        {
            dsize = sizeof(str_to_send);
            dsize = generate_packet((uint8_t *)str_to_send, dsize, 'm',
                    (count_transmissions_left--) ? TRANSMISSION_CONTINUES : END_OF_TRANSMISSION);
            if (!data_send_get_ack(sock, g_complete_packet, dsize, buffer1, buffer2, packet_size))
                break;
        }

        if (NULL != g_file_ptr)
        {
            FILE *f = fopen(g_file_ptr, "rb");
            if (NULL == f)
            {
                printf("[FATAL] Error opening file %s, errno == %d\n", g_file_ptr, errno);
                break;
            }

            struct stat st;
            if ((fstat(fileno(f), &st) != 0) || (! S_ISREG(st.st_mode))) {
                printf("[FATAL] Error getting size of file %s\n", g_file_ptr);
            }
            size_t file_size = st.st_size;
            if(!file_size)
                printf("[WARNING] File %s is empty, nothing is going to be sent.\n", g_file_ptr);
            size_t offset = 0;
            size_t fread_size = 0;
            uint8_t flag = END_OF_TRANSMISSION;
            for (offset = 0; offset < file_size; offset += MAX_BLOCK_SIZE)
            {
                if (((file_size - offset) <= MAX_BLOCK_SIZE))
                {
                    dsize = (file_size - offset);
                    flag = END_OF_TRANSMISSION;
                    fread_size = fread(g_file_buffer, (file_size - offset), 1, f);
                }
                else
                {
                    dsize = MAX_BLOCK_SIZE;
                    flag = TRANSMISSION_CONTINUES;
                    fread_size = fread(g_file_buffer, MAX_BLOCK_SIZE, 1, f);
                }
                if (1 != fread_size)
                {
                    printf("[FATAL] Error reading from file, expected one chunk, read %zu.\n", fread_size);
                    break;
                }
                if (0 == (dsize = generate_packet(g_file_buffer, dsize, 'f', flag)))
                {
                    printf("[FATAL] Failed to generate packet.\n");
                    break;
                }
                if (0 == (enc_size = data_send_get_ack(sock, g_complete_packet, dsize, buffer1, buffer2, packet_size)))
                    break;
            }
            fclose(f);
            if ((enc_size <= 0) || (1 != fread_size) || (0 == dsize))
                break;
        }

    }

    free(buffer1);
    free(buffer2);
}

int main(int argc, char *argv[])
{
    parse_command_line(argc, argv);

    if (prepare_client())
    {
        int sock = open_socket(g_addr_ptr, g_port);
        if (sock != 0)
        {
            printf("[INFO]  Connected to %s:%d.\n", g_addr_ptr, g_port);

            if (key_exchange(sock))
            {
                data_exchange(sock);
            }
            int retval = close(sock);
            if ((retval != 0) && (retval != EBADF))
            {
                retval = shutdown(sock, 2);
                if (retval != 0)
                    fprintf(stderr, "Failed to close the socket, exiting.\n");
            }
        }
        else
        {
            printf("[FATAL] Couldn't open port.\n");
        }
    }
    if (pA != NULL)
        free(pA);

    spake2plus_free(spake2_instance);
    spake2plus_openssl_cleanup();

    return 0;
}
