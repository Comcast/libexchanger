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

#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <ifaddrs.h>

#include "common.h"

//Default values
#define SERVER_DEFAULT_ID "server"
#define CLIENT_DEFAULT_ID "client"
#define AAD_DEFAULT "Use SPAKE2+ latest version."
#define PORT_DEFAULT 12345
#define DEFAULT_DIRECTORY "/tmp"
#define CLIENT_MSG_PREFIX "client_message_"
#define CLIENT_FILE_PREFIX "client_file_"
#define MAX_BLOCK_SIZE 1000
#define COUNT_AUXILARY_BYTES 6
#define MAX_PACK_SIZE (MAX_BLOCK_SIZE + COUNT_AUXILARY_BYTES)
#define DATE_MAX_SIZE 16

/*SMALL PROTOCOL*/

#define END_OF_TRANSMISSION 0
#define TRANSMISSION_CONTINUES 1

char *g_pw_ptr = NULL;
char *g_srv_id_ptr = SERVER_DEFAULT_ID;
char *g_client_id_ptr = CLIENT_DEFAULT_ID;
char *g_aad_ptr = AAD_DEFAULT;
uint16_t g_port = PORT_DEFAULT;
uint32_t g_max_connections_count = 0;
char *g_hash_ptr = SPAKE2PLUS_HASH_SHA256_SEARCH_NAME;
char *g_group_ptr = SPAKE2PLUS_GROUP_P256_SEARCH_NAME;
char *g_mac_ptr = SPAKE2PLUS_HMAC_SEARCH_NAME;
char *g_dir_ptr = DEFAULT_DIRECTORY;
char *g_itf_ptr = NULL;

struct sockaddr_in g_client;
socklen_t g_client_len = sizeof(g_client);

SPAKE2PLUS *spake2_instance = NULL;

void usage(char *a_my_name)
{
    printf("%s usage:\n", a_my_name);
    printf("(version: %s)\n", spake2plus_version());
    printf("  %s <options>\n", a_my_name);
    printf("  a) used only to initialize server with new password and exit:\n");
    printf("\t-p <password> - password\n");

    printf("  b) used only to accept connection:\n");
    printf("\t[-P <server port>] - UDP port number to open, default is %d\n", PORT_DEFAULT);
#ifdef __linux__
    printf("\t[-i <interface name>] - name of interface to be used, by default are used all interfaces\n");
#endif
    printf("\t[-d <directory>] - directory to store files and messages, default is %s\n", DEFAULT_DIRECTORY);

    printf("  c) used for both cases above and with identical set of options from below per \"init & accept-connections\" pair:\n");
    printf("\t[-a <additional string>] - default is \"%s\"\n", AAD_DEFAULT);
    printf("\t[-s <server id>] - default is \"%s\"\n", SERVER_DEFAULT_ID);
    printf("\t[-c <client id>] - default is \"%s\"\n", CLIENT_DEFAULT_ID);
    printf("\t[-G <EC group name>] - One of \"P-256\", \"P-384\", \"P-521\", default is %s\n", SPAKE2PLUS_GROUP_P256_SEARCH_NAME);
    printf("\t[-H <hash function name>] - \"SHA256\" or \"SHA512\", default is %s\n", SPAKE2PLUS_HASH_SHA256_SEARCH_NAME);
    printf("\t[-M <MAC function name>] - \"HMAC\" or \"CMAC\", default is %s\n", SPAKE2PLUS_HMAC_SEARCH_NAME);
    printf("\t[-n <max number of processed clients>] - maximal number of processed clients,  default is 0 (unlimited)\n");
    exit(1);
}

uint8_t save_bignum(const char *fname, BIGNUM *number)
{
    uint8_t result = 0;
    size_t size = BN_num_bytes(number);
    void *ptr = NULL;

    ptr = malloc(size);
    if (NULL == ptr)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", size);
        return (result);
    }

    memset(ptr, 0, size);
    BN_bn2bin(number, ptr);

    size_t b64_size = size * 2;
    void *b64_ptr = NULL;
    b64_ptr = malloc(b64_size);
    if (NULL == b64_ptr)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", b64_size);
        return (result);
    }
    memset(b64_ptr, 0, b64_size);
    size_t real_size = base64_encode(ptr, size, b64_ptr, b64_size);
    if(real_size > 0)
    {
        FILE *f = fopen(fname, "w");
        if (f != NULL)
        {
            fwrite(b64_ptr, real_size, 1, f);
            fclose(f);
            result = 1;
        }
        else
        {
            printf("[FATAL] Error creating file %s\n", fname);
        }
    }
    else
    {
        printf("[FATAL] Error converting to base64.");
    }
    free(ptr);
    free(b64_ptr);

    return result;
}

uint8_t save_point(const char *fname, SPAKE2PLUS *instance, EC_POINT *number)
{
    BN_CTX *ctx = NULL;
    uint8_t result = 0;
    if (NULL == (ctx = BN_CTX_secure_new()))
    {
        printf("[FATAL] Error creating ctx for converting L EC point.\n");
        return 0;
    }

    BN_CTX_start(ctx);
    size_t size = EC_POINT_point2oct(instance->group,
                                     number,
                                     EC_GROUP_get_point_conversion_form(instance->group),
                                     NULL,
                                     0,
                                     ctx);
    void *ptr = NULL;
    ptr = malloc(size);
    if (NULL == ptr)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", size);
        return (0);
    }
    memset(ptr, 0, size);
    if (size == EC_POINT_point2oct(instance->group,
                                   number,
                                   EC_GROUP_get_point_conversion_form(instance->group),
                                   ptr,
                                   size,
                                   ctx))

    {
        size_t b64_size = size * 2;
        void *b64_ptr = NULL;
        b64_ptr = malloc(b64_size);
        if (NULL == b64_ptr)
        {
            printf("[FATAL] Error while allocating %zu bytes of memory\n", b64_size);
            return (0);
        }
        memset(b64_ptr, 0, b64_size);
        size_t real_size = base64_encode(ptr, size, b64_ptr, b64_size);
        if(real_size > 0)
        {
            FILE *f = fopen(fname, "w");
            if (f != NULL)
            {
                fwrite(b64_ptr, real_size, 1, f);
                fclose(f);
                result = 1;
            }
            else
            {
                printf("[FATAL] Error creating file %s\n", fname);
            }
        }
        else
        {
            printf("[FATAL] Error converting to base64. Expected buffer size %zu, obtained %zu bytes\n",
                    b64_size, base64_encode(ptr, size, b64_ptr, b64_size));
        }
        free(b64_ptr);
    }
    else
    {
        printf("[FATAL] Error converting EC point to array.\n");
    }

    free(ptr);
    BN_CTX_CHECK_NULL_AND_FREE(ctx);
    return result;
}

void load_array(const char *fname, uint8_t **buffer, size_t *size)
{
    *buffer = NULL;
    *size = 0;

    FILE *f = fopen(fname, "r");
    if (f == NULL)
    {
        printf("[FATAL] Error opening file %s\n", fname);
        return;
    }

    struct stat st;
    if ((fstat(fileno(f), &st) != 0) || (! S_ISREG(st.st_mode))) {
        printf("[FATAL] Error getting size of file %s\n", fname);
    }
    size_t file_size = st.st_size;

    //+1 because of zero byte
    void *b64_ptr = NULL;
    b64_ptr = malloc(file_size + 1);
    if (NULL == b64_ptr)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", file_size + 1);
        fclose(f);
        return;
    }
    memset(b64_ptr, 0, file_size + 1);
    size_t fread_size = fread(b64_ptr, file_size, 1, f);
    fclose(f);
    if(1 != fread_size)
    {
        printf("[FATAL] Error reading from file, expected one chunk, read %zu.\n", fread_size);
        free(b64_ptr);
        return;
    }

    void *ptr = NULL;
    ptr = malloc(file_size);
    if (NULL == ptr)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", file_size);
        free(b64_ptr);
        return;
    }
    memset(ptr, 0, file_size);
    size_t real_size = base64_decode(b64_ptr, file_size + 1, ptr, file_size);
    if(real_size > 0)
    {
        *buffer = ptr;
        *size = real_size;
    }
    else
    {
        printf("[FATAL] Error converting from base64. Filesize = %zu.\n", file_size);
        free(ptr);
    }

    free(b64_ptr);
}

uint8_t init_password()
{
    assert(g_pw_ptr != NULL);
    int return_value;

    if (SPAKE2PLUS_OK != (return_value = spake2plus_pwd_init(
                              spake2_instance,
                              g_pw_ptr,
                              strlen(g_pw_ptr))))
    {
        printf("[FATAL] Failed to initialize SPAKE2+ server password.\n");
        return 0;
    }

    return save_point("L.dat", spake2_instance, spake2_instance->L) &&
        save_bignum("w0.dat", spake2_instance->w0);
}

int open_socket(uint16_t port)
{
    struct sockaddr_in si_me;
    int sock = 0;
    int retval = 0;
    struct ifreq ifr;
    struct sockaddr_in addr = { .sin_addr.s_addr = htonl(INADDR_ANY) };
    struct sockaddr si_me_raw;

    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        return 0;

#ifdef __linux__
    if (NULL != g_itf_ptr)
    {
        const size_t len = strnlen(g_itf_ptr, IFNAMSIZ);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, g_itf_ptr, IFNAMSIZ-1);

        if (len == IFNAMSIZ)
        {
            fprintf(stderr, "Too long iface name.\n");
            retval = -1;
            goto err;
        }
        assert(sizeof(ifr.ifr_addr) == sizeof(addr));
        memcpy(&addr, &ifr.ifr_addr, sizeof(ifr.ifr_addr));

        struct ifaddrs *ifa = NULL;
        struct ifaddrs *ifa_tmp = NULL;
        if (getifaddrs(&ifa) == -1)
        {
            fprintf(stderr, "Getifaddrs failed.\n");
            retval = -1;
            goto err;
        }
        ifa_tmp = ifa;
        while (ifa_tmp)
        {
            if (!strcmp(ifa_tmp->ifa_name, ifr.ifr_name) &&
                    ifa_tmp->ifa_addr && (ifa_tmp->ifa_addr->sa_family == AF_INET))
            {
                addr.sin_addr.s_addr =
                    ((struct sockaddr_in *)ifa_tmp->ifa_addr)->sin_addr.s_addr;
                break;
            }
            ifa_tmp = ifa_tmp->ifa_next;
        }
        freeifaddrs(ifa);

        if (addr.sin_addr.s_addr == 0)
        {
            fprintf(stderr, "Interface not found\n");
            retval = -1;
            goto err;
        }
    }
    else
#endif
    {
        memcpy(&ifr.ifr_addr, &addr, sizeof(ifr.ifr_addr));
    }

    //Open any local tcp port
    memset((char *)&si_me_raw, 0, sizeof(si_me_raw));
    memset((char *)&si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port); //Choose any port number
    assert(sizeof(si_me.sin_addr.s_addr) == sizeof(addr.sin_addr.s_addr));
    memcpy(&(si_me.sin_addr.s_addr), &(addr.sin_addr.s_addr), sizeof(addr.sin_addr.s_addr));
    assert(sizeof(si_me_raw) == sizeof(si_me));
    memcpy(&(si_me_raw), &(si_me), sizeof(si_me));

    int on = 1;
    retval = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof on);
    if (retval != 0)
    {
        fprintf(stderr, "Setsockopt SO_REUSEADDR failed, errno == %d.\n", errno);
        goto err;
    }
    on = 1;
    retval = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof on);
    if (retval != 0)
    {
        fprintf(stderr, "Setsockopt SO_REUSEPORT failed, errno == %d.\n", errno);
        goto err;
    }

    if ((retval = bind(sock, &si_me_raw, sizeof(si_me))) < 0)
    {
        fprintf(stderr, "Binding a socket failed, exiting. errno == %d\n", errno);
        goto err;
    }
    listen(sock, 1);
err:
    if (retval != 0)
    {
        if (sock >= 0)
        {
            retval = close(sock);
            if ((retval != 0) && (retval != EBADF))
            {
                retval = shutdown(sock, 2);
                if (retval != 0)
                    fprintf(stderr, "Failed to close the socket, exiting.\n");
            }
        }
        return 0;
    }
    return sock;
}

int wait_for_connection(int sock)
{
    struct sockaddr sa_client;
    socklen_t clientlen = sizeof(sa_client);

    memset(&sa_client, 0, sizeof(sa_client));

    return accept(sock, &sa_client, &clientlen);
}

int key_exchange(int sock)
{
    uint8_t *pB = NULL;
    size_t pB_len = 0;
    uint8_t Fb[EVP_MAX_MD_SIZE];
    size_t Fb_len = 0;
    int return_value = 1;

    if (SPAKE2PLUS_OK != (return_value = spake2plus_setup_protocol(
                              spake2_instance)))
    {
        printf("[FATAL] Failed to setup SPAKE2+ protocol from the client side.\n");
        return 0;
    }
    if (SPAKE2PLUS_OK != (return_value = spake2plus_get_own_pA_or_pB(
                              NULL,
                              &pB_len,
                              spake2_instance)))
    {
        printf("[FATAL] Failed to get SPAKE2+ setup protocol value length. Err = %d\n", return_value);
        return 0;
    }
    if (NULL == (pB = malloc(pB_len)))
    {
        printf("[FATAL] Failed to allocate %zu bytes.\n", pB_len);
        return 0;
    }
    if (SPAKE2PLUS_OK != (return_value = spake2plus_get_own_pA_or_pB(
                              pB,
                              &pB_len,
                              spake2_instance)))
    {
        printf("[FATAL] Failed to get pB SPAKE2+ protocol value. Err = %d\n", return_value);
        return_value = 0;
        goto err;
    }

    //Read pA from peer
    uint8_t buffer[2000];
    int data_size = read_block(sock, buffer, sizeof(buffer));
    if (data_size < 0)
    {
        printf("[FATAL] Failed to read pA from the client side.\n");
        return_value = 0;
        goto err;
    }
    if (write_block(sock, pB, pB_len) <= 0)
    {
        printf("[FATAL] Failed to send pB to the client.\n");
        return_value = 0;
        goto err;
    }

    if (SPAKE2PLUS_OK != (return_value = spake2plus_derive_confirmation_keys(
                              Fb,
                              &Fb_len,
                              spake2_instance,
                              buffer,
                              data_size)))
    {
        printf("[FATAL] Failed to calculate confirmation messages on the server side.\n");
        return_value = 0;
        goto err;
    }

    if (write_block(sock, Fb, Fb_len) <= 0)
    {
        printf("[FATAL] Failed to send Fb to the client.\n");
        return_value = 0;
        goto err;
    }
    //Read Fa from peer
    data_size = read_block(sock, buffer, sizeof(buffer));
    if (data_size < 0)
    {
        printf("[FATAL] Failed to get Fa from the client.\n");
        return_value = 0;
        goto err;
    }

    if (SPAKE2PLUS_OK != (return_value = spake2plus_verify(spake2_instance, buffer, data_size)))
    {
        printf("[INFO]  Can't derive common key, disconnecting...\n");
        return_value = 0;
        goto err;
    }

    size_t Ke_len;
    uint8_t Ke[EVP_MAX_MD_SIZE];
    if (SPAKE2PLUS_OK != (return_value = spake2plus_get_key_Ke(Ke, &Ke_len, spake2_instance)))
    {
        printf("[FATAL] Failed to get Ke on the server side.\n");
        return_value = 0;
        goto err;
    }
    return_value = 1;
err:
    if(NULL != pB)
    {
        free(pB);
        pB = NULL;
    }

    if(return_value)
        printf("[INFO]  Key exchange successfully finished\n");
    else
        printf("[INFO]  Key exchange failed.\n");
    return (return_value);
}

void data_exchange(int sock)
{
    size_t sock_packet_size = MAX_PACK_SIZE + EVP_CIPHER_block_size(CIPHER_ALGO()) - 1;
    size_t packet_size = MAX_PACK_SIZE + 2 * EVP_CIPHER_block_size(CIPHER_ALGO()) - 1;
    uint8_t *buffer1 = NULL;
    uint8_t *buffer2 = NULL;
    uint8_t *buffer_ack = NULL;
    const char str_to_send[] = "Super secret data from server";
    int tries = 1;
    uint8_t flags = TRANSMISSION_ERROR;
    FILE *f = NULL;
    int ret_code = 1;
    time_t t = time(NULL);
    struct tm tim = *localtime(&t);
    static char timestamp[DATE_MAX_SIZE] = "";
    uint8_t acknowledge[COUNT_AUXILARY_BYTES] = { 'a', END_OF_TRANSMISSION, 0, 0, 0, 0};
    char *file_name = NULL;
    size_t file_name_len = 0;
    char file_mode[3] = "";

    file_name_len = strlen(g_dir_ptr) + DATE_MAX_SIZE + sizeof(CLIENT_MSG_PREFIX) + 2;
    file_name = malloc(file_name_len);
    if (NULL == file_name)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", file_name_len);
        return;
    }
    memset(file_name, 0 , file_name_len);
    buffer1 = malloc(sock_packet_size);
    if (NULL == buffer1)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", sock_packet_size);
        free(file_name);
        return;
    }
    buffer2 = malloc(packet_size);
    if (NULL == buffer2)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", packet_size);
        free(file_name);
        free(buffer1);
        return;
    }
    buffer_ack = malloc(sock_packet_size);
    if (NULL == buffer_ack)
    {
        printf("[FATAL] Error while allocating %zu bytes of memory\n", sock_packet_size);
        free(file_name);
        free(buffer1);
        free(buffer2);
        return;
    }
    int ack_enc_size = aes_encrypt(
        acknowledge,
        COUNT_AUXILARY_BYTES,
        buffer_ack,
        sock_packet_size,
        spake2_instance->Ke);

    if (ack_enc_size <= 0)
    {
        printf("[FATAL] Can't encrypt a message.\n");
        tries = 0;
    }
    while (tries-- > 0)
    {
        //send data to a client
        size_t dsize = sizeof(str_to_send);
        int enc_size = aes_encrypt(
            (const uint8_t *)str_to_send,
            dsize,
            buffer1,
            MAX_BLOCK_SIZE,
            spake2_instance->Ke);

        if (enc_size <= 0)
        {
            printf("[FATAL] Can't encrypt a message.\n");
            break;
        }
        printf("--- Sent from server (encrypted data):\n");

        print_base64(buffer1, enc_size);

        if (write_block(sock, buffer1, enc_size) <= 0)
        {
            printf("[FATAL] Can't send a message.\n");
            break;
        }

        //get data from client
        do
        {
            enc_size = read_block(sock, buffer1, sock_packet_size);
            if (enc_size > 0)
            {
                printf("--- Received from client (encrypted data):\n");
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
                    ret_code = 0;
                    break;
                }
                else if (dsize - COUNT_AUXILARY_BYTES > 0)
                {
                    printf("--- Received from client (decrypted data), base64 format, type %c:\n", buffer2[0]);
                    print_base64(buffer2 + COUNT_AUXILARY_BYTES, dsize - COUNT_AUXILARY_BYTES);
                    printf("--- Received from client (decrypted data), raw format:\n%s\n", (const char *)(buffer2 + COUNT_AUXILARY_BYTES));
                }
                else
                    printf("--- Received from client empty message, type %c.\n", buffer2[0]);
                if ((dsize - COUNT_AUXILARY_BYTES) !=
                        ((size_t)(buffer2[2])) + (((size_t)(buffer2[3])) << 8) + (((size_t)(buffer2[4])) << 16) + (((size_t)(buffer2[5])) << 24))
                {
                    printf("[FATAL] Received data length == %zu differ from expected == %zu.\n",
                            ((size_t)(buffer2[2])) + (((size_t)(buffer2[3])) << 8) + (((size_t)(buffer2[4])) << 16) + (((size_t)(buffer2[5])) << 24),
                            dsize - COUNT_AUXILARY_BYTES);
                    ret_code = 0;
                    break;
                }
                flags = buffer2[1];
                t = time(NULL);
                tim = *localtime(&t);
                if(0 == strftime(timestamp, DATE_MAX_SIZE, "%Y%m%d_%H%M%S", &tim))
                {
                    printf("[FATAL] Can't get date or time for file name.\n");
                    ret_code = 0;
                    break;
                }
                switch(buffer2[0])
                {
                    case 'm':
                        if(0 == sprintf(file_name, "%s%s"CLIENT_MSG_PREFIX"%s",
                                g_dir_ptr,
                                ((g_dir_ptr[strlen(g_dir_ptr) - 1] == '/') ? "" : "/"),
                                timestamp))
                        {
                            printf("[FATAL] Can't create file name.\n");
                            ret_code = 0;
                        }
                        strcpy(file_mode, "a");
                        dsize--;
                        break;
                    case 'f':
                        if (!strcmp(file_name, ""))
                            if(0 == sprintf(file_name, "%s%s"CLIENT_FILE_PREFIX"%s",
                                    g_dir_ptr,
                                    ((g_dir_ptr[strlen(g_dir_ptr) - 1] == '/') ? "" : "/"),
                                    timestamp))
                            {
                                printf("[FATAL] Can't create file name.\n");
                                ret_code = 0;
                            }
                        strcpy(file_mode, "ab");
                        break;
                    default:
                        printf("[FATAL] Can't recognize if it is message of file.\n");
                        ret_code = 0;
                }
                if(!ret_code)
                    break;
                printf("[DEBUG] File name is %s.\n", file_name);
                f = fopen(file_name, file_mode);
                if (NULL == f)
                {
                    printf("[FATAL] Can't open file %s for saving data, please restart with correct -d parameter.\n", file_name);
                    ret_code = 0;
                    break;
                }
                fwrite(buffer2 + COUNT_AUXILARY_BYTES, dsize - COUNT_AUXILARY_BYTES, 1, f);
                if ('m' == buffer2[0])
                {
                    fwrite("\n", 1, 1, f);
                    strcpy(file_name, "");
                }
                fclose(f);
                f = NULL;
                if (write_block(sock, buffer_ack, ack_enc_size) <= 0)
                {
                    printf("[FATAL] Can't send a message.\n");
                    ret_code = 0;
                    break;
                }
            }
            else
            {
                flags = END_OF_TRANSMISSION;
            }

        }while (TRANSMISSION_CONTINUES == flags);
    }

    if(NULL != file_name)
    {
        free(file_name);
        file_name = NULL;
    }
    free(buffer1);
    free(buffer2);
    free(buffer_ack);
}

void serve_client(int sock)
{
    if (key_exchange(sock))
    {
        data_exchange(sock);
    }
}

uint8_t prepare_server()
{
    assert(NULL != spake2_instance);

    uint8_t *buf_pL = NULL;
    uint8_t *buf_pw0 = NULL;
    size_t buf_pL_len = 0;
    size_t buf_pw0_len = 0;
    uint8_t result = 1;

    load_array("L.dat", &buf_pL, &buf_pL_len);
    if (buf_pL == NULL)
        return 0;

    load_array("w0.dat", &buf_pw0, &buf_pw0_len);
    if (buf_pw0 == NULL)
        return 0;

    if (SPAKE2PLUS_OK != spake2plus_load_L_w0(
                             spake2_instance,
                             buf_pL,
                             buf_pL_len,
                             buf_pw0,
                             buf_pw0_len))
    {
        printf("[FATAL] Failed to load L and w0 values for server instance.\n");
        result = 0;
    }
    free(buf_pL);
    free(buf_pw0);
    return result;
}

void parse_command_line(int argc, char *argv[])
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "P:p:i:s:c:a:d:G:H:M:n:h?")) != -1)
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
        case 'd':
            g_dir_ptr = optarg;
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
        case 'i':
            g_itf_ptr = optarg;
            break;
        case 'n':
            g_max_connections_count = atoi(optarg);
            break;
        case '?':
        case 'h':
            usage(argv[0]);
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    parse_command_line(argc, argv);

    if (SPAKE2PLUS_OK != spake2plus_init(
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
                             SPAKE2PLUS_SERVER))
    {
        printf("[FATAL] Failed to initialize SPAKE2+ server instance.\n");
        exit(2);
    }

    if (g_pw_ptr != NULL)
    {
        init_password();
    }
    else
    {
        if (prepare_server())
        {
            int listen_sock = open_socket(g_port);
            if (listen_sock == 0)
            {
                printf("[FATAL] Couldn't open port %d for listening.\n", g_port);
            }
            else
            {
                printf("[INFO]  Listening to socket %d\n", listen_sock);

                int client_sock = 0;
                int retval = 0;
                uint64_t count_of_connections = 0;
                while (((g_max_connections_count == 0) || (count_of_connections < g_max_connections_count)) && ((client_sock = wait_for_connection(listen_sock)) > 0))
                {
                    printf("[INFO]  New client accepted\n");
                    serve_client(client_sock);
                    retval = close(client_sock);
                    if ((retval != 0) && (retval != EBADF))
                    {
                        retval = shutdown(client_sock, 2);
                        if (retval != 0)
                            fprintf(stderr, "Failed to close the socket, exiting.\n");
                    }
                    printf("[INFO]  Client disconnected\n");
                    if (g_max_connections_count)
                        ++count_of_connections;
                }
                printf("[INFO]  Exiting...\n");
                retval = close(listen_sock);
                if ((retval != 0) && (retval != EBADF))
                {
                    retval = shutdown(client_sock, 2);
                    if (retval != 0)
                        fprintf(stderr, "Failed to close the socket, exiting.\n");
                }
            }
        }
    }
    spake2plus_free(spake2_instance);
    spake2plus_openssl_cleanup();

    return 0;
}
