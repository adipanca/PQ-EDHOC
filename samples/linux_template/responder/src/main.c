/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "edhoc.h"
#include "sock.h"
}

#define USE_IPV4

static const uint16_t EDHOC_PORT = 56840;
static const char *SERVER_ADDR = "0.0.0.0";

// simple CBOR map {4: h'00'} and {4: h'01'} for ID_CREDs
static const uint8_t ID_CRED_I_RAW[] = {0xA1, 0x04, 0x41, 0x00};
static const uint8_t ID_CRED_R_RAW[] = {0xA1, 0x04, 0x41, 0x01};

static int start_udp_server(int *sockfd)
{
    int err;
    struct sockaddr_in servaddr;
    err = sock_init(SOCK_SERVER, SERVER_ADDR, IPv4, &servaddr,
                    sizeof(servaddr), sockfd);
    return err;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
    return ok;
}

enum err tx(void *sock, struct byte_array *data)
{
    ssize_t n = send(*((int *)sock), data->ptr, data->len, 0);
    if (n < 0 || (size_t)n != data->len) {
        perror("send");
        return unexpected_result_from_ext_lib;
    }
    return ok;
}

enum err rx(void *sock, struct byte_array *data)
{
    ssize_t n = recv(*((int *)sock), data->ptr, data->len, MSG_WAITALL);
    if (n < 0) {
        perror("recv");
        return unexpected_result_from_ext_lib;
    }
    data->len = (uint32_t)n;
    return ok;
}

/* Legacy placeholder: responder moved to main.cpp for C++ build. */
