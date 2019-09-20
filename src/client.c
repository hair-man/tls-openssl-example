/**
 *  Filename: client.c
 *   Created: 2019-09-19 17:38:25
 *      Desc: TODO (some description)
 *    Author: hair-man
 *   Company: owner 
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>


#include <openssl/ssl.h>
#include <openssl/err.h>

#include <getopt.h>

#define MAX_BUFFER_SIZE 65536

int readn(int fd, uint8_t* buffer, int n)
{
    int nleft = n;
    int nread = 0;

    while(nleft > 0)
    {
        if((nread = read(fd, buffer + nread, nleft)) == -1)
        {
            if(errno == EINTR)
                nread = 0;
            else
                return -1;
        }
        else if(nread == 0)
            break;

        nleft -= nread;
    }

    return n - nleft;
}

int writen(int fd, uint8_t* buffer, int n)
{
    int nleft = n;
    int nwrite = 0;

    while(nleft > 0)
    {
        if((nwrite = write(fd, buffer + nwrite, nleft)) <= 0)
        {
            if(errno == EINTR)
                nwrite = 0;
            else
                return -1;
        }

        nleft -= nwrite;
    }

    return n;
}


void usage(int argc, char** argv)
{
#if 1
    fprintf(stderr, "argc:%d", argc);
#endif

    fprintf(stdout, "\neg \n\t%s --ip [xxx.xxx.xxx.xxx] --port [1~65535]\n\n", argv[0]);
    exit(0);
}


int check_option(char* ip, uint16_t* port, int argc, char** argv)
{
	int opt = 0;
	struct option opts[] = 
	{
		{"ip", 1, NULL, 1},
		{"port", 1, NULL, 2},
		{0, 0, 0, 0}
	};

	while((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
	{
		switch(opt)
		{
			case 1:
				strcpy(ip, optarg);
                fprintf(stdout, "ip:%s\n", optarg);
				break;
			case 2:
                *port = atoi(optarg);
                fprintf(stdout, "port:%s\n", optarg);
				break;
            default:
                
                fprintf(stdout, "get opt fialed!\n");
                return -1;
        }
    }

    return 0;
}

int set_nonblock(int fd)
{
    int block_mode = 0;

    //设置非阻塞模式
    block_mode = fcntl(fd, F_GETFL);
    if(block_mode < 0)
    {
        fprintf(stderr, "get block mode failed!Error:%d ErrMsg:%s\n", errno, strerror(errno));
        return -1;
    }

    block_mode = O_NONBLOCK | block_mode;
    if(fcntl(fd, F_SETFL, block_mode) < 0)
    {
        fprintf(stderr, "set block mode failed!Error:%d ErrMsg:%s\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}


void init_ssl()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}



int main(int argc, char** argv)
{
    int ret = 0;
    int clientfd = 0;
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(struct sockaddr);

    char* buffer = (char*)malloc(MAX_BUFFER_SIZE);
    char ip[32] = {0};
    uint16_t port = 0;

    int sndmem = 1024*1024;
    int rcvmem = 1024*1024;

#ifdef USETLS
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
#endif

    if(argc != 5)
        usage(argc, argv);

#ifdef USETLS

    init_ssl();
#endif

#ifdef USETLS
    ctx = SSL_CTX_new(SSLv23_client_method());
#endif

    if(-1 == check_option((char*)ip, &port, argc, argv))
    {
        fprintf(stderr, "check option failed!\n\n");
        usage(argc, argv);
        exit(-1);
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_in));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);

    clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if(clientfd < 0)
    {
        fprintf(stderr, "client fd create failed!\n");
        return -1;
    }

    if(0 != setsockopt(clientfd, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvmem, sizeof(int)))
    {
        fprintf(stderr, "setsockopt SO_RCVBUF failed. ip: %s port: %d\n", inet_ntoa(*(struct in_addr *)&ip), port);
    }
    
    if(0 != setsockopt(clientfd, SOL_SOCKET, SO_SNDBUF, (const char*)&sndmem, sizeof(int)))
    {
        fprintf(stderr, "setsockopt SO_SNDBUF failed. ip: %s port: %d\n", inet_ntoa(*(struct in_addr *)&ip), port);
    }


    ret = connect(clientfd, (struct sockaddr*)&server_addr, server_len);
    if(ret < 0)
    {
        fprintf(stderr, "connect [%s:%d] failed! clientfd:%d errno:%u errmsg:%s\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), clientfd, errno, strerror(errno));
        return -1;
    }

    /* if(0 != set_nonblock(clientfd)) */
    /* { */
        /* printf("set nonblock failed!\n"); */
        /* return -1; */
    /* } */

#ifdef USETLS

    //不需要验证服务器证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    //需要验证服务器证书
    /* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);

    if((ret = SSL_connect(ssl)) != 1)
    {
        fprintf(stderr, "SSL connect failed! ret %d\n", ret);  
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL connect failed! ret %d errcode:%d\n", ret, SSL_get_error(ssl, ret));  
        return -1;
    }
    else
        fprintf(stdout, "Connect with [%s] encryption\n", SSL_get_cipher(ssl));

#endif

    while(1)
    {
        memset(buffer, 0, MAX_BUFFER_SIZE);
        memset(&server_addr, 0, sizeof(struct sockaddr_in));

        if(!getsockname(clientfd, (struct sockaddr*)&server_addr, &server_len))
        {
            sprintf(buffer, "TLS -> %s, %d Comming!", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
        }

#ifndef USETLS
        if(-1 == writen(clientfd, (uint8_t*)buffer, strlen(buffer)))
            fprintf(stderr, "write [%s] failed!\n", buffer);
        else
            fprintf(stdout, "write [%s] success!\n", buffer);
#else
        ret = SSL_write(ssl, buffer, strlen(buffer));
        if(ret <= 0)
        {
            ret = SSL_get_error(ssl, ret);
            fprintf(stderr, "SSL_read has error! ssl get errcode:%d\n", ret);

            if(ret == SSL_ERROR_WANT_READ)
            {
                fprintf(stderr, "SSL_ERROR_WANT_READ\n");
            }
            else if(ret == SSL_ERROR_WANT_WRITE)
            {
                fprintf(stderr, "SSL_ERROR_WANT_WRITE");
            }

        }
#endif

        memset(buffer, 0, MAX_BUFFER_SIZE);
#ifndef USETLS
        if(-1 == read(clientfd, (uint8_t*)buffer, MAX_BUFFER_SIZE))
            fprintf(stderr, "read failed! errno:%u, errmsg:%s\n", errno, strerror(errno));
        else
            fprintf(stdout, "read [%s] success!\n", (char*)buffer);
#else
        ret = SSL_read(ssl, buffer, MAX_BUFFER_SIZE);
        if(ret <= 0)
        {
            ret = SSL_get_error(ssl, ret);
            fprintf(stderr, "SSL_read has error! ssl get errcode:%d\n", ret);

            if(ret == SSL_ERROR_WANT_READ)
            {
                fprintf(stderr, "SSL_ERROR_WANT_READ\n");
            }
            else if(ret == SSL_ERROR_WANT_WRITE)
            {
                fprintf(stderr, "SSL_ERROR_WANT_WRITE");
            }

        }

        fprintf(stdout, "read [%s] success!\n", (char*)buffer);
#endif

        sleep(1);
    }

    return 0;
}
