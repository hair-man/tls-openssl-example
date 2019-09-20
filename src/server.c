/**
 *  Filename: server.c
 *   Created: 2019-09-19 11:15:30
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


#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/epoll.h>
#include <getopt.h>

#define MAX_EPOLL_EVENTS 1000000
#define MAX_BUFFER_SIZE  65536 


static __attribute__((unused))char* version = "VERSION"VERSION;


typedef struct _ssl_ctx_context
{
    int fd;
    SSL* ssl;
}scontext_t;


SSL_CTX* init_ssl_ctx(char* ca_file, char* pri_file, char* cer_file)
{
    SSL_CTX *ctx = NULL;
    int ret_err = 0;

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_CTX_new failed!\n");
        return NULL;
    }

    ret_err = SSL_CTX_load_verify_locations(ctx, ca_file, NULL);
    if (ret_err <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_CTX_load_verify_locations [%s] failed!\n", ca_file);
        return NULL;
    }

    ret_err = SSL_CTX_use_certificate_file(ctx, cer_file, SSL_FILETYPE_PEM);
    if (ret_err <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_CTX_use_certificate_file failed!\n");
        return NULL;
    }

    ret_err = SSL_CTX_use_PrivateKey_file(ctx, pri_file, SSL_FILETYPE_PEM);
    if (ret_err <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file failed!\n");
        return NULL;
    }

    //设置单双向认证
    //SSL_VERIFY_NONE
    //作为服务器：服务器不会向客户端询问客户端证书
    //作为客户端：服务器会向客户端发送一个证书，不关心校验结果
    //SSL_VERIFY_PEER
    //作为服务器：服务器向客户端询问客户端证书，并检查，验证失败则终止
    //作为客户端：检查服务求发来的证书，验证失败则终止
    //
    //
    //
    //下面两个标志必须与SSL_VERIFY_PEER联合使用
    //SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    //作为服务器有效：客户端如果不发送证书则表示验证失败，终止
    //SSL_VERIFY_CLIENT_ONCE
    //作为服务器有效：尽在初始TLS握手时请求客户端证书，重新协商不需要客户端证书
    
    //双向 - 让客户端发送客户端证书并进行验证
    /* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); */

    //单向 - 不需要客户端发送证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_CTX_check_private_key failed!\n");
        return NULL;
    }

    return ctx;
}

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


//ip - 网络序
//port - 主机序
int init_socket(int *sockfd, uint32_t ip, uint16_t port)
{
    int val = 1;
    int ret_err = 0;
    int sndmem = 1024*1024;
    int rcvmem = 1024*1024;

    struct sockaddr_in my_addr;

    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(*sockfd < 0)
    {
        fprintf(stderr, "socket failed.\n");
        return -1;
    }
    //设置端口复用
    ret_err = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    if (ret_err)
    {
        fprintf(stderr, "set reuse addr failed.\n");
        close(*sockfd);
        *sockfd = -1;
        return -1;
    }

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = ip;
    ret_err = bind(*sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    if(ret_err)
    {
        fprintf(stderr, "bind failed. ip: %s port: %d\n", inet_ntoa(*(struct in_addr *)&ip), port);
        close(*sockfd);
		*sockfd = -1;
        return -1;
    }
	else
        fprintf(stderr, "bind success. ip: %s port: %d\n", inet_ntoa(*(struct in_addr *)&ip), port);


    if(0 != setsockopt(*sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvmem, sizeof(int)))
    {
        fprintf(stderr, "setsockopt SO_RCVBUF failed. ip: %s port: %d\n", inet_ntoa(*(struct in_addr *)&ip), port);
    }
    
    if(0 != setsockopt(*sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&sndmem, sizeof(int)))
    {
        fprintf(stderr, "setsockopt SO_SNDBUF failed. ip: %s port: %d\n", inet_ntoa(*(struct in_addr *)&ip), port);
    }

    if(listen(*sockfd, 32) != 0)
    {
        fprintf(stderr, "listen socket tcp fd failed! Error:%d ErrMsg:%s\n", errno, strerror(errno));
        return -1;
    }


    if(0 != set_nonblock(*sockfd))
    {
        printf("set nonblock failed!\n");
        return -1;
    }



    return 0;
}

int add_epoll_fd(int efd, int fd, uint32_t events, void* user_data)
{
    struct epoll_event ev;

    ev.events = events;
    ev.data.ptr = (void *)user_data;
    if(epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) 
    {   
        fprintf(stderr, "epoll_ctl ADD failed! efd:%u, connfd:%u Error:%d ErrMsg:%s\n", efd, fd, errno, strerror(errno));
        return -1; 
    }   

    return 0;
}

int del_epoll_fd(int efd, int fd)
{
    struct epoll_event ev;

    if(epoll_ctl(efd, EPOLL_CTL_DEL, fd, &ev) == -1) 
    {   
        fprintf(stderr, "epoll_ctl DEL failed! efd:%u, connfd:%u Error:%d ErrMsg:%s\n", efd, fd, errno, strerror(errno));
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

void usage(int argc, char** argv)
{
#if 1
    fprintf(stderr, "argc:%d", argc);
#endif

    fprintf(stdout, "\neg \n\t%s --ca [ca filepath] --pri [pri filepath] --cer [cert filepath] --ip [x.x.x.x] --port [0~65535]\n\n", argv[0]);
    exit(0);
}



int check_option(char* ca, char* pri, char* cer, char*ip, uint16_t* port, int argc, char** argv)
{
	int opt = 0;
	struct option opts[] = 
	{
		{"ca", 1, NULL, 1},
		{"pri", 1, NULL, 2},
		{"cer", 1, NULL, 3},
		{"ip", 1, NULL, 4},
		{"port", 1, NULL, 5},
		{0, 0, 0, 0}
	};

	while((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
	{
		switch(opt)
		{
			case 1:
				strcpy(ca, optarg);
                fprintf(stdout, "ca filepath:%s\n", optarg);
				break;
			case 2:
				strcpy(pri, optarg);
                fprintf(stdout, "pri filepath:%s\n", optarg);
				break;
			case 3:
				strcpy(cer, optarg);
                fprintf(stdout, "cer filepath:%s\n", optarg);
				break;
			case 4:
				strcpy(ip, optarg);
                fprintf(stdout, "ip:%s\n", optarg);
				break;
			case 5:
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


int main(int argc, char** argv)
{
    int ret = 0;
    int serverfd = 0;

    int clientfd = 0;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(struct sockaddr);

    int efd = 0;
    int num = 0;
    int fd_counts = 0;

#ifdef USETLS
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
#endif

    uint8_t* buffer = (uint8_t*)malloc(MAX_BUFFER_SIZE);

    char ip[32] = {0};
    uint16_t port = 0;
    uint8_t* ca = (uint8_t*)malloc(MAX_BUFFER_SIZE);
    uint8_t* pri = (uint8_t*)malloc(MAX_BUFFER_SIZE);
    uint8_t* cer = (uint8_t*)malloc(MAX_BUFFER_SIZE);

    struct epoll_event* events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * MAX_EPOLL_EVENTS);
    memset(events, 0, sizeof(struct epoll_event) * MAX_EPOLL_EVENTS);

    if(argc != 11)
        usage(argc, argv);

    if(-1==  check_option((char*) ca, (char* )pri, (char* )cer, ip, &port, argc, argv))
    {
        fprintf(stderr, "check option failed!\n");
        exit(0);
    }

#ifdef USETLS
    init_ssl();
#endif

    ret = init_socket(&serverfd, inet_addr(ip), port);
    if(ret != 0)
        exit(0);

    efd = epoll_create(MAX_EPOLL_EVENTS);

    if(efd <= 0)
    {
        fprintf(stderr, "epoll_create failed! Error:%d ErrMsg:%s\n", errno, strerror(errno));
        return -1;
    }

    scontext_t* scontext = (scontext_t*)malloc(sizeof(scontext_t));
    if(scontext)
        memset(scontext, 0, sizeof(scontext_t));
    else
    {
        fprintf(stderr, "ssl ctx context create failed!\n");
        exit(0);
    }

    scontext->fd = serverfd;

#ifdef USETLS
    ctx = init_ssl_ctx((char*)ca, (char*)pri, (char*)cer);
#endif

    if(0 != add_epoll_fd(efd, serverfd, EPOLLIN, scontext))
    {
        printf("add listen socket tcp fd to epoll handle failed!");
        return -1;
    }

    fd_counts ++;


    do
    {
        num = epoll_wait(efd, events, fd_counts, -1);

        while(num--)
        {
            scontext = (scontext_t*)events[num].data.ptr;
            
            if(events[num].events & EPOLLERR || events[num].events & EPOLLHUP)
            {
                fprintf(stderr, "events ERR or HUP!\n");
                close(scontext->fd);
            }
            else if(scontext->fd == serverfd)
            {
                fprintf(stdout, "new connect is comming\n");

                memset(&client_addr, 0, sizeof(struct sockaddr));
                clientfd = accept(scontext->fd, (struct sockaddr*)&client_addr, &client_len);
                if(clientfd < 0)
                {
                    fprintf(stderr, "new client accept failed!\n");
                    continue;
                }

                fprintf(stdout, "new client [%s:%d] is accepted!\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

                scontext = (scontext_t*)malloc(sizeof(scontext_t));
                scontext->ssl = NULL;
#ifdef USETLS
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, clientfd);
                if ((ret = SSL_accept(ssl)) != 1)
                {
                    ERR_print_errors_fp(stderr);
                    ERR_print_errors_fp(stdout);
                    fprintf(stderr, "ssl accept failed! ret %d errcode:%d\n", ret, SSL_get_error(ssl, ret));
                    close(clientfd);
                    continue;
                }

                scontext->ssl = ssl;
#endif

                scontext->fd = clientfd;

                if(0 != set_nonblock(clientfd))
                {
                    printf("client fd set nonblock failed!\n");
                    continue;
                }

                if(0 != add_epoll_fd(efd, clientfd, EPOLLIN | EPOLLOUT, scontext))
                {
                    fprintf(stderr, "add epoll fd failed!\n");
                    continue;
                }

                continue;
            }


            if(events[num].events & EPOLLIN)
            {
                clientfd = scontext->fd;
                if(clientfd < 0)
                {
                    fprintf(stderr, "read fd < 0\n");
                    continue;
                }

                printf("epollin socket [%d]\n", clientfd);

                memset(buffer, 0, MAX_BUFFER_SIZE);
#ifndef USETLS
                ret = recv(clientfd, buffer, MAX_BUFFER_SIZE - 1, 0);
                if(ret <= 0)
                {
                    printf("cliet close!\n");
                    if(errno == ECONNRESET || ret == 0)    
                    {

                        if(0 != del_epoll_fd(efd, clientfd))
                        {
                            printf("del epoll fd failed!\n");
                        }

                        close(clientfd);
                    }

                    continue;
                }
#else
                ssl = scontext->ssl;
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
#endif

                fprintf(stdout, "recv buffer: %s\n", buffer);

                memset(buffer, 0, MAX_BUFFER_SIZE);

                if(!getpeername(clientfd, (struct sockaddr*)&client_addr, &client_len))
                {
                    sprintf((char*)buffer, "HTTP/1.1 200 OK >>>> ------------- %s:%u", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                }

#ifndef USETLS
                if(-1 == writen(clientfd, (uint8_t*)buffer, (int)strlen((char*)buffer)))
                {
                    fprintf(stderr, "write failde!\n");
                }
#else
                ret = SSL_write(ssl, buffer, (int)strlen((char*)buffer));
                if(ret <= 0)
                {
                    ret = SSL_get_error(ssl, ret);
                    fprintf(stderr, "SSL_write has error! ssl get errcode:%d\n", ret);

                    if(ret == SSL_ERROR_WANT_READ)
                    {
                        fprintf(stderr, "-> SSL_ERROR_WANT_READ\n");
                    }
                    else if(ret == SSL_ERROR_WANT_WRITE)
                    {
                        fprintf(stderr, "-> SSL_ERROR_WANT_WRITE");
                    }
                    
                }
#endif

            }

#if 0
            if(events[num].events & EPOLLOUT)
            {
                clientfd = scontext->fd;
                if(clientfd < 0)
                {
                    fprintf(stderr, "read fd < 0\n");
                    continue;
                }

                printf("epollout socket [%d]\n", clientfd);

                memset(buffer, 0, MAX_BUFFER_SIZE);
                sprintf((char*)buffer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", (int)strlen("hello tls world"), "hello tls world");

                if(-1 == writen(clientfd, (uint8_t*)buffer, (int)strlen((char*)buffer)))
                {
                    fprintf(stderr, "write failde!\n");
                }
            }
#endif

        }
    }while(1);
        
    return 0;
}
