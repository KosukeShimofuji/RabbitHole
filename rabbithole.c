#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex.h>
#include <time.h>

#define MAX_BUF 256

void usage(){
    printf("Usage RabbtHole -l list -u https_url -s signature -m [https|socks] [-d]\n");
    printf("-l target list\n");
    printf("-u https url\n");
    printf("-s signature\n");
    printf("-m mode choice [https|socks]\n");
    printf("-d domain resolution on socks proxy(Improvement of anonymity)\n");
    exit(EXIT_SUCCESS);
} 

void chomp(char *str){
    int len;
    len = strlen(str);
    if((len > 0) && (str[len - 1] == '\n')){
        str[len - 1] = '\0';
    }
    return;
}

void socks_scan(char *socks_ipaddr, char *socks_port, char *signature, 
        char *uri_proto, char *uri_hostname, char *uri_ipaddr, char *uri_path,
        int domain_resolution_flag){
    struct sockaddr_in addr;
    int sock;
    struct timeval tv;
    char recv_buf[MAX_BUF];
    char header[MAX_BUF*2];
    int recv_len, err;
    SSL *ssl;
    SSL_CTX *ctx;
    clock_t start_time, end_time;
    char second_request[MAX_BUF];

    start_time = clock();

    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    //tv.tv_sec = 10;
    //tv.tv_usec = 0;
    //setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(socks_port));
    addr.sin_addr.s_addr = inet_addr(socks_ipaddr);

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1){
        perror("connect");
        goto CONNECTION_END;
    };

    char first_request[] = {
        0x05, /* socks version */
        0x01, /* auth list num */
        0x00  /* unencessary authentication */
    };

    send(sock, first_request, sizeof(first_request), 0);
    recv_len = recv(sock, recv_buf, MAX_BUF, 0);

    if( recv_len > 0 ){
        if(recv_buf[0] != 0x05){
            printf("[!] Invalid socks version\n");
            goto CONNECTION_END;
        }
        if(recv_buf[1] != 0x00){
            printf("[!] Invalid authentication method\n");
            goto CONNECTION_END;
        }

        if(domain_resolution_flag){
            second_request[0] = 0x05; /* socks version */
            second_request[1] = 0x01; /* connect method */
            second_request[2] = 0x00; /* reserved */
            second_request[3] = 0x03; /* FQDN */
            addr.sin_port = htons(443);
            int uri_hostname_len = strlen(uri_hostname);
            second_request[4] = uri_hostname_len;
            memcpy(second_request + 5, uri_hostname, uri_hostname_len);
            memcpy(second_request + 5 + uri_hostname_len, &addr.sin_port, 2);
            send(sock, second_request, 5 + uri_hostname_len + 2, 0);
        }else{
            second_request[0] = 0x05; /* socks version */
            second_request[1] = 0x01; /* connect method */
            second_request[2] = 0x00; /* reserved */
            second_request[3] = 0x01; /* IPv4 */
            addr.sin_port = htons(443);
            addr.sin_addr.s_addr = inet_addr(uri_ipaddr);
            memcpy(second_request + 4, &addr.sin_addr.s_addr, 4);
            memcpy(second_request + 8, &addr.sin_port, 2);
            send(sock, second_request, 10, 0);
        }

        memset(recv_buf, '\0', MAX_BUF);
        recv_len = recv(sock, recv_buf, 10, 0);

        if ( recv_len <= 0 ){
            goto CONNECTION_END;
        }

        SSL_load_error_strings();
        SSL_library_init();
        ctx = SSL_CTX_new(SSLv23_client_method());
        ssl = SSL_new(ctx);
        err = SSL_set_fd(ssl, sock);
        SSL_connect(ssl);

        sprintf(header, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", 
                uri_path, uri_hostname);
        SSL_write(ssl, header, strlen(header));

        int buf_size = 256;
        char buf[buf_size];
        int read_size;

        do {
            read_size = SSL_read(ssl, buf, buf_size);
            //write(1, buf, read_size);
        } while(read_size > 0);

        end_time = clock();

        if(strstr(buf, signature) != NULL){
           printf("Success %dms %s:%s\n", 
                   end_time - start_time, socks_ipaddr, socks_port);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_free_strings();
    }

    CONNECTION_END:
    close(sock);
}

void https_scan(char *https_ipaddr, char *https_port, char *signature, 
        char *uri_proto, char *uri_hostname, char *uri_ipaddr, char *uri_path){
    struct sockaddr_in addr;
    int sock;
    struct timeval tv;
    char send_buf[MAX_BUF];
    char recv_buf[MAX_BUF];
    char header[MAX_BUF*2];
    int recv_len, err;
    SSL *ssl;
    SSL_CTX *ctx;
    clock_t start_time, end_time;
    char second_request[MAX_BUF];

    start_time = clock();

    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(https_port));
    addr.sin_addr.s_addr = inet_addr(https_ipaddr);

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1){
        perror("connect");
        goto CONNECTION_END;
    };

    sprintf(send_buf, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: RabbitHole\r\nProxy-Connection: Keep-Alive\r\n\r\n", uri_hostname, 443, uri_hostname, 443);
    send(sock, send_buf, strlen(send_buf), 0);
    recv_len = recv(sock, recv_buf, MAX_BUF, 0);
    if( recv_len > 0 ){
        SSL_load_error_strings();
        SSL_library_init();
        ctx = SSL_CTX_new(SSLv23_client_method());
        ssl = SSL_new(ctx);
        err = SSL_set_fd(ssl, sock);
        SSL_connect(ssl);
        sprintf(header, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", uri_path, uri_hostname);
        SSL_write(ssl, header, strlen(header));

        int buf_size = 256;
        char buf[buf_size];
        int read_size;

        do {
             read_size = SSL_read(ssl, buf, buf_size);
             //write(1, buf, read_size);
        } while(read_size > 0);

        end_time = clock();

        if(strstr(buf, signature) != NULL){
            printf("Success %dms %s:%s\n", 
                   end_time - start_time, https_ipaddr, https_port);
         }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_free_strings();
    }

    CONNECTION_END:
    close(sock);
}


void uriparse(char *uri, char **uri_proto, char **uri_hostname, char **uri_path){
    const char *re = "^([^/]+?)://([^/]+?)/?(.*)$";
    regex_t regbuf;
    regmatch_t regmatch[4];
    regcomp(&regbuf, re, REG_EXTENDED);
    regexec(&regbuf, uri, 4, regmatch, 0);
    
    //get proto
    if (regmatch[1].rm_so >= 0 && regmatch[1].rm_eo >= 0) {
        int start = regmatch[1].rm_so;
        int end =  regmatch[1].rm_eo;
        int size = end - start;
        char buf[size];
        int i=0,j=0;

        for(i=start; i<end; i++,j++){
            buf[j] = uri[i];
        } 
        buf[size] = '\0';

        *uri_proto = (char *)malloc(sizeof(char) * size);
        strcpy(*uri_proto, buf);
    }
    // get host 
    if (regmatch[2].rm_so >= 0 && regmatch[2].rm_eo >= 0) {
        int start = regmatch[2].rm_so;
        int end =  regmatch[2].rm_eo;
        int size = end - start;
        char buf[size];
        int i=0,j=0;

        for(i=start; i<end; i++,j++){
            buf[j] = uri[i];
        } 
        buf[size] = '\0';

        *uri_hostname = (char *)malloc(sizeof(char) * size);
        strcpy(*uri_hostname, buf);
    }
    // get path
    if (regmatch[3].rm_so >= 0 && regmatch[3].rm_eo >= 0) {
        int start = regmatch[3].rm_so;
        int end =  regmatch[3].rm_eo;
        int size = end - start;
        char buf[size];
        int i=0,j=0;

        for(i=start; i<end; i++,j++){
            buf[j] = uri[i];
        } 
        buf[size] = '\0';

        *uri_path = (char *)malloc(sizeof(char) * size);
        strcpy(*uri_path, buf);
    }
}

int main(int argc, char *argv[]){
    int opts;
    int domain_resolution_flag = 0;
    char *target_list = NULL;
    char *uri = NULL;
    char *signature = NULL;
    FILE *fp;
    char line[MAX_BUF];
    char *uri_proto, *uri_hostname, *uri_ipaddr, *uri_path;
    char mode[5];
    struct hostent* uri_hostent;

    while((opts=getopt(argc, argv, "l:u:s:m:d")) != -1){
        switch(opts){
            case 'l':
                target_list = optarg;
                break;
            case 'u':
                uri = optarg;
                break;
            case 's':
                signature = optarg;
                break;
            case 'd':
                domain_resolution_flag = 1;
                break;
            case 'm':
                strcpy(mode, optarg);
                break;
            default:
                printf("error! %c %c\n", opts, optarg);
                exit(EXIT_SUCCESS);
        }
    }

    if(target_list == NULL || uri == NULL || signature == NULL ){
        usage();
    }

    if((strcmp("https", mode) != 0) && (strcmp("socks", mode) != 0)){
        usage();
    }

    uriparse(uri, &uri_proto, &uri_hostname, &uri_path);

    fprintf(stderr, "[+] TARGET_LIST : %s\n", target_list);
    fprintf(stderr, "[+] SIGNATURE : %s\n", signature);
    fprintf(stderr, "[+] URI : %s\n", uri);
    fprintf(stderr, "[+] URI_PROTO : %s\n", uri_proto);
    fprintf(stderr, "[+] URI_HOSTNAME : %s\n", uri_hostname);
    fprintf(stderr, "[+] URI_PATH : %s\n", uri_path);

    if(strcmp(uri_proto, "https") != 0){
        fprintf(stderr, "[+] URI_PATH : %s\n", uri_path);
    }

    if(domain_resolution_flag == 0){
        uri_hostent = gethostbyname(uri_hostname);
        if(uri_hostent == NULL){
            perror("gethostbyname");
            exit(EXIT_FAILURE);
        }

        uri_ipaddr = inet_ntoa(*(struct in_addr*)(uri_hostent->h_addr_list[0])); 
        fprintf(stderr, "[+] URI_IPADDR : %s\n", uri_ipaddr);
    }

    if((fp = fopen(target_list, "r")) == NULL){
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while((fgets(line, MAX_BUF, fp)) != NULL){
        char *target_ipaddr, *target_port;
        chomp(line);
        target_ipaddr = strtok(line, ":");
        target_port = strtok(NULL, ":");
        if(strcmp("socks", mode) == 0){
             socks_scan(target_ipaddr, target_port, signature, uri_proto, 
                        uri_hostname, uri_ipaddr, uri_path, 
                        domain_resolution_flag);
        } 
        if(strcmp("https", mode) == 0){
             https_scan(target_ipaddr, target_port, signature, uri_proto, 
                        uri_hostname, uri_ipaddr, uri_path);
        } 
    } 

    free(uri_proto);
    free(uri_hostname);
    free(uri_path);
    fclose(fp);

    return 0;
}

