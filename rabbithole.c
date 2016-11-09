// gcc -o RabbitHole rabbithole.c -lssl -lcrypto -lpthread -g
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
#include <stdbool.h>
#include <pthread.h>

#define MAX_BUF 256
#define THREAD_NUM 50
pthread_mutex_t mutex;

typedef struct node {
    char *item;
    struct node *next;
} Node;

typedef struct {
    Node *top;
} LinkList;

typedef struct pthread_args{
    char *mode;
    char *signature;
    char *uri_proto;
    char *uri_hostname;
    char *uri_ipaddr;
    char *uri_path;
    int domain_resolution_flag;
    LinkList *list;
} PTHREAD_ARGS;

void usage(){
    printf("Usage RabbtHole -l list -u https_url -s signature -m [https|socks] [-d]\n");
    printf("-l target list\n");
    printf("-u https url\n");
    printf("-s signature\n");
    printf("-m mode choice [https|socks]\n");
    printf("-d domain resolution on socks proxy(Improvement of anonymity)\n");
    exit(EXIT_SUCCESS);
} 

Node *make_node(char *item, Node *node){
    Node *new_node = malloc(sizeof(Node));
    if(new_node != NULL){
        new_node->item = malloc(strlen(item));
        strcpy(new_node->item, item);
        new_node->next = node;
    }
    return new_node;
}

LinkList *make_linklist(void){
    LinkList *list = malloc(sizeof(LinkList));
    if(list != NULL){
       list->top = make_node("", NULL); 
       if(list->top == NULL){
         free(list);
         return NULL;
       }
    }
    return list;
}

void free_node(Node *node){
    while(node != NULL){
        Node *tmp = node->next;
        free(node->item);
        free(node);
        node = tmp;
    }
}

void free_linklist(LinkList *list){
    free_node(list->top);
    free(list);
}

Node *get_node(Node *node, int n){
    int i;
    for(i = -1; node != NULL; i++, node = node->next){
        if(i == n) break;
    }
    return node;
}

char *get_item(LinkList *list, int n, bool *err){
    Node *node = get_node(list->top, n);
    if(node == NULL){
        *err = 0;
        return "";
    } 
    *err = 1;
    return node->item;
} 

bool insert_node(LinkList *list, int n, char *item){
    Node *node = get_node(list->top, n - 1);
    if(node == NULL) return false;
    node->next = make_node(item, node->next);
    return true;
}

bool delete_node(LinkList *list, int n){
    Node *node = get_node(list->top, n - 1);
    if(node == NULL || node->next == NULL) return false;
    Node *tmp = node->next;
    node->next = node->next->next;
    free(tmp);
    return true;
}

bool push_node(LinkList *list, char *item){
    return insert_node(list, 0, item);
}

char *pop_node(LinkList *list, bool *err){
    char *item = get_item(list, 0, err);
    if(*err) delete_node(list, 0);
    return item;
}

void chomp(char *str){
    int len;
    len = strlen(str);
    if((len > 0) && (str[len - 1] == '\n')){
        str[len - 1] = '\0';
    }
    return;
}

bool empty_linklist(LinkList *list){
    return list->top->next == NULL;
}

void print_linklist(LinkList *list){
    printf("(\n");
    Node *node;
    for(node = list->top->next; node != NULL; node = node->next)
        printf("\t%s\n", node->item);
    printf(")\n");
}

void socks_scan(char *socks_ipaddr, char *socks_port, char *signature, 
        char *uri_proto, char *uri_hostname, char *uri_ipaddr, char *uri_path,
        int domain_resolution_flag){
    struct sockaddr_in addr;
    int sock;
    struct timeval tv;
    char recv_buf[MAX_BUF];
    char send_buf[MAX_BUF];
    int recv_len, send_len, err;
    SSL *ssl;
    SSL_CTX *ctx;
    clock_t start_time, end_time;

    fprintf(stderr, "[+][tid=%08x]SOCKS v5 PROXY TARGET %s:%s\n", 
            pthread_self(), socks_ipaddr, socks_port);

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

    send_buf[0] = 0x05; /* socks version */
    send_buf[1] = 0x01; /* auth list num */
    send_buf[2] = 0x00; /* unnecessary authentication */

    send(sock, send_buf, 3, 0);
    recv_len = recv(sock, recv_buf, MAX_BUF, 0);

    if( recv_len <= 0 ){
        goto CONNECTION_END;
    }

    if(recv_buf[0] != 0x05){
        printf("[!] Invalid socks version\n");
        goto CONNECTION_END;
    }
    if(recv_buf[1] != 0x00){
        printf("[!] Invalid authentication method\n");
        goto CONNECTION_END;
    }

    memset(send_buf, 0x00, sizeof(send_buf));

    if(domain_resolution_flag){
        send_buf[0] = 0x05; /* socks version */
        send_buf[1] = 0x01; /* connect method */
        send_buf[2] = 0x00; /* reserved */
        send_buf[3] = 0x03; /* FQDN */
        addr.sin_port = htons(443);
        int uri_hostname_len = strlen(uri_hostname);
        send_buf[4] = uri_hostname_len;
        memcpy(send_buf + 5, uri_hostname, uri_hostname_len);
        memcpy(send_buf + 5 + uri_hostname_len, &addr.sin_port, 2);
        send(sock, send_buf, 5 + uri_hostname_len + 2, 0);
    }else{
        send_buf[0] = 0x05; /* socks version */
        send_buf[1] = 0x01; /* connect method */
        send_buf[2] = 0x00; /* reserved */
        send_buf[3] = 0x01; /* IPv4 */
        addr.sin_port = htons(443);
        addr.sin_addr.s_addr = inet_addr(uri_ipaddr);
        memcpy(send_buf + 4, &addr.sin_addr.s_addr, 4);
        memcpy(send_buf + 8, &addr.sin_port, 2);
        send(sock, send_buf, 10, 0);
    }

    memset(recv_buf, 0x00, sizeof(recv_buf));
    recv_len = recv(sock, recv_buf, MAX_BUF, 0);

    if ( recv_len <= 0 ){
        goto CONNECTION_END;
    }

    SSL_load_error_strings();
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());
    ssl = SSL_new(ctx);
    err = SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    memset(send_buf, 0x00, sizeof(send_buf));
    sprintf(send_buf, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", 
            uri_path, uri_hostname);
    SSL_write(ssl, send_buf, strlen(send_buf));

    memset(recv_buf, 0x00, sizeof(recv_buf));
    recv_len = 0;

    do {
        recv_len = SSL_read(ssl, recv_buf, MAX_BUF);
        //write(1, recv_buf, recv_len);
    } while(recv_len > 0);

    end_time = clock();

    if(strstr(recv_buf, signature) != NULL){
        printf("[*][FOUND SOCKS PROXY] %dms %s:%s\n", 
                end_time - start_time, socks_ipaddr, socks_port);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();

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
    int send_len, recv_len, err;
    SSL *ssl;
    SSL_CTX *ctx;
    clock_t start_time, end_time;

    fprintf(stderr, "[+][tid=%08x] HTTPS PROXY SCAN TARGET %s:%s\n", 
            pthread_self(), https_ipaddr, https_port);

    start_time = clock();

    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    //tv.tv_sec = 10;
    //tv.tv_usec = 0;
    //setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(https_port));
    addr.sin_addr.s_addr = inet_addr(https_ipaddr);

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1){
        perror("connect");
        goto CONNECTION_END;
    };

    sprintf(send_buf, 
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: Mozilla/5.0 (Android; Linux armv7l; rv:9.0)\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n", 
            uri_hostname, 443, uri_hostname, 443);
    send(sock, send_buf, strlen(send_buf), 0);
    recv_len = recv(sock, recv_buf, MAX_BUF, 0);

    if( recv_len <= 0 ){
        goto CONNECTION_END;
    }

    memset(send_buf, 0x00, sizeof(send_buf));

    SSL_load_error_strings();
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());
    ssl = SSL_new(ctx);
    err = SSL_set_fd(ssl, sock);
    SSL_connect(ssl);
    sprintf(send_buf, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", uri_path, uri_hostname);
    SSL_write(ssl, send_buf, strlen(send_buf));

    memset(recv_buf, 0x00, sizeof(recv_buf));
    recv_len = 0;

    do {
        recv_len = SSL_read(ssl, recv_buf, MAX_BUF);
        //write(1, buf, read_size);
    } while(recv_len > 0);

    end_time = clock();

    if(strstr(recv_buf, signature) != NULL){
        printf("[*][FOUND HTTPS PROXY] %dms %s:%s\n", 
                end_time - start_time, https_ipaddr, https_port);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();

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

void *pthread_wrapper(void *p){
    PTHREAD_ARGS *args = (PTHREAD_ARGS *)p;
    char *target_ipaddr, *target_port;
    char *item;
    bool err;

    while(!empty_linklist(args->list)){
        pthread_mutex_lock(&mutex);
        item = pop_node(args->list, &err);
        pthread_mutex_unlock(&mutex);

        target_ipaddr = strtok(item, ":");
        target_port = strtok(NULL, ":");

        if(strcmp("socks", args->mode) == 0){
            socks_scan(
                    target_ipaddr, 
                    target_port, 
                    args->signature, 
                    args->uri_proto, 
                    args->uri_hostname, 
                    args->uri_ipaddr, 
                    args->uri_path, 
                    args->domain_resolution_flag
                    );
        } 
        if(strcmp("https", args->mode) == 0){
            https_scan(
                    target_ipaddr, 
                    target_port, 
                    args->signature, 
                    args->uri_proto, 
                    args->uri_hostname, 
                    args->uri_ipaddr, 
                    args->uri_path
                    );
        } 
    }

    return;
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
    pthread_t pthread[THREAD_NUM];
    PTHREAD_ARGS pargs;
    int i = 0;

    setbuf(stdout, NULL);

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

    fprintf(stderr, "[+] SCAN MODE : %s\n", mode);
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

    // generate LinkList
    LinkList *list = make_linklist();
    bool err;

    while((fgets(line, MAX_BUF, fp)) != NULL){
        chomp(line);
        push_node(list, line);

    } 
    fclose(fp);

    pargs.mode = mode;
    pargs.signature = signature;
    pargs.uri_proto = uri_proto;
    pargs.uri_hostname = uri_hostname;
    pargs.uri_ipaddr = uri_ipaddr;
    pargs.uri_path = uri_path;
    pargs.domain_resolution_flag = domain_resolution_flag;
    pargs.list = list;

    // generate thread
    for(i=0; i<THREAD_NUM; i++){
          pthread_create( &pthread[i], NULL, &pthread_wrapper, &pargs);
    }
    for(i=0; i<THREAD_NUM; i++){
          pthread_join(pthread[i], NULL);
    }

    // print_linklist(list);
    free_linklist(list);
    free(uri_proto);
    free(uri_hostname);
    free(uri_path);

    return 0;
}

