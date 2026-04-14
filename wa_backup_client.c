/*
 * wa_backup_client.c
 * WhatsApp Backup Client — auto-watches folders and uploads new media
 *
 * Compile (Linux):
 *   gcc -o wa_backup_client wa_backup_client.c -lpthread
 *
 * Run:
 *   ./wa_backup_client                  # watch mode (default)
 *   ./wa_backup_client --full-scan      # upload all existing files, then watch
 *   ./wa_backup_client --status         # print server summary and exit
 *
 * Edit the CONFIG section below before compiling.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dirent.h>
#include <pthread.h>

/* ── CONFIG — edit these before compiling ─────────────────────────────── */
#define SERVER_HOST   "192.168.100.2"  /* Server IP */
#define SERVER_PORT   5050
#define API_KEY       "changeme123"    /* Must match key passed to server */
#define DEVICE_ID     "client_192.168.100.5"  /* Label for this machine (client IP) */

/* Folders to watch — add/remove as needed */
static const char *WATCH_PATHS[] = {
    "/home/lohithkalyan/Downloads",
    NULL   /* sentinel — keep last */
};

/* Local file that caches already-uploaded SHA-256 hashes */
#define HASH_CACHE_FILE  "/tmp/.wa_backup_hashes"
/* Seconds to wait after a new file appears (lets download finish) */
#define SETTLE_SECS      3
/* Max upload size (bytes) */
#define MAX_UPLOAD_SIZE  (200 * 1024 * 1024)
/* ─────────────────────────────────────────────────────────────────────── */

#define MAX_PATH   512
#define MAX_HASHES 50000

/* ── SHA-256 (embedded, no OpenSSL needed) ──────────────────────────── */
typedef struct { uint32_t s[8]; uint64_t c; uint8_t b[64]; } S256;
static const uint32_t KK[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define R32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void s256t(S256*c,const uint8_t*d){
    uint32_t a,b,e,f,g,h,t1,t2,w[64];int i;
    for(i=0;i<16;i++)w[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for(;i<64;i++)w[i]=(R32(w[i-2],17)^R32(w[i-2],19)^(w[i-2]>>10))+w[i-7]+(R32(w[i-15],7)^R32(w[i-15],18)^(w[i-15]>>3))+w[i-16];
    a=c->s[0];b=c->s[1];uint32_t cc=c->s[2];uint32_t dd=c->s[3];
    e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for(i=0;i<64;i++){
        t1=h+(R32(e,6)^R32(e,11)^R32(e,25))+((e&f)^(~e&g))+KK[i]+w[i];
        t2=(R32(a,2)^R32(a,13)^R32(a,22))+((a&b)^(a&cc)^(b&cc));
        h=g;g=f;f=e;e=dd+t1;dd=cc;cc=b;b=a;a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=dd;
    c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void s256i(S256*c){c->c=0;c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;}
static void s256u(S256*c,const uint8_t*d,size_t l){
    size_t used=c->c&63;c->c+=l;
    if(used){size_t fr=64-used;if(l<fr){memcpy(c->b+used,d,l);return;}memcpy(c->b+used,d,fr);s256t(c,c->b);d+=fr;l-=fr;}
    for(size_t i=0;i+64<=l;i+=64)s256t(c,d+i);
    if(l%(64))memcpy(c->b,d+(l/64)*64,l%64);
}
static void s256f(S256*c,uint8_t*dg){
    uint8_t p[64]={0};size_t u=c->c&63;p[0]=0x80;
    if(u<56)s256u(c,p,56-u);else s256u(c,p,64-u+56);
    uint64_t bits=c->c*8;uint8_t lb[8];
    for(int i=7;i>=0;i--){lb[i]=(uint8_t)(bits&0xff);bits>>=8;}
    s256u(c,lb,8);
    for(int i=0;i<8;i++){dg[i*4]=(c->s[i]>>24)&0xff;dg[i*4+1]=(c->s[i]>>16)&0xff;dg[i*4+2]=(c->s[i]>>8)&0xff;dg[i*4+3]=c->s[i]&0xff;}
}
static void sha256_file_hex(const char *path, char *out){
    FILE*fp=fopen(path,"rb");out[0]='\0';if(!fp)return;
    S256 ctx;s256i(&ctx);
    uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),fp))>0) s256u(&ctx,buf,n);
    fclose(fp);
    uint8_t dg[32];s256f(&ctx,dg);
    for(int i=0;i<32;i++) sprintf(out+i*2,"%02x",dg[i]);
    out[64]='\0';
}

/* ── Hash cache (flat file of hex strings) ───────────────────────────── */
static char  g_hashes[MAX_HASHES][65];
static int   g_hash_count = 0;
static pthread_mutex_t g_hlock = PTHREAD_MUTEX_INITIALIZER;

static void cache_load(void){
    FILE*fp=fopen(HASH_CACHE_FILE,"r");if(!fp)return;
    char line[70];
    while(fgets(line,sizeof(line),fp)&&g_hash_count<MAX_HASHES){
        line[strcspn(line,"\r\n")]='\0';
        if(strlen(line)==64) memcpy(g_hashes[g_hash_count++],line,65);
    }
    fclose(fp);
    printf("[cache] Loaded %d hashes\n",g_hash_count);
}

static int cache_has(const char *h){
    for(int i=0;i<g_hash_count;i++) if(!strcmp(g_hashes[i],h)) return 1;
    return 0;
}

static void cache_add(const char *h){
    if(g_hash_count>=MAX_HASHES) return;
    memcpy(g_hashes[g_hash_count++],h,65);
    FILE*fp=fopen(HASH_CACHE_FILE,"a");if(!fp)return;
    fprintf(fp,"%s\n",h);fclose(fp);
}

/* ── HTTP multipart upload ───────────────────────────────────────────── */
static int tcp_connect(void){
    struct addrinfo hints={0},*res;
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    char port_s[16]; snprintf(port_s,sizeof(port_s),"%d",SERVER_PORT);
    if(getaddrinfo(SERVER_HOST,port_s,&hints,&res)!=0) return -1;
    int fd=socket(res->ai_family,res->ai_socktype,0);
    if(fd<0){freeaddrinfo(res);return -1;}
    struct timeval tv={30,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    if(connect(fd,res->ai_addr,res->ai_addrlen)<0){close(fd);freeaddrinfo(res);return -1;}
    freeaddrinfo(res);
    return fd;
}

static int send_all(int fd,const void*buf,size_t len){
    size_t sent=0;
    while(sent<len){
        ssize_t n=write(fd,(const char*)buf+sent,len-sent);
        if(n<=0) return -1;
        sent+=n;
    }
    return 0;
}

/* Returns HTTP status code, or -1 on network error */
static int http_upload(const char *filepath, const char *filename){
    /* Read file */
    FILE*fp=fopen(filepath,"rb");
    if(!fp){fprintf(stderr,"[!] Cannot open %s\n",filepath);return -1;}
    fseek(fp,0,SEEK_END);long fsz=ftell(fp);rewind(fp);
    if(fsz<=0||fsz>MAX_UPLOAD_SIZE){fclose(fp);return -1;}
    char*fbuf=malloc(fsz);if(!fbuf){fclose(fp);return -1;}
    if(fread(fbuf,1,fsz,fp)!=(size_t)fsz){fclose(fp);free(fbuf);return -1;}
    fclose(fp);

    const char *boundary = "----WA_BACKUP_BOUNDARY_7f3a9b";

    /* Build multipart body */
    char part1[1024];
    int p1len = snprintf(part1,sizeof(part1),
        "--%s\r\nContent-Disposition: form-data; name=\"device_id\"\r\n\r\n%s\r\n"
        "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        boundary, DEVICE_ID, boundary, filename);

    char part2[128];
    int p2len = snprintf(part2,sizeof(part2),"\r\n--%s--\r\n",boundary);

    long body_len = p1len + fsz + p2len;

    /* Build HTTP header */
    char hdr[1024];
    int hlen = snprintf(hdr,sizeof(hdr),
        "POST /upload HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "X-API-Key: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %ld\r\n\r\n",
        SERVER_HOST, SERVER_PORT, API_KEY, boundary, body_len);

    int fd = tcp_connect();
    if(fd<0){free(fbuf);fprintf(stderr,"[!] Cannot connect to server\n");return -1;}

    send_all(fd,hdr,hlen);
    send_all(fd,part1,p1len);
    send_all(fd,fbuf,fsz);
    send_all(fd,part2,p2len);
    free(fbuf);

    /* Read response status line */
    char resp[4096]={0};size_t rlen=0;
    while(rlen<sizeof(resp)-1){
        ssize_t n=read(fd,resp+rlen,1);if(n<=0)break;rlen++;
        if(rlen>=4&&!memcmp(resp+rlen-4,"\r\n\r\n",4))break;
    }
    /* Keep reading body */
    char body[512]={0};size_t blen=0;
    while(blen<sizeof(body)-1){
        ssize_t n=read(fd,body+blen,1);if(n<=0)break;blen++;
    }
    close(fd);

    int code=0; sscanf(resp,"HTTP/%*s %d",&code);
    return code;
}

/* ── Extension allow-list ────────────────────────────────────────────── */
static int allowed_ext(const char *name){
    const char *dot=strrchr(name,'.');if(!dot)return 0;const char*e=dot+1;
    return !strcasecmp(e,"jpg")||!strcasecmp(e,"jpeg")||!strcasecmp(e,"png")||
           !strcasecmp(e,"webp")||!strcasecmp(e,"gif")||!strcasecmp(e,"heic")||
           !strcasecmp(e,"heif")||!strcasecmp(e,"mp4")||!strcasecmp(e,"mov")||
           !strcasecmp(e,"avi")||!strcasecmp(e,"mkv")||!strcasecmp(e,"3gp")||
           !strcasecmp(e,"mp3")||!strcasecmp(e,"ogg")||!strcasecmp(e,"m4a")||
           !strcasecmp(e,"aac")||!strcasecmp(e,"opus")||!strcasecmp(e,"pdf")||
           !strcasecmp(e,"docx")||!strcasecmp(e,"txt")||!strcasecmp(e,"zip");
}

/* ── Upload one file (dedup + upload) ────────────────────────────────── */
static void upload_file(const char *path){
    const char *name = strrchr(path,'/');
    name = name ? name+1 : path;

    if(!allowed_ext(name)) return;

    /* Wait for file to be fully written */
    sleep(SETTLE_SECS);

    struct stat st;
    if(stat(path,&st)<0||!S_ISREG(st.st_mode)) return;
    if(st.st_size==0) return;

    char digest[65];
    sha256_file_hex(path,digest);
    if(!digest[0]) return;

    pthread_mutex_lock(&g_hlock);
    if(cache_has(digest)){
        pthread_mutex_unlock(&g_hlock);
        printf("[=] Already uploaded: %s\n",name);
        return;
    }
    pthread_mutex_unlock(&g_hlock);

    printf("[↑] Uploading %s (%lld KB)...\n",name,(long long)st.st_size/1024);
    int code = http_upload(path,name);

    if(code==200||code==201){
        printf("[✓] Done: %s (HTTP %d)\n",name,code);
        pthread_mutex_lock(&g_hlock);
        cache_add(digest);
        pthread_mutex_unlock(&g_hlock);
    } else {
        printf("[!] Failed: %s (HTTP %d)\n",name,code);
    }
}

/* ── Full scan ───────────────────────────────────────────────────────── */
static void full_scan(void){
    printf("\n[→] Full scan starting...\n");
    for(int i=0;WATCH_PATHS[i];i++){
        DIR*d=opendir(WATCH_PATHS[i]);if(!d){printf("[~] Not found: %s\n",WATCH_PATHS[i]);continue;}
        struct dirent*ent;
        while((ent=readdir(d))){
            if(ent->d_name[0]=='.') continue;
            char full[MAX_PATH];
            snprintf(full,sizeof(full),"%s/%s",WATCH_PATHS[i],ent->d_name);
            upload_file(full);
        }
        closedir(d);
    }
    printf("[✓] Full scan complete.\n\n");
}

/* ── inotify watcher ─────────────────────────────────────────────────── */
#define MAX_WATCHES 64
static int  g_wd_to_idx[MAX_WATCHES];
static char g_wd_path[MAX_WATCHES][MAX_PATH];

static volatile int g_running = 1;
static void on_sig(int s){ (void)s; g_running=0; }

static void watch_loop(void){
    int ifd = inotify_init();
    if(ifd<0){perror("inotify_init");return;}

    int active=0;
    for(int i=0;WATCH_PATHS[i]&&active<MAX_WATCHES;i++){
        int wd=inotify_add_watch(ifd,WATCH_PATHS[i],IN_CLOSE_WRITE|IN_MOVED_TO);
        if(wd<0){printf("[~] Cannot watch (skipping): %s\n",WATCH_PATHS[i]);continue;}
        /* store mapping wd -> path */
        for(int j=0;j<MAX_WATCHES;j++){
            if(g_wd_to_idx[j]==0){
                g_wd_to_idx[j]=wd;
                strncpy(g_wd_path[j],WATCH_PATHS[i],MAX_PATH-1);
                break;
            }
        }
        printf("[👁] Watching: %s\n",WATCH_PATHS[i]);
        active++;
    }
    if(active==0){printf("[!] No valid watch paths. Edit WATCH_PATHS in the source.\n");close(ifd);return;}

    printf("\nWatcher active. Press Ctrl+C to stop.\n\n");
    signal(SIGINT,on_sig);

    char evbuf[4096];
    while(g_running){
        ssize_t n=read(ifd,evbuf,sizeof(evbuf));
        if(n<=0){if(errno==EINTR)break;continue;}
        char *p=evbuf;
        while(p<evbuf+n){
            struct inotify_event *ev=(struct inotify_event*)p;
            if(ev->len>0&&!(ev->mask&IN_ISDIR)){
                /* Find the base path for this wd */
                char base[MAX_PATH]={0};
                for(int j=0;j<MAX_WATCHES;j++){
                    if(g_wd_to_idx[j]==ev->wd){
                        strncpy(base,g_wd_path[j],MAX_PATH-1);break;
                    }
                }
                if(base[0]){
                    char full[MAX_PATH];
                    snprintf(full,sizeof(full),"%s/%s",base,ev->name);
                    upload_file(full);
                }
            }
            p+=sizeof(struct inotify_event)+ev->len;
        }
    }
    close(ifd);
    printf("\nWatcher stopped.\n");
}

/* ── Status check ────────────────────────────────────────────────────── */
static void check_status(void){
    int fd=tcp_connect();
    if(fd<0){printf("[!] Cannot connect to %s:%d\n",SERVER_HOST,SERVER_PORT);return;}
    char req[512];
    int n=snprintf(req,sizeof(req),
        "GET /status HTTP/1.0\r\nHost: %s:%d\r\nX-API-Key: %s\r\n\r\n",
        SERVER_HOST,SERVER_PORT,API_KEY);
    send_all(fd,req,n);
    char resp[2048]={0};size_t rlen=0;
    while(rlen<sizeof(resp)-1){ssize_t k=read(fd,resp+rlen,1);if(k<=0)break;rlen++;}
    close(fd);
    char *body=strstr(resp,"\r\n\r\n");
    if(body) printf("Server status:\n%s\n",body+4);
}

/* ── Main ────────────────────────────────────────────────────────────── */
int main(int argc,char*argv[]){
    cache_load();

    int do_scan=0, do_watch=1, do_status=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--full-scan"))  do_scan=1;
        if(!strcmp(argv[i],"--no-watch"))   do_watch=0;
        if(!strcmp(argv[i],"--status"))   { do_status=1; do_watch=0; }
    }

    printf("=== WhatsApp Backup Client ===\n");
    printf("Server : %s:%d\n",SERVER_HOST,SERVER_PORT);
    printf("Device : %s\n\n",DEVICE_ID);

    if(do_status){ check_status(); return 0; }

    if(do_scan) full_scan();
    if(do_watch) watch_loop();

    return 0;
}
