/*
 * wa_backup_server.c
 * WhatsApp Backup Server — pure C, POSIX sockets
 *
 * Compile:
 *   gcc -o wa_backup_server wa_backup_server.c -lpthread
 *
 * Run:
 *   ./wa_backup_server [port] [backup_dir] [api_key]
 *   ./wa_backup_server 5050 ./backups mysecretkey
 *
 * Endpoints (HTTP/1.0):
 *   POST /upload   — upload a file (multipart/form-data)
 *   GET  /status   — show file count per type
 *   GET  /list     — list last 100 uploaded files
 *
 * Headers required on every request:
 *   X-API-Key: <api_key>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
56786
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <dirent.h>
#include <signal.h>

/* ── Config ─────────────────────────────────────────────────────────────── */
#define DEFAULT_PORT      5050
#define DEFAULT_DIR       "./wa_backups"
#define DEFAULT_KEY       "changeme123"
#define MAX_HEADER        8192
#define MAX_BODY          (200 * 1024 * 1024)   /* 200 MB max upload */
#define BACKLOG           16
#define MAX_PATH_LEN      512
#define MAX_RECORDS       10000

/* ── Globals ─────────────────────────────────────────────────────────────── */
static char g_backup_dir[MAX_PATH_LEN];
static char g_api_key[256];

typedef struct {
    char original_name[256];
    char saved_path[MAX_PATH_LEN];
    char sha256[65];
    char file_type[32];
    long size_bytes;
    char device_id[64];
    char uploaded_at[32];
} FileRecord;

static FileRecord g_records[MAX_RECORDS];
static int        g_record_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── SHA-256 (public domain implementation) ─────────────────────────────── */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} SHA256_CTX;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x)    (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define SIG1(x)    (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define sig0(x)    (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define sig1(x)    (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *data) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,w[64];
    int i;
    for (i=0;i<16;i++) w[i]=((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|((uint32_t)data[i*4+2]<<8)|data[i*4+3];
    for (;i<64;i++) w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (i=0;i<64;i++){
        t1=h+SIG1(e)+CH(e,f,g)+K[i]+w[i];
        t2=SIG0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx){
    ctx->count=0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len){
    size_t i,used;
    used = ctx->count & 63;
    ctx->count += len;
    if (used){
        size_t free = 64 - used;
        if (len < free){ memcpy(ctx->buf+used, data, len); return; }
        memcpy(ctx->buf+used, data, free);
        sha256_transform(ctx, ctx->buf);
        data += free; len -= free;
    }
    for (i=0;i+64<=len;i+=64) sha256_transform(ctx, data+i);
    if (len-i) memcpy(ctx->buf, data+i, len-i);
}

static void sha256_final(SHA256_CTX *ctx, uint8_t *digest){
    uint8_t pad[64]={0}; size_t used=ctx->count&63;
    pad[0]=0x80;
    if (used<56){ sha256_update(ctx,pad,56-used); }
    else { sha256_update(ctx,pad,64-used+56); }
    uint64_t bits=ctx->count*8;
    uint8_t len_bytes[8];
    for(int i=7;i>=0;i--){ len_bytes[i]=(uint8_t)(bits&0xff); bits>>=8; }
    sha256_update(ctx,len_bytes,8);
    for(int i=0;i<8;i++){
        digest[i*4+0]=(ctx->state[i]>>24)&0xff;
        digest[i*4+1]=(ctx->state[i]>>16)&0xff;
        digest[i*4+2]=(ctx->state[i]>>8)&0xff;
        digest[i*4+3]=ctx->state[i]&0xff;
    }
}

static void sha256_hex(const uint8_t *data, size_t len, char *out){
    SHA256_CTX ctx; uint8_t digest[32];
    sha256_init(&ctx); sha256_update(&ctx,data,len); sha256_final(&ctx,digest);
    for(int i=0;i<32;i++) sprintf(out+i*2,"%02x",digest[i]);
    out[64]='\0';
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
static void mkdirs(const char *path){
    char tmp[MAX_PATH_LEN]; snprintf(tmp,sizeof(tmp),"%s",path);
    for(char *p=tmp+1;*p;p++){
        if(*p=='/'){ *p='\0'; mkdir(tmp,0755); *p='/'; }
    }
    mkdir(tmp,0755);
}

static const char *classify(const char *name){
    const char *dot = strrchr(name,'.');
    if(!dot) return "other";
    const char *e = dot+1;
    if(!strcasecmp(e,"jpg")||!strcasecmp(e,"jpeg")||!strcasecmp(e,"png")||
       !strcasecmp(e,"webp")||!strcasecmp(e,"gif")||!strcasecmp(e,"heic")||
       !strcasecmp(e,"heif")) return "images";
    if(!strcasecmp(e,"mp4")||!strcasecmp(e,"mov")||!strcasecmp(e,"avi")||
       !strcasecmp(e,"mkv")||!strcasecmp(e,"3gp")) return "videos";
    if(!strcasecmp(e,"mp3")||!strcasecmp(e,"ogg")||!strcasecmp(e,"m4a")||
       !strcasecmp(e,"aac")||!strcasecmp(e,"opus")) return "audio";
    if(!strcasecmp(e,"pdf")||!strcasecmp(e,"docx")||!strcasecmp(e,"txt")) return "documents";
    if(!strcasecmp(e,"zip")) return "chats";
    return "other";
}

static void safe_filename(const char *src, char *dst, size_t max){
    size_t i=0;
    for(;*src&&i<max-1;src++){
        char c=*src;
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
           c=='.'||c=='-'||c=='_') dst[i++]=c;
        else dst[i++]='_';
    }
    dst[i]='\0';
}

static int find_by_hash(const char *hash){
    for(int i=0;i<g_record_count;i++)
        if(!strcmp(g_records[i].sha256,hash)) return i;
    return -1;
}

/* ── HTTP helpers ─────────────────────────────────────────────────────────── */
static void send_response(int fd, int code, const char *ctype, const char *body){
    char hdr[512];
    int blen = (int)strlen(body);
    int n = snprintf(hdr,sizeof(hdr),
        "HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n",
        code, code==200?"OK":code==201?"Created":code==401?"Unauthorized":
              code==400?"Bad Request":code==409?"Conflict":"Error",
        ctype, blen);
    write(fd, hdr, n);
    write(fd, body, blen);
}

static char *header_value(const char *headers, const char *key){
    /* Returns pointer into headers just past "key: " — not null-terminated safely */
    char *p = strcasestr((char*)headers, key);
    if(!p) return NULL;
    p += strlen(key);
    while(*p==' ') p++;
    return p;
}

static void trim_crlf(char *s){
    char *p=s+strlen(s)-1;
    while(p>=s && (*p=='\r'||*p=='\n'||*p==' ')) *p--='\0';
}

/* Parse multipart/form-data — returns pointer to file data, sets *file_len */
static const char *parse_multipart(const char *body, size_t body_len,
                                    const char *boundary,
                                    char *out_name, size_t name_max,
                                    char *out_device, size_t dev_max,
                                    size_t *file_len){
    char delim[256]; snprintf(delim,sizeof(delim),"--%s",boundary);
    size_t dlen = strlen(delim);

    const char *p = body;
    const char *end = body + body_len;
    *file_len = 0;
    out_name[0] = '\0';
    out_device[0] = '\0';

    while(p < end){
        /* Find next boundary */
        const char *bd = memmem(p, end-p, delim, dlen);
        if(!bd) break;
        bd += dlen;
        if(bd[0]=='-'&&bd[1]=='-') break;   /* final boundary */
        if(bd[0]=='\r') bd++;
        if(bd[0]=='\n') bd++;

        /* Read part headers */
        const char *part_hdr_end = memmem(bd, end-bd, "\r\n\r\n", 4);
        if(!part_hdr_end) break;
        size_t hdr_len = part_hdr_end - bd;

        /* Copy headers into temp buffer */
        char hdr_buf[2048]={0};
        if(hdr_len>=sizeof(hdr_buf)) hdr_len=sizeof(hdr_buf)-1;
        memcpy(hdr_buf, bd, hdr_len);

        const char *part_data = part_hdr_end + 4;

        /* Find end of this part */
        const char *next_bd = memmem(part_data, end-part_data, delim, dlen);
        size_t part_data_len = next_bd ? (size_t)(next_bd - part_data - 2) : (size_t)(end - part_data);

        /* Check Content-Disposition */
        char *disp = strcasestr(hdr_buf,"Content-Disposition:");
        if(disp){
            char *fname = strstr(disp,"filename=\"");
            char *field = strstr(disp,"name=\"");
            if(fname){
                fname += 10;
                char *eq = strchr(fname,'"');
                if(eq){
                    size_t n = (size_t)(eq-fname);
                    if(n>=name_max) n=name_max-1;
                    memcpy(out_name,fname,n); out_name[n]='\0';
                    *file_len = part_data_len;
                    p = next_bd ? next_bd : end;
                    /* Return pointer to file data */
                    return part_data;
                }
            } else if(field){
                field += 6;
                char *eq = strchr(field,'"');
                if(eq){
                    char fname2[64]={0};
                    size_t n=(size_t)(eq-field); if(n>=64)n=63;
                    memcpy(fname2,field,n);
                    if(!strcmp(fname2,"device_id")){
                        size_t dl = part_data_len < dev_max-1 ? part_data_len : dev_max-1;
                        memcpy(out_device, part_data, dl);
                        out_device[dl]='\0';
                        trim_crlf(out_device);
                    }
                }
            }
        }
        p = next_bd ? next_bd : end;
    }
    return NULL;
}

/* ── Request handlers ────────────────────────────────────────────────────── */
static void handle_upload(int fd, const char *headers,
                           const char *body, size_t body_len){
    /* Auth */
    char *key = header_value(headers,"X-API-Key:");
    if(!key){ send_response(fd,401,"application/json","{\"error\":\"No API key\"}"); return; }
    char key_copy[256]={0}; strncpy(key_copy,key,255); trim_crlf(key_copy);
    if(strcmp(key_copy,g_api_key)){
        send_response(fd,401,"application/json","{\"error\":\"Bad API key\"}"); return;
    }

    /* Parse boundary from Content-Type */
    char *ct = header_value(headers,"Content-Type:");
    if(!ct){ send_response(fd,400,"application/json","{\"error\":\"No Content-Type\"}"); return; }
    char *bnd = strstr(ct,"boundary=");
    if(!bnd){ send_response(fd,400,"application/json","{\"error\":\"No boundary\"}"); return; }
    bnd += 9;
    char boundary[256]={0}; strncpy(boundary,bnd,255); trim_crlf(boundary);

    /* Parse multipart */
    char filename[256]={0}, device_id[64]={0};
    size_t file_len = 0;
    const char *file_data = parse_multipart(body, body_len, boundary,
                                             filename, sizeof(filename),
                                             device_id, sizeof(device_id),
                                             &file_len);
    if(!file_data || !filename[0] || file_len==0){
        send_response(fd,400,"application/json","{\"error\":\"No file in request\"}"); return;
    }
    if(!device_id[0]) strcpy(device_id,"unknown");

    /* Hash */
    char digest[65];
    sha256_hex((const uint8_t*)file_data, file_len, digest);

    pthread_mutex_lock(&g_lock);

    /* Dedup */
    if(find_by_hash(digest)>=0){
        pthread_mutex_unlock(&g_lock);
        char resp[256]; snprintf(resp,sizeof(resp),"{\"status\":\"duplicate\",\"sha256\":\"%s\"}",digest);
        send_response(fd,200,"application/json",resp); return;
    }

    /* Organise path: backup_dir/type/YYYY-MM-DD/filename */
    const char *ftype = classify(filename);
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char datedir[32]; strftime(datedir,sizeof(datedir),"%Y-%m-%d",tm);
    char safe_name[256]; safe_filename(filename,safe_name,sizeof(safe_name));

    char dest_dir[MAX_PATH_LEN];
    snprintf(dest_dir,sizeof(dest_dir),"%s/%s/%s",g_backup_dir,ftype,datedir);
    mkdirs(dest_dir);

    char dest_path[MAX_PATH_LEN];
    snprintf(dest_path,sizeof(dest_path),"%s/%s",dest_dir,safe_name);

    /* Avoid name collision */
    int counter=1;
    while(access(dest_path,F_OK)==0){
        char *dot=strrchr(safe_name,'.');
        if(dot){
            char stem[256]={0}; size_t slen=(size_t)(dot-safe_name);
            if(slen>=256)slen=255;
            memcpy(stem,safe_name,slen);
            snprintf(dest_path,sizeof(dest_path),"%s/%s_%d%s",dest_dir,stem,counter,dot);
        } else {
            snprintf(dest_path,sizeof(dest_path),"%s/%s_%d",dest_dir,safe_name,counter);
        }
        counter++;
    }

    /* Write file */
    FILE *fp = fopen(dest_path,"wb");
    if(!fp){
        pthread_mutex_unlock(&g_lock);
        send_response(fd,500,"application/json","{\"error\":\"Cannot write file\"}"); return;
    }
    fwrite(file_data,1,file_len,fp);
    fclose(fp);

    /* Store record */
    if(g_record_count < MAX_RECORDS){
        FileRecord *r = &g_records[g_record_count++];
        strncpy(r->original_name, filename,   sizeof(r->original_name)-1);
        strncpy(r->saved_path,    dest_path,  sizeof(r->saved_path)-1);
        strncpy(r->sha256,        digest,      64);
        strncpy(r->file_type,     ftype,       sizeof(r->file_type)-1);
        r->size_bytes = (long)file_len;
        strncpy(r->device_id,     device_id,  sizeof(r->device_id)-1);
        strftime(r->uploaded_at, sizeof(r->uploaded_at), "%Y-%m-%d %H:%M:%S", tm);
    }

    pthread_mutex_unlock(&g_lock);

    printf("[+] Saved: %s (%zu KB) -> %s\n", filename, file_len/1024, dest_path);

    char resp[512];
    snprintf(resp,sizeof(resp),
        "{\"status\":\"ok\",\"path\":\"%s\",\"sha256\":\"%s\",\"size\":%zu}",
        dest_path, digest, file_len);
    send_response(fd,201,"application/json",resp);
}

static void handle_status(int fd, const char *headers){
    char *key = header_value(headers,"X-API-Key:");
    if(!key){ send_response(fd,401,"application/json","{\"error\":\"No API key\"}"); return; }
    char key_copy[256]={0}; strncpy(key_copy,key,255); trim_crlf(key_copy);
    if(strcmp(key_copy,g_api_key)){
        send_response(fd,401,"application/json","{\"error\":\"Bad API key\"}"); return;
    }

    pthread_mutex_lock(&g_lock);
    long images=0,videos=0,audio=0,docs=0,chats=0,other=0;
    for(int i=0;i<g_record_count;i++){
        const char *t=g_records[i].file_type;
        if(!strcmp(t,"images")) images++;
        else if(!strcmp(t,"videos")) videos++;
        else if(!strcmp(t,"audio")) audio++;
        else if(!strcmp(t,"documents")) docs++;
        else if(!strcmp(t,"chats")) chats++;
        else other++;
    }
    int total = g_record_count;
    pthread_mutex_unlock(&g_lock);

    char resp[512];
    snprintf(resp,sizeof(resp),
        "{\"total\":%d,\"images\":%ld,\"videos\":%ld,"
        "\"audio\":%ld,\"documents\":%ld,\"chats\":%ld,\"other\":%ld}",
        total,images,videos,audio,docs,chats,other);
    send_response(fd,200,"application/json",resp);
}

static void handle_list(int fd, const char *headers){
    char *key = header_value(headers,"X-API-Key:");
    if(!key){ send_response(fd,401,"application/json","{\"error\":\"No API key\"}"); return; }
    char key_copy[256]={0}; strncpy(key_copy,key,255); trim_crlf(key_copy);
    if(strcmp(key_copy,g_api_key)){
        send_response(fd,401,"application/json","{\"error\":\"Bad API key\"}"); return;
    }

    pthread_mutex_lock(&g_lock);
    char *buf = malloc(g_record_count * 512 + 64);
    if(!buf){ pthread_mutex_unlock(&g_lock); send_response(fd,500,"application/json","{}"); return; }

    int pos = 0;
    pos += sprintf(buf+pos,"[");
    int limit = g_record_count < 100 ? g_record_count : 100;
    int start = g_record_count - limit;
    for(int i=start;i<g_record_count;i++){
        FileRecord *r=&g_records[i];
        pos += sprintf(buf+pos,
            "%s{\"name\":\"%s\",\"type\":\"%s\",\"size\":%ld,"
            "\"device\":\"%s\",\"at\":\"%s\",\"sha256\":\"%s\"}",
            i>start?",":"",
            r->original_name,r->file_type,r->size_bytes,
            r->device_id,r->uploaded_at,r->sha256);
    }
    pos += sprintf(buf+pos,"]");
    pthread_mutex_unlock(&g_lock);

    send_response(fd,200,"application/json",buf);
    free(buf);
}

/* ── Connection thread ───────────────────────────────────────────────────── */
typedef struct { int fd; } ConnArg;

static void *handle_connection(void *arg){
    ConnArg *ca = (ConnArg*)arg;
    int fd = ca->fd; free(ca);

    /* Read request (headers + body) */
    char *headers = malloc(MAX_HEADER);
    char *body    = NULL;
    if(!headers){ close(fd); return NULL; }
    headers[0]='\0';

    /* Read headers */
    size_t hdr_len=0;
    while(hdr_len < MAX_HEADER-1){
        ssize_t n = read(fd, headers+hdr_len, 1);
        if(n<=0) break;
        hdr_len++;
        if(hdr_len>=4 && !memcmp(headers+hdr_len-4,"\r\n\r\n",4)) break;
    }
    headers[hdr_len]='\0';

    /* Parse method and path from request line */
    char method[16]={0}, path[256]={0};
    sscanf(headers,"%15s %255s",method,path);

    /* Strip query string */
    char *qs = strchr(path,'?'); if(qs) *qs='\0';

    size_t body_len=0;
    char *cl = header_value(headers,"Content-Length:");
    if(cl){
        body_len = (size_t)atol(cl);
        if(body_len > MAX_BODY) body_len = MAX_BODY;
        body = malloc(body_len+1);
        if(body){
            size_t got=0;
            while(got<body_len){
                ssize_t n=read(fd,body+got,body_len-got);
                if(n<=0) break;
                got+=n;
            }
            body[got]='\0';
            body_len=got;
        }
    }

    if(!strcmp(method,"POST") && !strcmp(path,"/upload")){
        if(body) handle_upload(fd,headers,body,body_len);
        else send_response(fd,400,"application/json","{\"error\":\"No body\"}");
    } else if(!strcmp(method,"GET") && !strcmp(path,"/status")){
        handle_status(fd,headers);
    } else if(!strcmp(method,"GET") && !strcmp(path,"/list")){
        handle_list(fd,headers);
    } else {
        send_response(fd,404,"application/json","{\"error\":\"Not found\"}");
    }

    free(headers);
    if(body) free(body);
    close(fd);
    return NULL;
}

/* ── Main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]){
    signal(SIGPIPE, SIG_IGN);

    int port = argc>1 ? atoi(argv[1]) : DEFAULT_PORT;
    strncpy(g_backup_dir, argc>2 ? argv[2] : DEFAULT_DIR, MAX_PATH_LEN-1);
    strncpy(g_api_key,    argc>3 ? argv[3] : DEFAULT_KEY, 255);

    mkdirs(g_backup_dir);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if(srv<0){ perror("socket"); return 1; }

    int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET;
    addr.sin_port=htons((uint16_t)port);
    addr.sin_addr.s_addr=INADDR_ANY;

    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); return 1; }
    if(listen(srv,BACKLOG)<0){ perror("listen"); return 1; }

    printf("=== WhatsApp Backup Server ===\n");
    printf("Port      : %d\n", port);
    printf("Backup dir: %s\n", g_backup_dir);
    printf("API key   : %s\n", g_api_key);
    printf("Waiting for connections...\n\n");

    while(1){
        struct sockaddr_in cli; socklen_t clen=sizeof(cli);
        int cfd = accept(srv,(struct sockaddr*)&cli,&clen);
        if(cfd<0){ perror("accept"); continue; }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&cli.sin_addr,ip,sizeof(ip));

        ConnArg *ca = malloc(sizeof(ConnArg));
        if(!ca){ close(cfd); continue; }
        ca->fd = cfd;

        pthread_t tid;
        if(pthread_create(&tid,NULL,handle_connection,ca)!=0){
            free(ca); close(cfd);
        } else {
            pthread_detach(tid);
        }
    }
    return 0;
}
