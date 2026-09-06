#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "libfdt.h"
typedef uint8_t u8; typedef uint32_t __be32;
#define cpu_to_be32(x) htonl(x)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define TPM2_DIGEST_LEN 32
static FILE *stream;
typedef struct { unsigned long n; } sha256_context;
static void sha256_starts(sha256_context *c){c->n=0;}
static void sha256_update(sha256_context *c,const u8 *d,unsigned l){c->n+=l; fwrite(d,1,l,stream);}
static void sha256_finish(sha256_context *c,u8 *o){memset(o,0,32);}
#include "extract.c"
int main(int argc,char**argv){
  FILE*f=fopen(argv[1],"rb"); if(!f){perror("open");return 2;}
  fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
  void*fdt=malloc(n); fread(fdt,1,n,f); fclose(f);
  if(fdt_check_header(fdt)){fprintf(stderr,"bad header\n");return 2;}
  stream=fopen(argv[2],"wb");
  u8 out[32]; int rc=tcg2_dtb_canonical_digest(fdt,out); fclose(stream);
  printf("rc=%d ", rc); return rc?1:0;
}
