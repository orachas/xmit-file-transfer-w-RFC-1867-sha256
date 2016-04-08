#include <stdio.h> /* sha256micro.c -        Copyright 2015 Charles Fisher. */
#define uchar unsigned char /* 8-bit byte    Distributedunder the terms of  */
#define uint unsigned int /* 32-bit word     the GNU Lesser General Public  */
/* cc -o sha256micro sha256micro.c sha256.c  License (LGPL 2.1)             */

typedef struct
{ uchar data[64]; uint datalen; uint bitlen[2]; uint state[8]; } SHA256_CTX;
void sha256_init(SHA256_CTX *); void sha256_final(SHA256_CTX *, uchar *hash);
void sha256_update(SHA256_CTX *, uchar *, uint len);

int main(int argc, char **argv)
{FILE *fp;
 while(argc)
 {if((fp = fopen(argv[argc], "r")))
  {int l; SHA256_CTX ctx; uchar buf[BUFSIZ];
   sha256_init(&ctx);
   while((l = fread(buf, 1, BUFSIZ, fp))) sha256_update(&ctx, buf, l);
   sha256_final(&ctx, buf); fclose(fp);
   for(l = 0; l < 32; l++) printf("%02x", buf[l]);
   printf(" %s\n", argv[argc]);
  }
  argc--; 
} return 0; }
