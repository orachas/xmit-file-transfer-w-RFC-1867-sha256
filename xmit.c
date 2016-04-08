#include <stdio.h>    /*xmit.c *prototype* RFC-1867 file transfer with:*/
#include <string.h>   /* http://libccgi.sourceforge.net - cgi by Losen */
#include <stdlib.h>   /* http://bradconte.com/sha256_c  - sha by Conte */
#include <unistd.h>   /* Copyright 2015 Charles Fisher. Distributed    */  
#include <sys/types.h>/* under the terms of the GNU Lesser General     */
#include <sys/stat.h> /* Public License (LGPL 2.1)                     */  
#include "ccgi.h"

/* Compile with: gcc -static -Wall -I. -O2 -o xmit.cgi xmit.c ccgi.c \
                   strlcpy.c strlcat.c sha256.c
##BEWARE:
http://www.slideshare.net/phdays/chw00t-breaking-unices-chroot-solutions
https://matt.sh/howto-c
*/

#define UPL_PATH "/upload/" /* Trailing slash or filename prefix.      */
#define TMP_PATH "/upload/cgi-upload" /* Must point to same filesystem.*/
#define uchar unsigned char /* 8-bit byte                              */
#define uint unsigned int /* 32-bit word                               */

typedef struct { uchar data[64];  uint datalen;  uint bitlen[2];
 uint state[8]; } SHA256_CTX;

void sha256_init(SHA256_CTX *);
void sha256_update(SHA256_CTX *, uchar *, uint len);
void sha256_final(SHA256_CTX *, uchar *hash);
size_t strlcat(char *, const char *, size_t);
size_t strlcpy(char *, const char *, size_t);

int main(int argc, char **argv)
{CGI_varlist *vl;  const char *name;  int mask_len = strlen(TMP_PATH);
 char prefix[BUFSIZ] = UPL_PATH, dst[BUFSIZ], *p = getenv("SCRIPT_NAME");

 /* Removing write and execute should constrain uploads to 400.        */
 umask(umask((mode_t)0)|S_IWUSR|S_IWGRP|S_IWOTH|S_IXUSR|S_IXGRP|S_IXOTH);

 printf("Content-type: text/plain\r\n\r\n");

 if(p != NULL) /* Use the SCRIPT_NAME as a filename local prefix.      */
 {char genbuf[BUFSIZ];

  if(strlcpy(dst, p, BUFSIZ) >= BUFSIZ) return 1;
  if((p = strrchr(dst, '/')) != NULL) p++; else p = dst;
  if(strlcpy(genbuf, p, BUFSIZ) >= BUFSIZ) return 1;
  if((p = strchr(genbuf, '.')) != NULL) *p = '\0';
  if(strlcat(prefix, genbuf, BUFSIZ) >= BUFSIZ ||
   strlcat(prefix, "-", BUFSIZ) >= BUFSIZ) return 1;
 } else if(strlcat(prefix, "IN-", BUFSIZ) >= BUFSIZ) return 1;

 if((vl = CGI_get_all(TMP_PATH "-XXXXXX")) == 0)
 { printf("CGI_get_all() failed\r\n"); return 1; }

 sync(); /* Rather: sync && echo 3 > /proc/sys/vm/drop_caches          */

 for(name = CGI_first_name(vl); name != 0; name = CGI_next_name(vl))
 {FILE *fp;  CGI_value *val;  struct stat junk_buf;  int i, j;

  if(!(val = CGI_lookup_all(vl, 0))) continue;
  for(i = 0; val[i]; i++)
  { /* Does filename match TMP_PATH, and does it exist?                */
   if(!strncmp(val[i], TMP_PATH, mask_len) && !stat(val[i], &junk_buf))
   { /* Abort if sent an empty|malicious|oversized filename.           */
    j = i++;
    if(!strlen(val[i]) || strchr(val[i], '/') || strchr(val[i], '\\') ||
     strlcpy(dst, prefix, BUFSIZ) >= BUFSIZ ||
     strlcat(dst, val[i], BUFSIZ) >= BUFSIZ) {printf("error");return 1;}

    if(link(val[j], dst))
    { /* On link failure, try our best to keep this data.              */
      if(strlcat(dst, val[j] + mask_len, BUFSIZ) >= BUFSIZ ||
       link(val[j], dst)) /* mkstemp suffix appended to filename.      */
      { printf("name_error\t%s\r\n", val[i]); continue; }
    }

    if(unlink(val[j])) { printf("tmp_error\t%s\r\n", val[i]); }

    if((fp = fopen(dst, "r")))
    {SHA256_CTX ctx;  uchar buf[BUFSIZ];

     sha256_init(&ctx);
     while((j = fread(buf, 1, BUFSIZ, fp))) sha256_update(&ctx, buf, j);
     sha256_final(&ctx, buf); fclose(fp);
     for(j = 0; j < 32; j++) printf("%02x", buf[j]);
     printf("\t%s\r\n", val[i]);
 }}}}
 CGI_free_varlist(vl); return 0;
}
