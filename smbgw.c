#include <stdio.h>    /* smbgw.c - RFC-1867 file transfer to SMB3      */
#include <string.h>   /* http://libccgi.sourceforge.net - cgi by Losen */
#include <stdlib.h>   /* http://bradconte.com/sha256_c  - sha by Conte */
#include <unistd.h>   /* Copyright 2017 Charles Fisher. Distributed    */
#include <time.h>     /* under the terms of the GNU Lesser General     */
#include <sys/stat.h> /* Public License (LGPL 2.1)                     */
#include <sys/types.h>/* Compile with:
cc -Wall -I. -O2 -o smbgw.cgi smbgw.c ccgi.c strlcpy.c strlcat.c sha256.c
I wish I could: https://matt.sh/howto-c - also consider -static/chroot */

#include "ccgi.h"

#define UPL_PATH "/home/httpd/smbgw/" /* Trailing slash/filename prefix 400 */
#define TMP_PATH "/home/httpd/smbgw/smbgw" /* Must lie in same filesystem.  */
#define LOG_PATH "/home/httpd/logs/smbgw.log" /* Must be writable. */
#define DIR_PATH "/usr/local/etc/allowed_dirs.txt"

#define uchar unsigned char /*  8-bit byte                             */
#define uint unsigned int /*   32-bit word                             */

typedef struct {
 uchar data[64];
 uint  datalen;
 uint  bitlen[2];
 uint  state[8]; } SHA256_CTX;

void sha256_init(SHA256_CTX *);
void sha256_update(SHA256_CTX *, uchar *, uint len);
void sha256_final(SHA256_CTX *, uchar *hash);

size_t strlcat(char *, const char *, size_t);
size_t strlcpy(char *, const char *, size_t);

int main(int argc, char **argv)
{
 CGI_varlist *vl;
 int tlen = strlen(TMP_PATH);
 FILE *log;
 const char *name, *dir;
 char prefix[BUFSIZ] = UPL_PATH, dst[BUFSIZ], srv[BUFSIZ],
      *p = getenv("SCRIPT_NAME"), *q;

 umask(umask((mode_t)0)|S_IWUSR|S_IWGRP|S_IWOTH|S_IXUSR|S_IXGRP|S_IXOTH);

 if(p != NULL) /* The program must be named after the target server */
 {
  char genbuf[BUFSIZ];

  if(strlcpy(dst, p, BUFSIZ) >= BUFSIZ) return 1;
  if((p = strrchr(dst, '/')) != NULL) p++; else p = dst;
  if(strlcpy(genbuf, p, BUFSIZ) >= BUFSIZ) return 1;
  if(strlcpy(srv, p, BUFSIZ) >= BUFSIZ) return 1;
  if((p = strchr(genbuf, '.')) != NULL) *p = '\0';
  if((p = strchr(srv, '.')) != NULL) *p = '\0';
  if(strlcat(prefix, genbuf, BUFSIZ) >= BUFSIZ ||
   strlcat(prefix, "-", BUFSIZ) >= BUFSIZ) return 1;
 } else if(strlcat(prefix, "IN-", BUFSIZ) >= BUFSIZ) return 1;

 printf("Content-type: text/plain\r\n\r\n");

 if((log = fopen(LOG_PATH,"a")) == NULL) { printf("log error\n"); return 1; }

 if((vl = CGI_get_all(TMP_PATH"-XXXXXX")) == 0 )
 { printf("nodata\n"); return 1; }

/*All files received--force to disk: sync && echo 3 > /proc/sys/vm/drop_caches*/
 sync(); /* Suggest to disk */

 if(!(dir = CGI_lookup(vl, "dir"))) { printf("no dir\n"); return 1; }
 else
 {
  FILE *dirs = fopen(DIR_PATH, "r"); /* SMB server permitted directories */
  char genbuf[BUFSIZ], f = 1;

  if(!dirs) { printf("no dir\n"); return 1; }
  while(fgets(genbuf, BUFSIZ, dirs))
  { /* Remove the fgets-included newline */
   if((p = strrchr(genbuf, '\n')) != NULL) *p = '\0';
   if(!strcmp(genbuf, dir)) { f = 0; break; }
  }

  fclose(dirs);

  if(f) { printf("no dir\n"); return 1; }
 }

 printf("%s\n", dir);

 for(name = CGI_first_name(vl); name != 0; name = CGI_next_name(vl))
 {
  int i, j;
  CGI_value *val;

  if(!(val = CGI_lookup_all(vl, 0))) continue;

  for(i = 0; val[i]; i++) /* Does filename match TMP_PATH, and exist?  */
  {
   struct stat junk_buf;
   //printf("NAME{VAL}: %s{%s}\n", name, val[i]);

   if(!strncmp(val[i], TMP_PATH, tlen) && !stat(val[i], &junk_buf))
   {
    FILE *fp;
    time_t epoch = time(NULL);
    struct tm *now = localtime(&epoch);

    j = i++; /* Now, val[j] == tmp_name, val[i] == user's sent name.   */

    strftime(dst, BUFSIZ, "%y/%m/%d %H:%M:%S", now);
    fprintf(log, "%s %s %s", dst, getenv("REMOTE_ADDR"), val[i]);

    if((p = strrchr(val[i], '/')) != NULL) p++; else p = val[i];
    if((q = strrchr(p, '\\')) != NULL) p = q + 1; /*IE sends full path.*/
    q = p; /* Original file name is retained here */

    if(strlcpy(dst, prefix, BUFSIZ) >= BUFSIZ ||
     strlcat(dst, p, BUFSIZ) >= BUFSIZ) /* Skip if basename oversized. */
    {
     printf("error\n"); fprintf(log, " _FLEN-RETAINED_ %s\n", val[j]);
     continue;
    }

    if(link(val[j], dst) && /* On link failure, try to keep this data. */
     (strlcat(dst, val[j] + tlen, BUFSIZ) >= BUFSIZ ||
     link(val[j], dst))) /* mkstemp suffix appended to filename.       */
    {
     printf("name_error\t%s\n", val[i]);
     fprintf(log, " _LINK-RETAINED_ %s\n", val[j]); continue;
    } else fprintf(log, " _RENAMED_ %s", dst);

    if(unlink(val[j]))
    {
     printf("tmp_error\t%s\n", val[i]);
     fprintf(log, " _UNLINK-RETAINED_ %s", val[j]);
    }

    fprintf(log,"\n");

    if((fp = fopen(dst, "r")))
    {
     SHA256_CTX ctx;
     uchar buf[BUFSIZ];
     char cmd[BUFSIZ], dirbuf[BUFSIZ];

     /* Report the sha256sum--at least client can verify this leg of the trip */
     sha256_init(&ctx);
     while((j = fread(buf, 1, BUFSIZ, fp))) sha256_update(&ctx, buf, j);
     sha256_final(&ctx, buf);
     fclose(fp);
     for(j = 0; j < 32; j++) printf("%02x", buf[j]);
     printf("\t%s\n", val[i]);


     /* Build the smbclient command line - add -e for encryption if desired */
     strlcpy(cmd, "smbclient -mSMB3 -A/usr/local/etc/.", BUFSIZ);
     strlcat(cmd, srv,			BUFSIZ); /*Note that smbclient didn't*/
     strlcat(cmd, ".auth '//",		BUFSIZ); /*get SMB3 until Samba v4.1 */
     strlcat(cmd, srv,			BUFSIZ);
     if(*dir != '/') strlcat(cmd, "/",	BUFSIZ);

     strlcpy(dirbuf,  dir,		BUFSIZ);
     if((p = strchr(dirbuf + 1, '/')) != NULL)
     { /* Pull the share name off, then cd to subdir */
      *p = '\0';
      strlcat(cmd, dirbuf,		BUFSIZ);
      strlcat(cmd, "' -c 'cd \"",	BUFSIZ);
      strlcat(cmd, p + 1,		BUFSIZ);
      strlcat(cmd, "\"; ",		BUFSIZ);
     } /* smbclient doesn't cd properly if this isn't done */
     else
     { /* No subdir, so put directly */
      strlcat(cmd, dir,			BUFSIZ);
      strlcat(cmd, "' -c '",		BUFSIZ);
     }

     strlcat(cmd, "put ",		BUFSIZ);
     strlcat(cmd, dst,			BUFSIZ);
     strlcat(cmd, " ",			BUFSIZ);
     strlcat(cmd, q,			BUFSIZ);
     strlcat(cmd, "' 2>&1",		BUFSIZ);

     fprintf(log, "%s\n", cmd);

     if((fp = popen(cmd, "r"))) /* Run the SMB transfer */
     {
      while(fgets(cmd, BUFSIZ, fp)) printf("%s", cmd);
      fclose(fp);
     }
    }
   }
  }
 }

 CGI_free_varlist(vl);
 fclose(log);
 fflush(NULL);
 return 0;
}

/* Client usage examples:

[server] cd apache/cgi-bin
[server] ln smbgw.cgi remotesmbhost.cgi
[server] grep search /etc/resolv.conf
search someweirddomain.com
[server] nslookup remotesmbhost.someweirddomain.com
Name:	 remotesmbhost.someweirddomain.com
Address: 1.2.3.4



[client] curl -F dir=/allowed/target -F blah=@your.file http://webserver.com/remotesmbhost.cgi
/allowed/target
b9087b71faee72d6d63da2c1fe5a252889473f80582082567d21d56d6e148c25   your.file
Domain=[NT_IS_WONDERFUL] OS=[] Server=[]
putting file /home/httpd/smbgw/remotesmbhost-your.file as \allowed\target\your.file (886.7 kb/s) (average 886.7 kb/s)


[client] cat perl_upload.pl
#!/usr/bin/perl -w
# This reads the whole file into memory at once - don't use for big files.
use LWP::UserAgent; #Usage perl_upload file server_dir url
use HTTP::Request::Common qw(POST);
my $ua = LWP::UserAgent->new();
my $content;

open(my $fh, '<', $ARGV[0]) or die "cannot open file $ARGV[0]";
{ local $/; $content = <$fh>; }
close($fh);

my $request = POST $ARGV[2],
    Content_Type => 'form-data',
    Content => [ 'smbfile' => [undef, $ARGV[0], Content => $content],
                 'dir' => $ARGV[1] ];

my $results = $ua->request($request);

print $results->status_line() . "\n";
if($results->is_success){ print "Successful transfer.\n"; }
else { print "Failed transfer.\n"; }

print $results->content() . "\n";


[client] perl_upload.pl your.file /allowed/target http://webserver.com/remotesmbhost.cgi
200 OK
Successful transfer.
/allowed/target
23d98070c297be886e792496415b1a1c97e5f17ca596fb3c33367c8a8e9e447c	your.file
Domain=[NT_IS_WONDERFUL] OS=[] Server=[]
putting file /home/httpd/smbgw/remotesmbhost-your.file as \allowed\target\your.file (886.7 kb/s) (average 886.7 kb/s)

*/
