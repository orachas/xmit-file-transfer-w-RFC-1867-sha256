#include <stdio.h>    /* smbgw.c - RFC-1867 gateway to SMB3            */
#include <string.h>   /* http://libccgi.sourceforge.net - cgi by Losen */
#include <stdlib.h>   /* http://bradconte.com/sha256_c  - sha by Conte */
#include <unistd.h>   /* Copyright 2015 Charles Fisher. Distributed    */
#include <time.h>     /* under the terms of the GNU Lesser General     */
#include <sys/stat.h> /* Public License (LGPL 2.1)                     */
#include <sys/types.h>/* Compile with:
cc -Wall -I. -g -O2 -o smbgw.cgi smbgw.c ccgi.c strlcpy.c strlcat.c sha256.c
I wish I could: https://matt.sh/howto-c - also consider -static/chroot */

#include "ccgi.h"

#define UPL_PATH "/home/httpd/smbgw/" /* Trailing slash/filename prefix 400 */
#define TMP_PATH "/home/httpd/smbgw/smbgw" /* Must lie in same filesystem.  */
#define LOG_PATH "/home/httpd/logs/smbgw.log" /* Must exist & be writable.  */
#define DIR_PATH "/usr/local/etc/allowed_dirs.txt"

#define uchar unsigned char /*  8-bit byte                             */
#define uint unsigned int /*   32-bit word                             */

typedef struct {               /* smbclient now depends on over 100    */
 uchar data[64];               /* .so libraries on modern systems - it */
 uint  datalen;                /* is far too large for admins to build */
 uint  bitlen[2];              /* from source for every critical patch */
 uint  state[8]; } SHA256_CTX; /* Old systems need a gateway           */

void sha256_init(SHA256_CTX *);
void sha256_update(SHA256_CTX *, uchar *, uint len);
void sha256_final(SHA256_CTX *, uchar *hash);

size_t strlcat(char *, const char *, size_t);
size_t strlcpy(char *, const char *, size_t);

void E(void) { printf("command error\n"); } /* error functions */
void e(char *s) { printf(s); }

int main(int argc, char **argv)
{
 CGI_varlist *vl;
 int tlen = strlen(TMP_PATH);
 FILE *log;
 const char *name, *dir;
 char prefix[BUFSIZ] = UPL_PATH, dst[BUFSIZ], srv[BUFSIZ],
      *p = getenv("SCRIPT_NAME");

 umask(umask((mode_t)0)|S_IWUSR|S_IWGRP|S_IWOTH|S_IXUSR|S_IXGRP|S_IXOTH);

 printf("Content-type: text/plain\r\n\r\n");

 if(p != NULL) /* The CGI-reported basename must be the target server */
 {
  char genbuf[BUFSIZ];

  if(strlcpy(dst, p,         BUFSIZ) >= BUFSIZ) return 1; /* These are self-  */
  if((p = strrchr(dst, '/')) != NULL) p++; else p = dst;
  if(strlcpy(genbuf, p,      BUFSIZ) >= BUFSIZ) return 1; /* inflicted errors */
  if(strlcpy(srv, p,         BUFSIZ) >= BUFSIZ) return 1; /* that users should*/
  if((p = strchr(genbuf, '.')) != NULL) *p = '\0';
  if((p = strchr(srv, '.')) != NULL) *p = '\0';
  if(strlcat(prefix, genbuf, BUFSIZ) >= BUFSIZ ||
     strlcat(prefix, "-",    BUFSIZ) >= BUFSIZ) return 1; /* not normally see */
 } else { e("config error"); return 1; }


 if((log = fopen(LOG_PATH, "a")) == NULL) { e("log error"); return 1; }

 if((vl = CGI_get_all(TMP_PATH"-XXXXXX")) == 0 ) { e("nodata"); return 1; }

/*All files received--force to disk: sync && echo 3 > /proc/sys/vm/drop_caches*/
 sync(); /* Suggest to disk */

 if((dir = CGI_lookup(vl, "dir")))
 {
  FILE *dirs = fopen(DIR_PATH, "r"); /* SMB server permitted directories */
  char genbuf[BUFSIZ], f = 1;

  if(!dirs) { e("no dir"); return 1; }
  while(fgets(genbuf, BUFSIZ, dirs))
  { /* Remove the fgets-included newline */
   if((p = strrchr(genbuf, '\n')) != NULL) *p = '\0';
   if(!strcmp(genbuf, dir)) { f = 0; break; }
  }

  fclose(dirs);

  if(f) { e("no dir"); return 1; }
 }
 else { e("no dir"); return 1; }

 printf("%s\n", dir);

 for(name = CGI_first_name(vl); name != 0; name = CGI_next_name(vl))
 {
  int i;
  CGI_value *val;

  if(!(val = CGI_lookup_all(vl, 0))) continue;

  for(i = 0; val[i]; i++)
  {
   struct stat junk_buf; /* Does filename match TMP_PATH, and exist? */

   if(!strncmp(val[i], TMP_PATH, tlen) && !stat(val[i], &junk_buf))
   { /* RFC-1867 files come in name pairs, and the index must be advanced. */
    FILE *goodfile;
    const char *z;
    time_t epoch = time(NULL);
    struct tm *now = localtime(&epoch);
    int j = i++; /* Now, val[j] == tmp_name, val[i] == user's sent name. */

    strftime(dst, BUFSIZ, "%y/%m/%d %H:%M:%S", now);
    fprintf(log, "%s %s %s", dst, getenv("REMOTE_ADDR"), val[i]);

    if((z = strrchr(val[i], '/')) != NULL) z++; else z = val[i];
    if((p = strrchr(z, '\\')) != NULL) z = p + 1; /* IE sends full path. */

    if(strlcpy(dst, prefix, BUFSIZ) >= BUFSIZ ||
       strlcat(dst, z,      BUFSIZ) >= BUFSIZ) /* Skip if basename oversized. */
    {
     e("error\n");
     fprintf(log, " _FLEN-RETAINED_ %s\n", val[j]);
     continue;
    }

    if(link(val[j], dst) && /* On link failure, try to keep this data.   */
       (strlcat(dst, val[j] + tlen, BUFSIZ) >= BUFSIZ || /* new filename */
        link(val[j], dst))) /* mkstemp suffix appended                   */
    {
     printf("name_error\t%s\n", val[i]);
     fprintf(log, " _LINK-RETAINED_ %s\n", val[j]);
     continue;
    } else fprintf(log, " _RENAMED_ %s", dst);

    if(unlink(val[j]))
    {
     printf("tmp_error\t%s\n", val[i]); /* This is not a fatal error */
     fprintf(log, " _UNLINK-RETAINED_ %s", val[j]);
    }

    fprintf(log,"\n");

    if((goodfile = fopen(dst, "r")))
    {
     SHA256_CTX ctx;
     uchar buf[BUFSIZ];
     char cmd[BUFSIZ], dirbuf[BUFSIZ];

     /* Report the sha256sum--at least client can verify this leg of the trip */
     sha256_init(&ctx);
     while((j = fread(buf, 1, BUFSIZ, goodfile))) sha256_update(&ctx, buf, j);
     sha256_final(&ctx, buf);
     fclose(goodfile);

     for(j = 0; j < 32; j++) printf("%02x", buf[j]);
     printf("\t%s\n", val[i]);

     /* Build the smbclient command line - add -e for encryption if desired */
     if(strlcpy(cmd, "smbclient -mSMB3 -A/usr/local/etc/.", BUFSIZ) >= BUFSIZ ||
     strlcat(cmd, srv,         BUFSIZ) >= BUFSIZ ||/*Note:smbclient didn't get*/
     strlcat(cmd, ".auth '//", BUFSIZ) >= BUFSIZ ||/*    SMB3 until Samba v4.1*/
     strlcat(cmd, srv,         BUFSIZ) >= BUFSIZ) { E(); continue; }

     if(*dir != '/' && strlcat(cmd, "/", BUFSIZ) >= BUFSIZ) { E(); continue; }
     if(            strlcpy(dirbuf, dir, BUFSIZ) >= BUFSIZ) { E(); continue; }

     if((p = strchr(dirbuf + 1, '/')) != NULL)
     { /* Pull the share name off, then cd to subdir */
      *p = '\0';
      if(strlcat(cmd, dirbuf,        BUFSIZ) >= BUFSIZ ||
         strlcat(cmd, "' -c 'cd \"", BUFSIZ) >= BUFSIZ ||
         strlcat(cmd, p + 1,         BUFSIZ) >= BUFSIZ ||
         strlcat(cmd, "\"; ",        BUFSIZ) >= BUFSIZ) { E(); continue; }
     } /* smbclient doesn't cd properly if this isn't done */
     else
     { /* No subdir, so put directly */
      if(strlcat(cmd, dir,           BUFSIZ) >= BUFSIZ ||
         strlcat(cmd, "' -c '",      BUFSIZ) >= BUFSIZ) { E(); continue; }
     }

     if(strlcat(cmd, "put \"",       BUFSIZ) >= BUFSIZ ||
        strlcat(cmd, dst,            BUFSIZ) >= BUFSIZ ||
        strlcat(cmd, "\" \"",        BUFSIZ) >= BUFSIZ ||
        strlcat(cmd, z,              BUFSIZ) >= BUFSIZ ||
        strlcat(cmd, "\"; dir \"",   BUFSIZ) >= BUFSIZ ||
        strlcat(cmd, z,              BUFSIZ) >= BUFSIZ ||
        strlcat(cmd, "\"' 2>&1",     BUFSIZ) >= BUFSIZ) { E(); continue; }

     fprintf(log, "%s\n", cmd);

     if((goodfile = popen(cmd, "r"))) /* Run the SMB transfer */
     {
      while(fgets(cmd, BUFSIZ, goodfile)) printf("%s", cmd);
      pclose(goodfile);
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

/*

Server configuration for \\remotesmbhost.someweirddomain.com\share\subdir\targetdir:

[server] cd apache/cgi-bin
[server] ln smbgw.cgi remotesmbhost.cgi              # Each server needs a separate copy/link of the program
[server] grep search /etc/resolv.conf                # If smb server not in DNS domain, add a search, maybe /etc/hosts
search someweirddomain.com
[server] cat /usr/local/etc/allowed_dirs.txt         # Share with subdir - exact match w/case, **NO BACKSLASHES**
/share/subdir/targetdir
[server] cat /usr/local/etc/.remotesmbhost.auth      # The auth file format for "smbclient -A" - one for each server
username=NTaccount
password=NTpassword
domain=NT_IS_WONDERFUL
[server] nslookup remotesmbhost.someweirddomain.com  # then "smbclient -L remotesmbhost -A..." (confirm credentials)
Name:    remotesmbhost.someweirddomain.com
Address: 1.2.3.4

# Tight access control should rely on stunnel - either tcpwrapper settings and/or a validate=4 of the RSA key
# stunnel can directly launch inetd-style services - Apache or Busybox should work in this configuration



Client usage examples:

[client] curl -F dir=/share/subdir/targetdir -F blah=@your.file -F blah=another.file http://webserver.com/remotesmbhost.cgi
/share/subdir/targetdir
b9087b71faee72d6d63da2c1fe5a252889473f80582082567d21d56d6e148c25   your.file
Domain=[NT_IS_WONDERFUL] OS=[] Server=[]
putting file /home/httpd/smbgw/remotesmbhost-your.file as \share\subdir\targetdir\your.file (886.7 kb/s) (average 886.7 kb/s)
  your.file                           A 32348970  Wed Jun  7 12:49:17 2017

                256000 blocks of size 4096. 227238 blocks available
178acdd84f47bcd66d30233f704f18732bfecf85b5d10737d5aa4ea7d167a7af   another.file
Domain=[NT_IS_WONDERFUL] OS=[] Server=[]
putting file /home/httpd/smbgw/remotesmbhost-another.file as \share\subdir\targetdir\another.file (142.9 kb/s) (average 142.9 kb/s)
  another.file                        A     1610  Wed Jun  7 12:49:57 2017

                256000 blocks of size 4096. 219341 blocks available


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


[client] perl_upload.pl your.file /share/subdir/targetdir http://webserver.com/remotesmbhost.cgi
200 OK
Successful transfer.
/share/subdir/targetdir
b9087b71faee72d6d63da2c1fe5a252889473f80582082567d21d56d6e148c25   your.file
Domain=[NT_IS_WONDERFUL] OS=[] Server=[]
putting file /home/httpd/smbgw/remotesmbhost-your.file as \share\subdir\targetdir\your.file (886.7 kb/s) (average 886.7 kb/s)
  your.file                           A 32348970  Wed Jun  7 12:49:17 2017

                256000 blocks of size 4096. 219341 blocks available
*/
