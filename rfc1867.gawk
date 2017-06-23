#!/bin/gawk -f

BEGIN { # RFC-1867 file transfer - reads all files into memory at once.

if(ARGC < 2) { print "usage rfc1867.gawk URL file1 file2 file3..."; exit }

srand(systime() + PROCINFO["pid"])

HOST = ARGV[1]

sub(/http:[/][/]/, "", HOST)

PAGE = substr(HOST, match(HOST, "/"))

sub(/[/].*$/, "", HOST)

if(i = match(HOST, ":"))
{
 PORT = substr(HOST, i + 1)
 HOST = substr(HOST, 0, i - 1)
} else PORT = 80

http = "/inet/tcp/0/" HOST "/" PORT # GAWK socket syntax

BOUNDARY = "------------------------------"

for(i = 0; i < 12; i++)             # We don't need high-quality random numbers.
{
 t = rand() * 16
 BOUNDARY = BOUNDARY (t > 10 ? sprintf("%c", 87 + t) : int(t))
}

CONTENT_LENGTH = length(BOUNDARY)

#MIME = "Content-Type: text/plain\r\n\r\n"
MIME = "Content-Type: application/octet-stream\r\n\r\n"

RS = "\x01" #Unsafe for binary files. Check with: grep -obUaP "\x01" file.txt

for(i = 2; i < ARGC; i++)
{
 getline FILE[i] < ARGV[i]          # Read the whole file. Hope it isn't big.
 close(ARGV[i])                     # This only works if RS is not in file.
 DISP[i] = "Content-Disposition: form-data; name=\"F" i "\"; filename=\"" \
           ARGV[i] "\"\r\n"
 CONTENT_LENGTH += length(DISP[i]) + length(MIME) + length(FILE[i]) + 4 + \
                   length(BOUNDARY) # It sure would be nice to have stat().
}

CONTENT_LENGTH += 4

ORS="\r\n"

print "POST " PAGE " HTTP/1.1"           |& http;
print "User-Agent: rfc1867.gawk"         |& http;
print "Host: " HOST ":" PORT             |& http;
print "Accept: */*"                      |& http;
print "Content-Length: " CONTENT_LENGTH  |& http;
#print "Expect: 100-continue" |& http;            # No prior send confirmation.
print "Content-Type: multipart/form-data; boundary=" substr(BOUNDARY, 3) \
      "\r\n\r\n" BOUNDARY                |& http; # Header boundry is 2 short.

for(i = 2; i < ARGC; i++) printf "%s", DISP[i] MIME FILE[i] "\r\n" BOUNDARY \
 (i == ARGC - 1 ? "--" : "") "\r\n"      |& http; #More dashes on last boundary.

while(http |& getline x) print x
}

#nc -l 80 & curl -F file=@/etc/shells http://localhost:80/xmit.cgi #show session
