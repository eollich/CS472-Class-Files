#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "http.h"
#include <ctype.h>

//---------------------------------------------------------------------------------
// TODO:  Documentation
//
// Note that this module includes a number of helper functions to support this
// assignment.  YOU DO NOT NEED TO MODIFY ANY OF THIS CODE.  What you need to do
// is to appropriately document the socket_connect(), get_http_header_len(), and
// get_http_content_len() functions.
//
// NOTE:  I am not looking for a line-by-line set of comments.  I am looking for
//        a comment block at the top of each function that clearly highlights
//        you understanding about how the function works and that you researched
//        the function calls that I used.  You may (and likely should) add
//        additional comments within the function body itself highlighting key
//        aspects of what is going on.
//
// There is also an optional extra credit activity at the end of this function.
// If you partake, you need to rewrite the body of this function with a more
// optimal implementation. See the directions for this if you want to take on
// the extra credit.
//--------------------------------------------------------------------------------

char *strcasestr(const char *s, const char *find) {
  char c, sc;
  size_t len;

  if ((c = *find++) != 0) {
    c = tolower((unsigned char)c);
    len = strlen(find);
    do {
      do {
        if ((sc = *s++) == 0)
          return (NULL);
      } while ((char)tolower((unsigned char)sc) != c);
    } while (strncasecmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

char *strnstr(const char *s, const char *find, size_t slen) {
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
        if ((sc = *s++) == '\0' || slen-- < 1)
          return (NULL);
      } while (sc != c);
      if (len > slen)
        return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

/*
 This function establishes a TCP connection to the given host and port
 Returns the socket file descriptor on success or an error code on failure


  ------------------------------Variables------------------------------
  hp: Stores the resolved DNS information of the host
  addr: A structure holding the server's address and port information
  sock: Holds the socket file descriptor if successful or an error code if not

 ------------------------------Steps------------------------------
 1) Resolves the hostname to an IP address using gethostbyname() (retrieves
    the host's DNS information, the IP address is copied into addr.sin_addr)
 2) Port number is converted to network byte order using htons() and
    assigned to addr.sin_port
 3) A socket is created with socket() call, specifying PF_INET (aka IPv4) and
    SOCK_STREAM (aka TCP)
 4) The connect() function tries to establish a connection to the server
    using the address and port information. On error returns -1, otherwise
    returns sock fd

 ------------------------------Error Handling------------------------------
 If gethostbyname() fails the error is logged with herror() and returns -2
 If socket() fails error is logged with perror() and -1 is returned
 If connect() fails the socket is closed to release resources and returns -1
*/

int socket_connect(const char *host, uint16_t port) {
  struct hostent *hp;
  struct sockaddr_in addr;
  int sock;

  if ((hp = gethostbyname(host)) == NULL) {
    herror("gethostbyname");
    return -2;
  }

  bcopy(hp->h_addr_list[0], &addr.sin_addr, hp->h_length);
  addr.sin_port = htons(port);
  addr.sin_family = AF_INET;
  sock = socket(PF_INET, SOCK_STREAM, 0);

  if (sock == -1) {
    perror("socket");
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) ==
      -1) {
    perror("connect");
    close(sock);
    return -1;
  }

  return sock;
}

/*
 This function calculates the length of the HTTP header in a buffer

 Returns the header length on success or -1 if the header terminator '\r\n\r\n'
 is not found

 -----------------------------Variables------------------------------
 end_ptr: NULL or points to the position of the header terminator
 header_len: Stores the calculated length of the header

 ------------------------------Steps------------------------------
 1) Searches for the end of the HTTP header (header terminator)
    '\r\n\r\n' using strnstr()
    (strnstr scans the buffer for the header terminator start location)
    will result in end_ptr pointing to the location of the header's end in the
    buffer due to adding len of HTTP_HEADER_END (4)
 2) If the terminator is found calcualte the header length as the end_ptr
    - http_buff + length of the header terminator terminator(which is 4).
    This is simply start of header to end of \r\n\r\n
 3) If terminator is not found log an error and return -1
*/
char *end_ptr;
int get_http_header_len(char *http_buff, int http_buff_len) {
  char *end_ptr;
  int header_len = 0;
  end_ptr = strnstr(http_buff, HTTP_HEADER_END, http_buff_len);

  if (end_ptr == NULL) {
    fprintf(stderr, "Could not find the end of the HTTP header\n");
    return -1;
  }

  header_len = (end_ptr - http_buff) + strlen(HTTP_HEADER_END);

  return header_len;
}

/*
 This function gets the Content-Length from the HTTP header
 Returns the content length if found or 0 if no Content-Length header is found

 ------------------------------Variables------------------------------
 next_header_line: Tracks the start of the current header line
 end_header_buff: Marks the end of the header buffer
 header_line: Stores the current header line being processed

 ------------------------------Steps------------------------------
 1) Iterates through each line of the HTTP header
    Uses sscanf() to copy each header line into header_line (splits lines
      by finding \r\n)
 2) Searches for the Content-Length header using strcasestr()
    If found, locates the colon HTTP_HEADER_DELIM (':') with strchr() to
      separate the header name and value
    Extracts the value part of the header and converts it to an integer
      using atoi()
 3) Returns the content length if found or 0 if the header is not present


 */
int get_http_content_len(char *http_buff, int http_header_len) {
  char header_line[MAX_HEADER_LINE];

  char *next_header_line = http_buff;
  char *end_header_buff = http_buff + http_header_len;

  while (next_header_line < end_header_buff) {
    bzero(header_line, sizeof(header_line));
    sscanf(next_header_line, "%[^\r\n]s", header_line);

    char *isCLHeader2 = strcasecmp(header_line, CL_HEADER);
    char *isCLHeader = strcasestr(header_line, CL_HEADER);
    if (isCLHeader != NULL) {
      char *header_value_start = strchr(header_line, HTTP_HEADER_DELIM);
      if (header_value_start != NULL) {
        char *header_value = header_value_start + 1;
        int content_len = atoi(header_value);
        return content_len;
      }
    }
    next_header_line += strlen(header_line) + strlen(HTTP_HEADER_EOL);
  }
  fprintf(stderr, "Did not find content length\n");
  return 0;
}

// This function just prints the header, it might be helpful for your debugging
// You dont need to document this or do anything with it, its self explanitory.
// :-)
void print_header(char *http_buff, int http_header_len) {
  fprintf(stdout, "%.*s\n", http_header_len, http_buff);
}

// finds first occurence of single or double carriage return in a string
// returns index of start of carriage return if found, if not returns -1
// if a carriage return is found, it will also set the value of mult ptr to
// 1 or 2 depending on if it found a single cr or double \r\n vs \r\n\return
int findCarriageReturn(char *buff, int buff_len, int *mult) {
  for (int i = 0; i < buff_len; i++) {
    if (buff[i] == '\r' && buff[i + 1] == '\n') {
      if (i + 3 < buff_len && buff[i + 2] == '\r' && buff[i + 3] == '\n') {
        *mult = 2;
        return i;
      }
      *mult = 1;
      return i;
    }
  }
  *mult = 0;
  return -1;
}

//--------------------------------------------------------------------------------------
// EXTRA CREDIT - 10 pts - READ BELOW
//
// Implement a function that processes the header in one pass to figure out BOTH
// the header length and the content length.  I provided an implementation below
// just to highlight what I DONT WANT, in that we are making 2 passes over the
// buffer to determine the header and content length.
//
// To get extra credit, you must process the buffer ONCE getting both the header
// and content length.  Note that you are also free to change the function
// signature, or use the one I have that is passing both of the values back via
// pointers.  If you change the interface dont forget to change the signature in
// the http.h header file :-).  You also need to update client-ka.c to use this
// function to get full extra credit.
//--------------------------------------------------------------------------------------
int process_http_header(char *http_buff, int http_buff_len, int *header_len,
                        int *content_len) {

  *header_len = -1;
  *content_len = 0;
  int num_cr;
  int res;

  char *cur = http_buff;
  char cl_buff[MAX_HEADER_LINE];
  char *buff_end = http_buff + http_buff_len;

  while (cur < buff_end) {
    res = findCarriageReturn(cur, buff_end - cur, &num_cr);
    if (num_cr < 1) {
      return -1;
    }

    int line_length = res + (num_cr * 2);

    bzero(cl_buff, sizeof(cl_buff));
    strncpy(cl_buff, cur, line_length - (2 * num_cr));
    cl_buff[line_length - (num_cr * 2)] = '\0';

    char *isCLHeader = strcasestr(cl_buff, CL_HEADER);
    if (isCLHeader != NULL) {
      char *header_value_start = strchr(isCLHeader, HTTP_HEADER_DELIM);
      if (header_value_start != NULL) {
        *content_len = atoi(header_value_start + 1);
      }
    }

    cur += line_length;

    if (num_cr == 2) {
      *header_len = (cur - http_buff);
      break;
    }
  }
  if (*header_len < 0 || *content_len < 0) {
    *header_len = 0;
    *content_len = 0;
    return -1;
  }
  return 0;
}
