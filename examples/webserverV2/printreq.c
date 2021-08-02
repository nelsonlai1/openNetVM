#include "simple-web-server.c"

static inline int user_init_func(int argc __attribute__ ((unused)), char *argv[]
				 __attribute__ ((unused)))
{
	printf("user_init_func: argc=%d\n", argc);
	return 0;
}

//#define DEBUGHTTP

char test_data[] =
    "0023456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0223456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0323456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0423456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0523456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0623456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0723456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0823456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "0923456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1023456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1223456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1323456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1423456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1523456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1623456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1723456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1823456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "1923456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2023456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2223456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2323456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2423456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2523456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2623456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2723456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2823456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789<br>"
    "2923456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

static inline int process_http(int ip_version __attribute__ ((unused)),
			       void *iph __attribute__ ((unused)), struct rte_tcp_hdr *tcph
			       __attribute__ ((unused)), unsigned char *http_req
			       __attribute__ ((unused)), int req_len
			       __attribute__ ((unused)), unsigned char *http_resp, int *resp_len,
			       int *resp_in_req)
{
#ifdef DEBUGHTTP
	printf("http req payload is: ");
	int i;
	for (i = 0; i < req_len; i++) {
		unsigned char c = *(http_req + i);
		if ((c > 31) && (c < 127))
			printf("%c", c);
		else
			printf(".");
	}
	printf("\n");
	printf("max-http-response len: %d\n", *resp_len);
#endif
	http_req[req_len] = 0;
	*resp_in_req = 0;
	int ret = snprintf((char *)http_resp, *resp_len, "%s%s%s%s%s",
			   "HTTP/1.1 200 OK\r\n"
			   "Server: dpdk-simple-web-server by james@ustc.edu.cn\r\n"
			   "Content-Type: text/html; charset=iso-8859-1\r\n"
			   "Cache-Control: no-cache, must-revalidate\r\n" "Pragma: no-cache\r\n"
			   "Connection: close\r\n" "\r\n<html>" "Your request is: <pre>",
			   http_req,
			   "</pre>" "3000 bytes: test data:<p>",
			   test_data,
			   "</html>");
	if (ret < *resp_len)
		*resp_len = ret;
#ifdef DEBUGHTTP
	printf("resp_len %d\n", *resp_len);
#endif
	return 1;
}
