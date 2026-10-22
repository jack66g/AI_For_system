/* W10-B TLS 验证探针 v2：调 http_client https_get，raw 打印 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http_client.h"

int main(int argc, char **argv)
{
	char *resp = NULL, *err = NULL;
	int rc;

	if (argc < 2) { fprintf(stderr, "usage: %s <url>\n", argv[0]); return 2; }
	https_init();
	rc = https_get(argv[1], &resp, &err);
	printf("rc=%d\n", rc);
	if (err) { printf("err=%s\n", err); free(err); }
	if (resp) {
		printf("resp_len=%zu\n", strlen(resp));
		printf("resp_head=%.300s\n", resp);
		free(resp);
	} else {
		printf("resp=NULL\n");
	}
	return rc == 0 ? 0 : 1;
}
