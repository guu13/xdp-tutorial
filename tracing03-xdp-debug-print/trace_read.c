/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/common_defines.h"
#include <netinet/ether.h>
#include <arpa/inet.h>

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

static void print_ether_addr(const char *type, char *str)
{
	__u64 addr;

	if (1 != sscanf(str, "%llu", &addr))
		return;

	printf("%s: %s ", type, ether_ntoa((struct ether_addr *) &addr));
}

static void print_ip_addr(const char *type, char *str)
{
	__u32 ip_addr;

	if (1 != sscanf(str, "%u", &ip_addr))
		return;

    struct in_addr _in_addr = {ip_addr};
	printf("%s: %s ", type, inet_ntoa(_in_addr));
} 


// static void print_ip6_addr(const char *type, char *str)
// {
// 	struct in6_addr _in6_addr;
// 	_in6_addr.__in6_u

// 	inet_ntop()
// } 

char * printMac(char *tok, char *saveptr)
{
	unsigned int proto;

	if (!strncmp(tok, "srcMAC:", 7)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("srcMAC", tok);
	}

	if (!strncmp(tok, "dstMAC:", 7)) {
		tok = strtok_r(NULL, " ", &saveptr);
		print_ether_addr("dstMAC", tok);
	}

	if (!strncmp(tok, "ethProto:", 8)) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (1 == sscanf(tok, "%u", &proto))
			printf("ethProto: %u", proto);
	}

	return tok;
}

char * printIP4(char *tok, char *saveptr)
{
	unsigned int ip_type;

	if (!strncmp(tok, "srcIP4:", 6)) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (1 == sscanf(tok, "%u", &ip_type))
			printf("srcIP4: %u", ip_type);
	}

	if (!strncmp(tok, "desIP4:", 6)) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (1 == sscanf(tok, "%u", &ip_type))
			printf("desIP4: %u", ip_type);
	}

	if (!strncmp(tok, "ipType:", 8)) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (1 == sscanf(tok, "%u", &ip_type))
			printf("ipType: %u", ip_type);
	}

	return tok;
}

void printIP6(char *tok, char *saveptr)
{

}



int main(int argc, char **argv)
{
	FILE *stream;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;

	stream = fopen(TRACEFS_PIPE, "r");
	if (stream == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}


	while ((nread = getline(&line, &len, stream)) != -1) {
		char *tok, *saveptr;
		unsigned int tmp;

		tok = strtok_r(line, " ", &saveptr);

		while (tok) {
			if (!strncmp(tok, "src:", 4)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("src", tok);
			}

			if (!strncmp(tok, "dst:", 4)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("dst", tok);
			}

			if (!strncmp(tok, "proto:", 5)) {
				tok = strtok_r(NULL, " ", &saveptr);
				if (1 == sscanf(tok, "%u", &tmp))
					printf("proto: %u", tmp);
			}

			// 
			if (!strncmp(tok, "srcMAC:", 7)) {
						tok = strtok_r(NULL, " ", &saveptr);
						print_ether_addr("srcMAC", tok);
			}

			if (!strncmp(tok, "dstMAC:", 7)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("dstMAC", tok);
			}

			if (!strncmp(tok, "ethProto:", 8)) {
				tok = strtok_r(NULL, " ", &saveptr);
				if (1 == sscanf(tok, "%u", &tmp))
					printf("ethProto: %X", tmp);
			}

			//
			if (!strncmp(tok, "srcIP4:", 6)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ip_addr("srcIP4", tok);
			}

			if (!strncmp(tok, "desIP4:", 6)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ip_addr("desIP4", tok);
			}

			//
			//__u64 tmp_u64 ;
			//char tmp_c[25] = {};
			if (!strncmp(tok, "srcIP6:", 6)) {
				tok = strtok_r(NULL, " ", &saveptr);
					printf("srcIP6: %s ", tok);
			}

			if (!strncmp(tok, "desIP6:", 6)) {
				tok = strtok_r(NULL, " ", &saveptr);
				//if (1 == sscanf(tok, "%s", tmp_c))
					printf("desIP6: %s ", tok);
			}

			//
			if (!strncmp(tok, "srcUdpPort:", 9)) {
				tok = strtok_r(NULL, " ", &saveptr);
				tmp = 0 ;
				if (1 == sscanf(tok, "%u", &tmp))
					printf("srcUdpPort: %u ", tmp);
			}

			if (!strncmp(tok, "dstUdpPort:", 8)) {
				tok = strtok_r(NULL, " ", &saveptr);
				tmp = 0;
				if (1 == sscanf(tok, "%u", &tmp))
					printf("dstUdpPort: %u ", tmp);
			}

			if (!strncmp(tok, "srcTcpPort:", 9)) {
				tok = strtok_r(NULL, " ", &saveptr);
				tmp = 0 ;
				if (1 == sscanf(tok, "%u", &tmp))
					printf("srcTcpPort: %u ", tmp);
			}

			if (!strncmp(tok, "dstTcpPort:", 8)) {
				tok = strtok_r(NULL, " ", &saveptr);
				tmp = 0;
				if (1 == sscanf(tok, "%u", &tmp))
					printf("dstTcpPort: %u ", tmp);
			}

			if (!strncmp(tok, "ipProto:", 8)) {
				tok = strtok_r(NULL, " ", &saveptr);
				tmp = 0;
				if (1 == sscanf(tok, "%u", &tmp))
					printf("ipProto: %u", tmp);
			}

			if (!strncmp(tok, "otherIPProto:", 8)) {
				tok = strtok_r(NULL, " ", &saveptr);
				tmp = 0;
				if (1 == sscanf(tok, "%u", &tmp))
					printf("otherIPProto: %X", tmp);
			}

			tok = strtok_r(NULL, " ", &saveptr);
		}

		printf("\n");
	}

	free(line);
	fclose(stream);
	return EXIT_OK;
}
