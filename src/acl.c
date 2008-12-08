#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>

#include "config.h"
#include "acl.h"
#include "log.h"

typedef struct acl {
	struct acl *next;
	struct sockaddr_storage sa;
	int mask;
} acl_t;

static acl_t *acl_head = NULL;

static acl_t *acl_allow_add_list (acl_t *, struct sockaddr *, int);

int acl_allow_add (char *str)
{
	struct addrinfo hints, *res;
	char *pmask = NULL;
	int mask = -1;
	int rc;

	pmask = strchr(str, '/');
	if (pmask != NULL) {
		*pmask++ = '\0';
		mask = atoi(pmask);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rc = getaddrinfo(str, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo(): failed, %s\n",
				gai_strerror(rc));
		exit(1);
	}

	acl_head = acl_allow_add_list(acl_head, res->ai_addr, mask);

	freeaddrinfo(res);

	return 0;
}

static acl_t *acl_allow_add_list (acl_t *acl, struct sockaddr *ss, int mask)
{
	if (acl == NULL) {
		acl = malloc(sizeof(acl_t));
		if (acl == NULL) {
			logging_log(LOG_WARNING, "malloc: %s", strerror(errno));
			exit(1);
		}
		acl->next = NULL;
		memcpy(&acl->sa, ss, sizeof(struct sockaddr_storage));
		acl->mask = mask;
	} else {
		acl->next = acl_allow_add_list(acl->next, ss, mask);
	}

	return acl;
}

int acl_check (struct sockaddr *sa)
{
	struct sockaddr *acl_sa = NULL;
	struct sockaddr_in *sin = NULL, *acl_sin = NULL;
	struct sockaddr_in6 *sin6 = NULL, *acl_sin6 = NULL;
	acl_t *acl = NULL;
	int allow, i;

	if (acl_head == NULL) {
		return ACL_ALLOW;
	}

	for (acl = acl_head; acl != NULL; acl = acl->next) {

		acl_sa = (struct sockaddr *)&acl->sa;

		if (sa->sa_family != acl_sa->sa_family) {
			continue;
		}

		switch (sa->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)sa;
			acl_sin = (struct sockaddr_in *)acl_sa;

			if (acl->mask == -1) {
				acl->mask = 32;
			}

			if (acl->mask < 1 || acl->mask > 32) {
				fprintf(stderr, "Error: Bad netmask.\n");
				break;
			}

			if ((ntohl(sin->sin_addr.s_addr) >>
						(32 - acl->mask)) ==
					(ntohl(acl_sin->sin_addr.s_addr) >>
					 (32 - acl->mask))) {
				return ACL_ALLOW;
			}

			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)sa;
			acl_sin6 = (struct sockaddr_in6 *)acl_sa;

			if (acl->mask == -1) {
				acl->mask = 128;
			}

			if (acl->mask < 1 || acl->mask > 128) {
				fprintf(stderr, "Error: Bad netmask.\n");
				break;
			}

			allow = 1;

			for (i = 0; i < (acl->mask / 8); i++) {
				if (sin6->sin6_addr.s6_addr[i]
					!= acl_sin6->sin6_addr.s6_addr[i]) {
					allow = 0;
					break;
				}
			}

			if ((sin6->sin6_addr.s6_addr[i] >>
			    (8 - (acl->mask % 8))) !=
					(acl_sin6->sin6_addr.s6_addr[i] >>
					 (8 - (acl->mask % 8)))) {
				allow = 0;
			}

			if (allow) {
				return ACL_ALLOW;
			}

			break;

		default:
			logging_log(LOG_WARNING, "Unknown address family.");
			break;
		}
	}

	return ACL_DENY;
}
