#define ACL_ALLOW	1
#define ACL_DENY	0

int acl_allow_add (char *);
int acl_check (struct sockaddr *);
