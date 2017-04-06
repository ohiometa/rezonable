/*
 * Open UDP port 53 on file descriptor 3, then exec a nonprivileged script.
 *
 * Intentionally super-short to permit quick security auditing,
 * this file needs to be either setcap 'cap_net_bind_service=+ep'
 * or setuid root, the former being more conserative.
 *
 * Darkest aspect: bind() will fail if traced with strace(1)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[], char *env[])
{
	int s;
	struct sockaddr_in a = { 0 };

	a.sin_family = AF_INET;
	a.sin_addr.s_addr = INADDR_ANY;
	a.sin_port = htons(53);

	do {
		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) break;
		if (bind(s, (struct sockaddr *) &a, sizeof a)) break;
		setgid(getgid());
		setuid(getuid());
		if (dup2(s, 3) < 0) break;
		execve(argv[1], argv+1, env);
	} while (0);

	return 1;		// startup failed
}
