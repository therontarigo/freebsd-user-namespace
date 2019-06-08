
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <sys/socket.h>
#include <sys/mount.h>

int main (int argc, char * *argv) {
  if (argc!=2) {
    fprintf(stderr, "Usage: %s filename\n", argv[0]);
    return 1;
  }
  const char *path = argv[1];
  printf("Opening with fopen\n");
  FILE *stf = fopen(path, "r");
  if (stf) fclose(stf);
  printf("Opening with open\n");
  int fd = open(path, O_RDONLY);
  if (fd!=-1) close(fd);
  printf("mknod\n");
  mknod(path, 0, 0);
  printf("mknodat\n");
  mknodat(AT_FDCWD, path, 0, 0);
  printf("Chown with chown\n");
  chown(path, 0, 0);
  printf("Chown with lchown\n");
  lchown(path, 0, 0);
  printf("Chown with fchownat\n");
  fchownat(AT_FDCWD, path, 0, 0, 0);
  printf("access\n");
  access(path, 0);
  printf("eaccess\n");
  eaccess(path, 0);
  printf("faccessat\n");
  faccessat(AT_FDCWD, path, 0, 0);
  printf("chflags\n");
  chflags(path, 0);
  printf("lchflags\n");
  lchflags(path, 0);
  printf("chflagsat\n");
  chflagsat(AT_FDCWD, path, 0, 0);
  printf("ktrace\n");
  ktrace(path, KTROP_CLEAR, 0, 0);
  printf("acct\n");
  acct(path); acct(NULL);
  printf("revoke\n");
  revoke(path);
  printf("symlink\n");
  symlink("bar", path);
  printf("symlinkat\n");
  symlinkat("bar", AT_FDCWD, path);
  printf("readlink\n");
  readlink(path, NULL, 0);
  printf("readlinkat\n");
  readlinkat(AT_FDCWD, path, NULL, 0);
  printf("sendto\n");
  sendto(0, NULL, 0, 0, NULL, 0);

  printf("statfs\n");
  statfs(path, NULL);
  return 0;
}
