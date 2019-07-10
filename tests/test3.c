
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>

void test (int itest) {
  switch (itest) {
    case (1): {
      printf("mount\n");
      mount("foo", "bar", 0, NULL);
    } break;
    case (2): {
      printf("unmount\n");
      unmount("foo", 0);
    } break;
    case (3): {
      printf("nmount\n");
      nmount(NULL, 0, 0);
    } break;
    case (0): {
    } break;
    default: break;
  }
}

int main (int argc, char * *argv) {
  for (int itest = 1; itest < 5; itest++) {
    if (!fork()) {
      test(itest); exit(0);
    }
  }
  return 0;
}
