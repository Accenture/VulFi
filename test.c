#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
  char *buffer;
  char tmp_buffer[100] = "OLALA LOL";
  if (atoi(argv[1]) == 1) {
    buffer = "DEFINETELY ONE";
  } else {
    buffer = "NOT ONE";
  }
  strcat(tmp_buffer,buffer);
  printf("GOT %s LEN: %ld ORIG: %s\n",tmp_buffer,strlen(buffer),argv[1]);
  return 0;
}
