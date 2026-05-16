#include <cstdio>
#include <cstring>
#include <sodium/crypto_pwhash.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: gen_hash <password>\n");
    return 1;
  }

  char hash[crypto_pwhash_STRBYTES];
  if (crypto_pwhash_str(hash, argv[1], std::strlen(argv[1]),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
    std::fprintf(stderr, "out of memory\n");
    return 1;
  }

  std::printf("%s", hash);
  return 0;
}
