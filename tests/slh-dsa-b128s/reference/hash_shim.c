/* Independent checker only; links the hash-pinned upstream portable C backend. */
#include "blake3.h"
void slh_reference_xof(const unsigned char *in, size_t in_len, unsigned char *out,
                  size_t out_len, int mode, const unsigned char *key) {
  blake3_hasher h;
  if (mode == 1) blake3_hasher_init_keyed(&h, key);
  else if (mode == 2) blake3_hasher_init_derive_key(&h, (const char *)key);
  else blake3_hasher_init(&h);
  blake3_hasher_update(&h, in, in_len);
  blake3_hasher_finalize(&h, out, out_len);
}
