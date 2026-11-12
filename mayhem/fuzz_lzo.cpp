// Mirrors lzopipe.cpp / lzostraw.cpp: a block is LZO1X-compressed (lzo1x_1_compress, worst-case
// output buffer LZO_BUFFER_SIZE) and decompressed back into a buffer of the block's size, and the
// round trip must reproduce the block. The input is the plaintext block. (lzo1x_decompress has no
// bounds checks at all, so feeding it raw bytes crashes on nearly every input and cannot fuzz.)
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "lzo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > (1u << 20))
		return -1;

	std::vector<unsigned char> out(LZO_BUFFER_SIZE(size));
	std::vector<unsigned char> wrk(LZO1X_MEM_COMPRESS + 16);
	lzo_uint olen = out.size();
	if (lzo1x_1_compress(data, size, out.data(), &olen, wrk.data()) != LZO_E_OK)
		return 0;
	if (olen > out.size())
		abort();

	std::vector<unsigned char> back(size);
	lzo_uint blen = back.size();
	int r = lzo1x_decompress(out.data(), olen, back.data(), &blen, nullptr);
	if (r != LZO_E_OK || blen != size || memcmp(back.data(), data, size) != 0)
		abort();
	return 0;
}
