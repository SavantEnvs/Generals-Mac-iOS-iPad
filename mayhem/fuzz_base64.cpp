// Base64_Decode on arbitrary text into an exactly-sized buffer, then Base64_Encode of the result.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > (1u << 20))
		return -1;

	char *src = (char *)malloc(size);
	memcpy(src, data, size);

	size_t decCap = size;
	unsigned char *dec = (unsigned char *)malloc(decCap);
	int n = Base64_Decode(src, (int)size, dec, (int)decCap);

	if (n > 0)
	{
		size_t encCap = ((size_t)n + 2) / 3 * 4 + 1;
		char *enc = (char *)malloc(encCap);
		Base64_Encode(dec, n, enc, (int)encCap);
		free(enc);
	}

	free(dec);
	free(src);
	return 0;
}
