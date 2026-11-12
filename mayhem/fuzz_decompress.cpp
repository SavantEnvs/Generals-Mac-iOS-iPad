// Mirrors the callers of CompressionManager::decompressData: DataChunk.cpp (map/data chunk files)
// and ConnectionManager.cpp (map transfer): size the destination from the untrusted header, then
// decompress into an exactly-sized heap buffer.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Compression.h"

static const Int kMaxUncompressed = 1 << 24;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 8 || size > (1u << 22))
		return -1;

	void *src = malloc(size);
	memcpy(src, data, size);

	int rc = 0;
	if (CompressionManager::isDataCompressed(src, (Int)size))
	{
		Int uncompLen = CompressionManager::getUncompressedSize(src, (Int)size);
		if (uncompLen < 0 || uncompLen > kMaxUncompressed)
		{
			rc = -1;
		}
		else
		{
			void *dest = malloc(uncompLen ? uncompLen : 1);
			CompressionManager::decompressData(src, (Int)size, dest, uncompLen);
			free(dest);
		}
	}
	else
	{
		rc = -1;
	}

	free(src);
	return rc;
}
