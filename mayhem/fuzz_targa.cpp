// Targa::Load over an in-memory image: header, optional 2.0 footer/extension, palette and
// uncompressed / RLE pixel data, as the texture loaders call it (image + palette allocated by Targa).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "TARGA.h"
#include "memfile.h"

extern FileFactoryClass *_TheFileFactory;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < sizeof(TGAHeader) || size > (1u << 22))
		return -1;

	// Targa sizes its image and palette buffers from the header (as signed shorts/chars) and checks
	// malloc() for failure. A sanitizer allocator aborts on an absurd request instead of returning
	// NULL, so bound the requests the way Targa::Load computes them: image = Width*Height*bytes per
	// pixel, palette = CMapLength*(CMapDepth/8).
	TGAHeader header;
	memcpy(&header, data, sizeof header);
	int64_t imageSize = (int64_t)header.Width * header.Height * TGA_BytesPerPixel(header.PixelDepth);
	int64_t paletteSize = (int64_t)header.CMapLength * (header.CMapDepth >> 3);
	const int64_t kMaxAlloc = 1 << 26;
	if (imageSize < 0 || imageSize > kMaxAlloc || (header.ColorMapType == 1 && (paletteSize < 0 || paletteSize > kMaxAlloc)))
		return -1;

	void *buf = malloc(size);
	memcpy(buf, data, size);

	MemoryFileFactory factory(buf, (int)size);
	FileFactoryClass *saved = _TheFileFactory;
	_TheFileFactory = &factory;

	{
		Targa tga;
		tga.Load("fuzz.tga", TGAF_IMAGE | TGAF_PAL, false);
	}
	{
		Targa tga;
		tga.Load("fuzz.tga", TGAF_IMAGE, true);
	}

	_TheFileFactory = saved;
	free(buf);
	return 0;
}
