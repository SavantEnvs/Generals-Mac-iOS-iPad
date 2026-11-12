// Known-answer probe for mayhem/test.sh. Built with the project's normal flags (no sanitizers) and
// linked dynamically; each subcommand prints values that test.sh compares against constants.
//   kat decompress <file>   decompress a compressed blob exactly as DataChunk.cpp does
//   kat roundtrip           compress + decompress a fixed buffer with every codec
//   kat base64              encode / decode fixed strings
//   kat lzo                 LZO1X compress + decompress a fixed buffer
//   kat targa               load fixed uncompressed and RLE Targa images
//   kat gen <dir>           (re)generate the fuzz_decompress / fuzz_lzo / fuzz_targa / fuzz_base64 seeds
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "Compression.h"
#include "TARGA.h"
#include "base64.h"
#include "lzo.h"
#include "memfile.h"

extern FileFactoryClass *_TheFileFactory;

static uint32_t fnv(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	uint32_t h = 2166136261u;
	for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 16777619u; }
	return h;
}

static std::vector<uint8_t> plaintext(size_t n)
{
	std::vector<uint8_t> v(n);
	uint32_t s = 12345;
	for (size_t i = 0; i < n; ++i)
	{
		s = s * 1103515245u + 12345u;
		v[i] = (i % 64 < 40) ? (uint8_t)("GENERALS ZERO HOUR "[i % 19]) : (uint8_t)(s >> 16);
	}
	return v;
}

static std::vector<uint8_t> readFile(const char *path)
{
	std::vector<uint8_t> v;
	FILE *f = fopen(path, "rb");
	if (!f) return v;
	uint8_t buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof buf, f)) > 0) v.insert(v.end(), buf, buf + n);
	fclose(f);
	return v;
}

static void writeFile(const char *dir, const char *name, const void *p, size_t n)
{
	char path[512];
	snprintf(path, sizeof path, "%s/%s", dir, name);
	FILE *f = fopen(path, "wb");
	if (!f) { perror(path); exit(2); }
	fwrite(p, 1, n, f);
	fclose(f);
}

static int cmdDecompress(const char *path)
{
	std::vector<uint8_t> in = readFile(path);
	if (in.empty()) return 2;
	Int comp = CompressionManager::getCompressionType(in.data(), (Int)in.size());
	Int ulen = CompressionManager::getUncompressedSize(in.data(), (Int)in.size());
	std::vector<uint8_t> out(ulen > 0 ? ulen : 1);
	Int actual = CompressionManager::decompressData(in.data(), (Int)in.size(), out.data(), ulen);
	printf("type=%d usize=%d actual=%d fnv=%08x\n", (int)comp, (int)ulen, (int)actual, fnv(out.data(), actual));
	return 0;
}

static std::vector<uint8_t> compress(CompressionType t, std::vector<uint8_t> &pt)
{
	Int max = CompressionManager::getMaxCompressedSize((Int)pt.size(), t);
	std::vector<uint8_t> out(max + 64);
	Int n = CompressionManager::compressData(t, pt.data(), (Int)pt.size(), out.data(), (Int)out.size());
	out.resize(n > 0 ? n : 0);
	return out;
}

static int cmdRoundtrip()
{
	std::vector<uint8_t> pt = plaintext(4096);
	printf("plain fnv=%08x\n", fnv(pt.data(), pt.size()));
	for (int t = COMPRESSION_REFPACK; t <= COMPRESSION_MAX; ++t)
	{
		std::vector<uint8_t> c = compress((CompressionType)t, pt);
		std::vector<uint8_t> back(pt.size());
		Int n = c.empty() ? 0 : CompressionManager::decompressData(c.data(), (Int)c.size(), back.data(), (Int)back.size());
		printf("%s: compressed=%d decompressed=%d fnv=%08x\n", CompressionManager::getCompressionNameByType((CompressionType)t),
		       c.empty() ? 0 : 1, (int)n, fnv(back.data(), n));
	}
	return 0;
}

static int cmdBase64()
{
	const char *msg = "Hello, Generals!";
	char enc[64];
	memset(enc, 0, sizeof enc);
	int en = Base64_Encode(msg, (int)strlen(msg), enc, sizeof enc);
	unsigned char dec[64];
	memset(dec, 0, sizeof dec);
	int dn = Base64_Decode(enc, en, dec, sizeof dec);
	printf("enc=%s n=%d dec=%.*s n=%d\n", enc, en, dn, dec, dn);
	return 0;
}

static int cmdLzo()
{
	std::vector<uint8_t> pt = plaintext(4096);
	std::vector<uint8_t> out(LZO_BUFFER_SIZE(pt.size()));
	std::vector<uint8_t> wrk(LZO1X_MEM_COMPRESS + 16);
	lzo_uint olen = out.size();
	int r = lzo1x_1_compress(pt.data(), pt.size(), out.data(), &olen, wrk.data());
	std::vector<uint8_t> back(pt.size());
	lzo_uint blen = back.size();
	int r2 = lzo1x_decompress(out.data(), olen, back.data(), &blen, nullptr);
	printf("compress=%d decompress=%d len=%u fnv=%08x smaller=%d\n", r, r2, (unsigned)blen, fnv(back.data(), blen), olen < pt.size());
	return 0;
}

static std::vector<uint8_t> tgaHeader(uint8_t type, uint8_t desc)
{
	uint8_t h[18] = {0, 0, type, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 24, desc};
	return std::vector<uint8_t>(h, h + 18);
}

static std::vector<uint8_t> tgaRaw(uint8_t desc)
{
	std::vector<uint8_t> v = tgaHeader(2, desc);
	const uint8_t px[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	v.insert(v.end(), px, px + 12);
	return v;
}

static std::vector<uint8_t> tgaRle()
{
	std::vector<uint8_t> v = tgaHeader(10, 0);
	const uint8_t body[] = {0x81, 20, 21, 22, 0x01, 30, 31, 32, 40, 41, 42};
	v.insert(v.end(), body, body + sizeof body);
	return v;
}

static void loadTga(const char *label, std::vector<uint8_t> file, bool invert)
{
	MemoryFileFactory factory(file.data(), (int)file.size());
	FileFactoryClass *saved = _TheFileFactory;
	_TheFileFactory = &factory;
	Targa tga;
	long err = tga.Load("kat.tga", TGAF_IMAGE, invert);
	printf("%s: err=%ld w=%d h=%d depth=%d px=", label, err, (int)tga.Header.Width, (int)tga.Header.Height, (int)tga.Header.PixelDepth);
	if (err == 0 && tga.GetImage())
		for (int i = 0; i < 12; ++i) printf("%s%d", i ? "," : "", (unsigned char)tga.GetImage()[i]);
	printf("\n");
	_TheFileFactory = saved;
}

static int cmdTarga()
{
	loadTga("raw", tgaRaw(0), false);
	loadTga("raw-yflip", tgaRaw(0x20), false);
	loadTga("rle", tgaRle(), false);
	std::vector<uint8_t> bad = tgaRaw(0);
	bad[2] = 99;
	loadTga("badtype", bad, false);
	return 0;
}

static int cmdGen(const char *dir)
{
	std::vector<uint8_t> pt = plaintext(1500);
	std::vector<uint8_t> small(pt.begin(), pt.begin() + 200);
	static const char *names[] = {"", "refpack", "nox", "zlib1", "zlib2", "zlib3", "zlib4", "zlib5", "zlib6", "zlib7", "zlib8", "zlib9", "btree", "huff"};
	char name[64];
	for (int t = COMPRESSION_REFPACK; t <= COMPRESSION_MAX; ++t)
	{
		if (t != COMPRESSION_ZLIB1 && t != COMPRESSION_ZLIB5 && t != COMPRESSION_ZLIB9 && (t >= COMPRESSION_ZLIB1 && t <= COMPRESSION_ZLIB9))
			continue;
		std::vector<uint8_t> c = compress((CompressionType)t, pt);
		snprintf(name, sizeof name, "%s_text.bin", names[t]);
		writeFile(dir, name, c.data(), c.size());
		c = compress((CompressionType)t, small);
		snprintf(name, sizeof name, "%s_small.bin", names[t]);
		writeFile(dir, name, c.data(), c.size());
	}

	writeFile(dir, "lzo_text.bin", pt.data(), pt.size());   // fuzz_lzo takes the plaintext block

	std::vector<uint8_t> raw = tgaRaw(0), flipped = tgaRaw(0x20), rle = tgaRle();
	writeFile(dir, "tga_raw.bin", raw.data(), raw.size());
	writeFile(dir, "tga_yflip.bin", flipped.data(), flipped.size());
	writeFile(dir, "tga_rle.bin", rle.data(), rle.size());

	const char *b64 = "SGVsbG8sIEdlbmVyYWxzIQ==";
	writeFile(dir, "b64_hello.bin", b64, strlen(b64));
	const char *b64b = "R2VuZXJhbHMgWmVybyBIb3VyOiB0aGUgZW5naW5lIHBhcnNlcyB0aGlzLg==";
	writeFile(dir, "b64_long.bin", b64b, strlen(b64b));
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 3 && !strcmp(argv[1], "decompress")) return cmdDecompress(argv[2]);
	if (argc >= 3 && !strcmp(argv[1], "gen")) return cmdGen(argv[2]);
	if (argc >= 2 && !strcmp(argv[1], "roundtrip")) return cmdRoundtrip();
	if (argc >= 2 && !strcmp(argv[1], "base64")) return cmdBase64();
	if (argc >= 2 && !strcmp(argv[1], "lzo")) return cmdLzo();
	if (argc >= 2 && !strcmp(argv[1], "targa")) return cmdTarga();
	fprintf(stderr, "usage: kat decompress <file>|roundtrip|base64|lzo|targa|gen <dir>\n");
	return 2;
}
