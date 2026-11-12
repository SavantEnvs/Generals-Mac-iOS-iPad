// Serves one in-memory buffer through the engine's FileFactoryClass, so Targa (which reads through
// _TheFileFactory) can parse fuzzer / test input without touching the filesystem.
#pragma once

#include "always.h"
#include "ffactory.h"
#include "RAMFILE.h"

class MemoryFileFactory : public FileFactoryClass
{
public:
	MemoryFileFactory(void *buffer, int length) : m_buffer(buffer), m_length(length) {}
	FileClass *Get_File(char const *) override { return new RAMFileClass(m_buffer, m_length); }
	void Return_File(FileClass *file) override { delete file; }

private:
	void *m_buffer;
	int m_length;
};
