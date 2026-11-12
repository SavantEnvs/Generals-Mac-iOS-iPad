// The two factory globals ffactory.cpp would define; ffactory.cpp itself drags in the whole
// raw-file / string / mutex stack, which Targa does not need once reads go through memfile.h.
#include "memfile.h"

FileFactoryClass *_TheFileFactory = nullptr;
RawFileFactoryClass *_TheWritingFileFactory = nullptr;

// Targa's write paths name this factory; the harnesses and probe never write.
RawFileClass *RawFileFactoryClass::Get_File(char const *) { return nullptr; }
