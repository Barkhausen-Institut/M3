#include <m3/stream/Standard.h>
#include <m3/vfs/File.h>
#include <m3/vfs/VFS.h>

using namespace m3;

int main(int argc, char **argv) {
    if(argc != 2) {
        eprintln("Usage: {} <file>"_cf, argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    auto file = VFS::open(filename, FILE_R);

    println("Contents of {}:"_cf, filename);
    char buffer[512];
    size_t count;
    while((count = file->read(buffer, sizeof(buffer)).unwrap()) > 0)
        cout.write_all(buffer, count);

    return 0;
}
