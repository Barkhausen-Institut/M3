#include <m3/com/RecvGate.h>
#include <m3/com/GateStream.h>
#include <m3/stream/Standard.h>

using namespace m3;

int main() {
    RecvGate rgate = RecvGate::create_named("chan");
    rgate.activate();

    while(true) {
        GateIStream is = receive_msg(rgate);
        int i;
        is >> i;
        cout << "got message " << i << "\n";
        reply_vmsg(is, 0);
    }
    return 0;
}
