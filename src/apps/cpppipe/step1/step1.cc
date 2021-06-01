#include <m3/com/SendGate.h>
#include <m3/com/RecvGate.h>
#include <m3/com/GateStream.h>
#include <m3/stream/Standard.h>

using namespace m3;

int main() {
    RecvGate reply_gate = RecvGate::create(8, 6);
    reply_gate.activate();

    SendGate sgate = SendGate::create_named("chan", &reply_gate);

    int sends = 0;
    int replies = 0;
    while(replies < 64) {
        if(sends < 64 && sgate.can_send()) {
            const TCU::Message *msg;
            while((msg = reply_gate.fetch())) {
                replies++;
                reply_gate.ack_msg(msg);
            }

            send_vmsg(sgate, sends);
            sends++;
        }
        else {
            reply_gate.ack_msg(reply_gate.receive(&sgate));
            replies++;
        }
    }
    return 0;
}
