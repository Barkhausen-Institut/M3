/*

This file contains code for demoing RATLS. It's purpose is to send the status
of client and server to the demo dashboard and to receive simple commands from
the user who controls the demo.

server control channel:

asynchronous command received from user / dashboard controls:

	command:{restart}
	mode:{clean,corrupt,no-attest}

asynchronous report sent to dashboard:

	status:{restarting,idle}
	mode:{clean,corrupt,no-attest}


client control channel:

asynchronous command received from user / dashboard controls:

	command:{connect}
	mode:{tls-attest,tls}
	sensor-data:<numeric string value>
	ra-expectation:{error,ok} [ignored by client]

asynchronous report sent to dashboard:

	mode:{tls-attest,tls}
	status:{idle,error,connecting,active,restarting}
	status-tls:{ok,error}
	status-attest:{ok,error,unknown}
	peer-tls-cert:<certificate info, e.g., O, OU, ...>
	peer-attest-pubkey:<fingerprint of known public key that verified the attestation report>
	peer-attest-hash:<SHA1 or SHA256 hash of reported software>
	peer-attest-info:<some string describing the reported software>

example reports for client:

	mode:tls-attest
	status:idle
	status-tls:idle
	status-attest:idle
	peer-tls-cert:
	peer-attest-pubkey:
	peer-attest-hash:
	peer-attest-info:
    ===
	mode:tls-attest
	status:connecting
	status-tls:idle
	status-attest:idle
	peer-tls-cert:
	peer-attest-pubkey:
	peer-attest-hash:
	peer-attest-info:
    ===
	mode:tls-attest
	status:connecting
	status-tls:idle
	status-attest:ok
	peer-tls-cert:
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo
    ===
	mode:tls-attest
	status:connecting
	status-tls:ok
	status-attest:ok
	peer-tls-cert:Barkhausen Institute
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo
    ===
	mode:tls-attest
	status:ok
	status-tls:ok
	status-attest:ok
	peer-tls-cert:Barkhausen Institute
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo
    ===
	mode:tls-attest
	status:active
	status-tls:ok
	status-attest:ok
	peer-tls-cert:Barkhausen Institute
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo
    ===
	mode:tls-attest
	status:idle
	status-tls:idle
	status-attest:idle
	peer-tls-cert:
	peer-attest-pubkey:
	peer-attest-hash:
	peer-attest-info:

*/

#if defined(__m3__)

#include <m3/com/GateStream.h>
using namespace m3;

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#endif

#include <cstdio>

#include "demo.h"
#include "dashboard.h"
#include "errorhelper.h"

using namespace Err;

// ************************************************************************************************

namespace BI {

// ************************************************************************************************

DemoClient demoClient;
DemoServer demoServer;

// ************************************************************************************************

static std::vector<std::string> demoStatusString = {
	"idle",
	"ok",
	"error",
	"connecting",
	"active",
	"restarting",
	"unknown"
};

static std::vector<std::string> demoModeString = {
	"tls",
	"tls-attest"
};

// ************************************************************************************************

void DemoBase::parseCommandLine(int &argc, char const *argv[]) {

	for(int i = 1; i < argc; i++) {
		std::string argument = argv[i];
		if (argument == "--demo-client") {
			demoClient = true;

		} else if(argument == "--demo-server") {
			demoServer = true;

		} else {
			continue;
		}

        // remove recognized commandline arguments to simplify argument handling
        // in calling program's main() function
        for (int j = i; j+1 < argc; j++)
            argv[j] = argv[j+1];
        argc--;
	}
}

// ************************************************************************************************

void DemoClient::init() {

	if (!clientIsDemo())
		return;

#if ! defined(__m3__)
	commandPipeFd = chksys(open(RATLS_DASHBOARD_CONNECTOR_COMMAND_FIFO, O_RDONLY),
	                       "open dashboard command fifo");
	reportPipeFd = chksys(open(RATLS_DASHBOARD_CONNECTOR_REPORT_FIFO, O_WRONLY),
	                      "open dashboard report fifo");
#endif

	reset(DemoReport::NoSend);
}


void DemoClient::reset(DemoReport sendMode) {

	if (!clientIsDemo())
		return;

	connectionStatus = DemoStatus::Idle;
	tlsStatus = DemoStatus::Idle;
	attestationStatus = DemoStatus::Idle;
	tlsCertificate = "";
	attestationPubKey = "";
	attestationHash = "";
	attestationInfo = "";
	text = "";

	if (sendMode == DemoReport::Send) {
		sendReport();
#if defined(__m3__)
		printf("Sending reset\n");
		m3::send_receive_vmsg(report, "");
		printf("Received reset ACK\n");
#else
		char const resetReport[] = ""; 
		size_t resetSize = strlen(resetReport) + 1; // "" + null byte
		chksys(write(reportPipeFd, &resetSize, sizeof(resetSize)), "write reset report size");
		chksys(write(reportPipeFd, &resetReport, resetSize), "write empty reset report");
#endif
	}
}


std::string DemoClient::waitForCommand() {

	if (!clientIsDemo())
		return "";

#if defined(__m3__)
	printf("Waiting for command...\n");
    m3::String cmd;
	auto is = m3::receive_msg(command);
    is >> cmd;
	m3::reply_vmsg(is, 0);
	printf("Ack'ed command\n");
	return cmd.c_str();
#else
	char cmdBuf[RATLS_DASHBOARD_MESSAGE_SIZE];
	size_t cmdSize;
	chksys(read(commandPipeFd, &cmdSize, sizeof(cmdSize)), "read command size");
	chksys(read(commandPipeFd, cmdBuf, std::min(cmdSize, sizeof(cmdBuf))), "read command");
	cmdBuf[sizeof(cmdBuf)-1] = 0;
	return std::string(cmdBuf);
#endif
}


void DemoClient::setConnectionStatus(DemoStatus s, DemoReport sendMode) {

	if (!clientIsDemo())
		return;

	connectionStatus = s;

	if (sendMode == DemoReport::Send)
		sendReport();
}


void DemoClient::setTlsStatus(DemoStatus s, std::string cert, DemoReport sendMode) {

	if (!clientIsDemo())
		return;

	tlsStatus = s;
	tlsCertificate = cert;

	if (sendMode == DemoReport::Send)
		sendReport();
}


void DemoClient::setAttestationStatus(DemoStatus s, std::string pubKey, std::string hash,
                                      std::string info, DemoReport sendMode) {
	if (!clientIsDemo())
		return;

	attestationStatus = s;
	attestationPubKey = pubKey;
	attestationHash = hash;
	attestationInfo = info;

	if (sendMode == DemoReport::Send)
		sendReport();
}


char const *DemoClient::reportAsText() {

	try {
		text = "";
		text += "mode:" + demoModeString.at(mode) + "\n";
		text += "status:" + demoStatusString.at(connectionStatus) + "\n";
		text += "status-tls:" + demoStatusString.at(tlsStatus) + "\n";
		text += "status-attest:" + demoStatusString.at(attestationStatus) + "\n";
		text += "peer-tls-cert:" + tlsCertificate + "\n";
		text += "peer-attest-pubkey:" + attestationPubKey + "\n";
		text += "peer-attest-hash:" + attestationHash + "\n";
		text += "peer-attest-info:" + attestationInfo + "\n";
	}
	catch (...) {
		text  = "";
		text += "status:error\n";
		text += "status:unknown\n";
		text += "status-tls:unknown\n";
		text += "status-attest:unknown\n";
		text += "peer-tls-cert:unknown\n";
		text += "peer-attest-pubkey:unknown\n";
		text += "peer-attest-hash:unknown\n";
		text += "peer-attest-info:unknown\n";
	}
	return text.c_str();
}


void DemoClient::sendReport() {
	const char *reportStr = reportAsText();

	if (verbose) {
		printf("%s", reportStr);
		printf("===\n");
	}

#if defined(__m3__)
	m3::send_receive_vmsg(report, m3::String(reportStr));
#else
	size_t reportSize = strlen(reportStr) + 1; // length + null byte
	chksys(write(reportPipeFd, &reportSize, sizeof(reportSize)), "write report size");
	chksys(write(reportPipeFd, reportStr, reportSize), "write report");
#endif
}

// ************************************************************************************************

} // namespace BI
