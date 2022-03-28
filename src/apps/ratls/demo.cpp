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

asynchronous report sent to dashboard:

	status:{idle,error,connecting,active,restarting}
	status-tls:{ok,error}
	status-attest:{ok,error,unknown}
	peer-tls-cert:<certificate info, e.g., O, OU, ...>
	peer-attest-pubkey:<fingerprint of known public key that verified the attestation report>
	peer-attest-hash:<SHA1 or SHA256 hash of reported software>
	peer-attest-info:<some string describing the reported software>

example reports for client:

	status:idle
	status-tls:idle
	status-attest:idle
	peer-tls-cert:
	peer-attest-pubkey:
	peer-attest-hash:
	peer-attest-info:

	status:connecting
	status-tls:idle
	status-attest:idle
	peer-tls-cert:
	peer-attest-pubkey:
	peer-attest-hash:
	peer-attest-info:

	status:connecting
	status-tls:idle
	status-attest:ok
	peer-tls-cert:
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo

	status:connecting
	status-tls:ok
	status-attest:ok
	peer-tls-cert:Barkhausen Institute
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo

	status:ok
	status-tls:ok
	status-attest:ok
	peer-tls-cert:Barkhausen Institute
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo

	status:active
	status-tls:ok
	status-attest:ok
	peer-tls-cert:Barkhausen Institute
	peer-attest-pubkey:01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06
	peer-attest-hash:b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6
	peer-attest-info:RATLS Demo

	status:idle
	status-tls:idle
	status-attest:idle
	peer-tls-cert:
	peer-attest-pubkey:
	peer-attest-hash:
	peer-attest-info:

*/

#include <cstdio>

#include "demo.h"
#include "errorhelper.h"

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

// ************************************************************************************************

void DemoBase::parseCommandLine(int argc, char const *argv[]) {

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

void DemoClient::init(std::string dashBoardHost, int dashBoardPort) {

	// FIXME: open socket, etc.

	fd = -1;
	reset();
}


void DemoClient::reset() {

	connectionStatus = DemoStatus::Idle;
	tlsStatus = DemoStatus::Idle;
	attestationStatus = DemoStatus::Idle;
	tlsCertificate = "";
	attestationPubKey = "";
	attestationHash = "";
	attestationInfo = "";

	printReportVerbose();
}


void DemoClient::setConnectionStatus(DemoStatus s) {

	connectionStatus = s;

	printReportVerbose();
}


void DemoClient::setTlsStatus(DemoStatus s, std::string cert) {

	tlsStatus = s;
	tlsCertificate = cert;

	printReportVerbose();
}


void DemoClient::setAttestationStatus(DemoStatus s, std::string pubKey, std::string hash, std::string info) {

	attestationStatus = s;
	attestationPubKey = pubKey;
	attestationHash = hash;
	attestationInfo = info;

	printReportVerbose();
}


char const *DemoClient::reportAsText() {

	try {
		text = "";
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


void DemoClient::printReportVerbose() {

	if (verbose) {
		printf("-------- BI RATLS DEMO - BEGIN --------\n");
		printf("%s", reportAsText());
		printf("--------- BI RATLS DEMO - END ---------\n");
	}
}

// ************************************************************************************************

} // namespace BI
