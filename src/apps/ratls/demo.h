/*

This file contains interface for classes needed to demo RATLS. It's purpose is
to send the status of client and server to the demo dashboard and to receive
simple commands from the user who controls the demo.

*/

// ************************************************************************************************

#pragma once

#include <string>
#include <vector>

// ************************************************************************************************

namespace BI {

// ************************************************************************************************

typedef enum {
	Idle = 0,
	Ok = 1,
	Error = 2,
	Connecting = 3,
	Active = 4,
	Restarting = 5,
	Unknown = 6
} DemoStatus;

// ************************************************************************************************

class DemoBase {
public:
	void parseCommandLine(int argc, char const *argv[]);

	bool clientIsDemo() { return demoClient; }
	bool serverIsDemo() { return demoServer; }

protected:
	bool demoClient;
	bool demoServer;
};

class DemoClient : public DemoBase {
public:
	DemoClient() {
		verbose = false;
		init("", 0);
	}

	void init(std::string dashBoardHost, int dashBoardPort);
	void reset();
	void setVerbose(bool v) { verbose = v; }

	void setConnectionStatus(DemoStatus s);
	void setTlsStatus(DemoStatus s, std::string cert);
	void setAttestationStatus(DemoStatus s, std::string pubKey, std::string hash, std::string info);

protected:
	char const *reportAsText();
	void printReportVerbose();

	DemoStatus connectionStatus;
	DemoStatus tlsStatus;
	DemoStatus attestationStatus;
	std::string tlsCertificate;
	std::string attestationPubKey;
	std::string attestationHash;
	std::string attestationInfo;

	std::string text;
	bool verbose;

	int fd;
};

// ************************************************************************************************

class DemoServer : public DemoBase { };

// ************************************************************************************************

extern DemoClient demoClient;
extern DemoServer demoServer;

// ************************************************************************************************

} // namespace BI
