/*

This file contains interface for classes needed to demo RATLS. It's purpose is
to send the status of client and server to the demo dashboard and to receive
simple commands from the user who controls the demo.

*/

// ************************************************************************************************

#pragma once

#if defined(__m3__)
#include <m3/com/SendGate.h>
#endif

#include <unistd.h>

#include <string>
#include <vector>

// ************************************************************************************************

namespace BI {

// ************************************************************************************************

typedef enum {
	Send = 0,
	NoSend = 1
} DemoReport;

typedef enum {
	Tls = 0,
	TlsAttest = 1
} DemoMode;

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
	void parseCommandLine(int &argc, char const *argv[]);

	bool clientIsDemo()    { return demoClient; }
	bool serverIsDemo()    { return demoServer; }

    bool hasUDPIP()        { return ! udp_report_ip.empty(); }
    
    std::string getUDPIP() { return udp_report_ip; }

    // For demo clients that dump output of the serial device to a third-party
    // dashboard reachable via UDP
    std::string udp_report_ip = std::string("");

protected:
	bool demoClient;
	bool demoServer;
};

class DemoClient : public DemoBase {
public:
	DemoClient()
#if defined(__m3__)
		: report(m3::SendGate::create_named("report")),
		  command(m3::RecvGate::create_named("command")),
#else
		: commandPipeFd(-1),
		  reportPipeFd(-1),
#endif
		  verbose(false)
	{
#if defined(__m3__)
		command.activate();
#endif
	}

	~DemoClient() {
#if ! defined(__m3__)
		if (commandPipeFd >= 0)
			close(commandPipeFd);
		if (reportPipeFd >= 0)
			close(reportPipeFd);
#endif
	}

	void init();
	void reset(DemoReport sendMode = DemoReport::Send);
	void setVerbose(bool v) { verbose = v; }

	std::string waitForCommand();

	void setMode(DemoMode m) { mode = m; }
	void setConnectionStatus(DemoStatus s, DemoReport sendMode = DemoReport::Send);
	void setTlsStatus(DemoStatus s, std::string cert, DemoReport sendMode = DemoReport::Send);
	void setAttestationStatus(DemoStatus s, std::string pubKey, std::string hash,
	                          std::string info, DemoReport sendMode = DemoReport::Send);

protected:
	char const *reportAsText();
	void sendReport();

#if defined(__m3__)
	m3::SendGate report;
	m3::RecvGate command;
#else
	int commandPipeFd;
	int reportPipeFd;
#endif

	DemoMode mode;
	DemoStatus connectionStatus;
	DemoStatus tlsStatus;
	DemoStatus attestationStatus;
	std::string tlsCertificate;
	std::string attestationPubKey;
	std::string attestationHash;
	std::string attestationInfo;

	std::string text;
	bool verbose;
};

// ************************************************************************************************

class DemoServer : public DemoBase { };

// ************************************************************************************************

extern DemoClient demoClient;
extern DemoServer demoServer;

// ************************************************************************************************

} // namespace BI
