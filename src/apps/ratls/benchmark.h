#pragma once

#include <chrono>
#include <vector>
#include <algorithm>
#include <string>
#include <map>
#include <iostream>
#include <fstream>

namespace Benchmarking {

typedef enum {
	RemoteAttest = 1,
	CheckQuote = 2,
	Seal = 3,
	Unseal = 4,
	Setup = 5,
	FullHandshake = 6,
	ResumedHandshake = 7,
	TCP = 8,
	NumSeals = 9,
	FullPureSSL = 10,
	ResumedPureSSL = 11
} OpType;

std::string opTypeToString(OpType opType);

struct Benchmark {
	long value;
	OpType type;
};

struct BenchmarkSetupData {
	bool performBenchmarking;
	uint32_t numSamples;
	bool resumeSessions;
	bool performPureSSLHandshakes;
	std::string outputPath;
};

BenchmarkSetupData parseCommandLine(int argc, char const *argv[]);

void startMeasure(OpType type);

void stopMeasure(OpType type);

double getAverageTimeForMeasurement(OpType type);

void measureSingleValue(OpType type);

long getSingleValue(OpType type);

void writeBenchmarksToFile(std::string path);



} // namespace Benchmarking
