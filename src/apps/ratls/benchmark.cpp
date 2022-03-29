#include <chrono>
#include <vector>
#include <algorithm>
#include <map>
#include <string>

#include "benchmark.h"

namespace Benchmarking {

std::map<OpType, std::vector<Benchmark>> benchmarks;
std::map<OpType, long> benchmarkSingleValues;
std::map<OpType, std::chrono::steady_clock::time_point> currentMeasurements;

// client --tpm-hardware /dev/tmp0 127.0.0.1 --benchmarking-samples 1000 -benchmarking-resume-sessions
BenchmarkSetupData parseCommandLine(int argc, char const *argv[]) {
	BenchmarkSetupData setupData = { false, 0, false, false, "" };
	for(int i = 0; i < argc; i++) {
		std::string argument = argv[i];
		if(argument == "--benchmarking-samples" && i + 1 < argc) {
			setupData.performBenchmarking = true;
			std::string value = argv[i + 1];
			setupData.numSamples = std::stoi(value);
			i++;
		} else if(argument == "--benchmarking-resume-sessions") {
			setupData.resumeSessions = true;
		} else if(argument == "--benchmarking-pure-ssl") {
			setupData.performPureSSLHandshakes = true;
		} else if(argument == "--benchmarking-outputfile" && i + 1 < argc) {
			std::string value = argv[i + 1];
			setupData.outputPath = value;
			i++;
		}
	}
    return setupData;
}

std::string opTypeToString(OpType opType) {
	switch(opType) {
		case RemoteAttest: return "RemoteAttest"; break;
		case CheckQuote: return "CheckQuote"; break;
		case Seal: return "Seal"; break;
		case Unseal: return "Unseal"; break;
		case Setup: return "Setup"; break;
		case FullHandshake: return "FullHandshake"; break;
		case ResumedHandshake: return "ResumedHandshake"; break;
		case TCP: return "TCP"; break;
		case NumSeals: return "NumSeals"; break;
		case FullPureSSL: return "FullPureSSL"; break;
		case ResumedPureSSL: return "ResumedPureSSL"; break;
		default:
			return std::to_string((int)opType);
	}
}

void startMeasure(OpType type) {
	currentMeasurements[type] = std::chrono::steady_clock::now();
}

void stopMeasure(OpType type) {
	long time = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - currentMeasurements[type]).count();
	benchmarks[type].push_back(Benchmark{time, type});
}

void measureSingleValue(OpType type) {
	if(benchmarkSingleValues.find(type) == benchmarkSingleValues.end()) {
		benchmarkSingleValues[type] = 0;
	}
	benchmarkSingleValues[type]++;
}

long getSingleValue(OpType type) {
	if(benchmarkSingleValues.find(type) == benchmarkSingleValues.end()) {
		return 0;
	}
	return benchmarkSingleValues[type];
}


double getAverageTimeForMeasurement(OpType type) {
	double d = 0;
	int c = 0;
	
	for (Benchmark b : benchmarks[type]) {
		if (b.type == type) {
			d += b.value;
			c++;
		}
	}

	return (d / (double)(std::max(1, c))) / 1000000.0;
}

void writeBenchmarksToFile(std::string outputPath) {
	if(outputPath.length() <= 0) return;

	std::ofstream file;
    file.open (outputPath);

	size_t maxBenchmarkNum = 0;
	for (std::map<OpType, std::vector<Benchmark>>::iterator it = benchmarks.begin(); it != benchmarks.end(); it++)  {
		if(it->second.size() > maxBenchmarkNum) maxBenchmarkNum = it->second.size();
		file << opTypeToString(it->first) << ",";
	}
	file << "\n";

	for(size_t i = 0; i < maxBenchmarkNum; i++) {
		for (std::map<OpType, std::vector<Benchmark>>::iterator it = benchmarks.begin(); it != benchmarks.end(); it++)  {
			std::vector<Benchmark>& bechmarkValues = it->second;
			if(i < bechmarkValues.size()) {
				file << (double)(bechmarkValues[i].value / 1000000.0) << ",";
			} else {
				file << "" << ",";
			}
		}
		file << "\n";
	}

    file.close();
}

} // namespace Benchmarking
