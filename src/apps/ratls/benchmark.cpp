#include <chrono>
#include <vector>
#include <algorithm>

#include "benchmark.h"

namespace Benchmarking {

std::chrono::steady_clock::time_point currentMeasurementTS;
OpType currentMeasurementType;

std::vector<Benchmark> benchmarks;

void startMeasure(OpType type) {
	currentMeasurementTS = std::chrono::steady_clock::now();
	currentMeasurementType = type;
}

void stopMeasure() {
	long time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - currentMeasurementTS).count();
	benchmarks.push_back(Benchmark{time, currentMeasurementType});
}

double getAverageTimeForMeasurement(OpType type) {
	double d = 0;
	int c = 0;
	
	for (Benchmark b : benchmarks) {
		if (b.type == type) {
			d += b.timeTook;
			c++;
		}
	}

	return d / (double)(std::max(1, c));
}

} // namespace Benchmarking
