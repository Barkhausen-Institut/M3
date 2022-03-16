#pragma once

#include <chrono>
#include <vector>
#include <algorithm>

namespace Benchmarking {

typedef enum {
	RemoteAttest = 1,
	CheckQuote = 2,
	Seal = 3,
	Unseal = 4
} OpType;

struct Benchmark {
	long timeTook;
	OpType type;
};

void startMeasure(OpType type);

void stopMeasure();

double getAverageTimeForMeasurement(OpType type);

} // namespace Benchmarking
