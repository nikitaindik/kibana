const fs = require("fs");
const readline = require("readline");

const filePath = process.argv[2];

if (!filePath) {
  console.error("Please provide the path to the JSON results file.");
  process.exit(1);
}

const metrics = {
  immediateSuccessCount: 0,
  retryStartCount: 0,
  retrySuccessCount: 0,
  retries: {}, // Map of requestId -> retries count
};

const processLine = (line) => {
  if (!line.trim()) return;

  try {
    const entry = JSON.parse(line);
    if (entry.type !== "Point" || !entry.metric) return;

    if (entry.metric === "immediate_success_count") {
      metrics.immediateSuccessCount += entry.data.value;
    } else if (entry.metric === "retry_start_count") {
      metrics.retryStartCount += entry.data.value;
    } else if (entry.metric === "retry_success_count") {
      metrics.retrySuccessCount += entry.data.value;
    } else if (entry.metric === "retry_progress") {
      const { requestId } = entry.data.tags;

      if (!metrics.retries[requestId]) {
        metrics.retries[requestId] = 0;
      }

      metrics.retries[requestId] = Math.max(
        metrics.retries[requestId],
        entry.data.value
      );
    }
  } catch (err) {
    // Ignore malformed lines
  }
};

const MAX_BACKOFF = 30000;

const cappedExponentialBackoff = (failedAttempts) => {
  const backoff = Math.min(1000 * 2 ** failedAttempts, MAX_BACKOFF);
  return backoff;
};

const calculateTotalWaitTime = (retries) => {
  let totalWaitTime = 0;
  for (let i = 1; i <= retries; i++) {
    totalWaitTime += cappedExponentialBackoff(i);
  }
  return totalWaitTime / 1000;
};

const printResults = () => {
  const initialRequestsCount =
    metrics.immediateSuccessCount + metrics.retryStartCount;

  const unresolvedRetriesCount =
    metrics.retryStartCount - metrics.retrySuccessCount;

  const frequencyMap = Object.values(metrics.retries).reduce((acc, value) => {
    acc.set(value, (acc.get(value) || 0) + 1);
    return acc;
  }, new Map());

  const sortedFrequencyMap = Array.from(frequencyMap.entries()).sort(
    (a, b) => a[0] - b[0]
  );

  console.log("\n--- Retry Metrics Summary ---");
  console.log(`Initial requests: ${initialRequestsCount} (100%)`);
  console.log(
    `├── Succeeded on first attempt: ${metrics.immediateSuccessCount} (${(
      (metrics.immediateSuccessCount / initialRequestsCount) *
      100
    ).toFixed(2)}%)`
  );
  console.log(
    `└── Needed retries: ${metrics.retryStartCount} (${(
      (metrics.retryStartCount / initialRequestsCount) *
      100
    ).toFixed(2)}%)`
  );
  console.log(`    ├── Resolved retries: ${metrics.retrySuccessCount}`);
  console.log(`    └── Unresolved retries: ${unresolvedRetriesCount}`);

  sortedFrequencyMap.forEach(([retries, count]) => {
    const waitTime = calculateTotalWaitTime(retries);
    console.log(
      `${retries} retry(s) needed (${waitTime} sec): ${count} requests`
    );
  });

  console.log("-----------------------------\n");
};

const processFile = async () => {
  const fileStream = fs.createReadStream(filePath);

  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    processLine(line);
  }

  printResults();
};

processFile().catch((err) => {
  console.error("Error processing file:", err);
});
