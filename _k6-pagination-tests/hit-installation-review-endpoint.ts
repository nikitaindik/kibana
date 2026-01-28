import http from 'k6/http';
import encoding from 'k6/encoding';
import execution from 'k6/execution';
import { Counter, Trend, Gauge } from 'k6/metrics';
import { cappedExponentialBackoff } from './utils.ts';
import { sleep } from 'k6';

export function hitInstallationReviewEndpoint(
  context: {
    KIBANA_URL: string;
    PASSWORD: string;
    TYPE: string;
    counters: {
      immediateSuccess: Counter;
      retryStart: Counter;
      retrySuccess: Counter;
      retryProgress: Gauge;
    };
  },
  requestBody = {}
) {
  const { KIBANA_URL, PASSWORD, TYPE, counters } = context;

  const body = JSON.stringify(requestBody);

  let retryNumber = 0;

  const vuId = execution.vu.idInTest;
  const iter = execution.vu.iterationInInstance;
  const requestId = `vu-${vuId}-iter-${iter}-${Math.random().toString(36).substring(2, 6)}`;

  while (true) {
    if (retryNumber > 0) {
      console.log(`Retrying... (retry attempt ${retryNumber}) VU ID: ${vuId}, Iteration: ${iter}`);
    }

    const response = http.post(
      `${KIBANA_URL}/internal/detection_engine/prebuilt_rules/installation/_review`,
      body,
      {
        headers: {
          Authorization: `Basic ${encoding.b64encode(`elastic:${PASSWORD}`)}`,
          'content-type': 'application/json',
          'elastic-api-version': '1',
          'kbn-version': '9.4.0-SNAPSHOT',
          'x-elastic-internal-origin': 'Kibana',
        },
        tags: {
          requestId,
        },
      }
    );

    if (response.status === 200) {
      break;
    }

    if (response.status !== 429 && response.status !== 0) {
      // It's not 200 and not 429: something went wrong
      const errorText = `Unexpected status code: ${
        response.status
      }. VU ID: ${vuId}, Iteration: ${iter}. Response: ${JSON.stringify(response.body)}`;

      console.error(errorText);
      execution.test.abort();
      throw new Error(errorText);
    }

    // It's a 429
    if (retryNumber === 0) {
      // Increase global counter for the number of retries started
      counters.retryStart.add(1);
    }

    retryNumber++;
    counters.retryProgress.add(retryNumber, { requestId }); // Remember that this VU ID and iteration had this many retries

    const backoff = cappedExponentialBackoff(retryNumber);
    sleep(backoff / 1000);
  }

  // Request eventually succeeded
  if (retryNumber === 0) {
    // Succeeded on first attempt
    counters.immediateSuccess.add(1);
  } else {
    // Succeeded after retries
    counters.retrySuccess.add(1);
  }

  return;
}
