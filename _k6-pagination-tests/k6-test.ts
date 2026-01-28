/* eslint-disable import/no-default-export */

import { sleep } from 'k6';
import execution from 'k6/execution';
import { Counter, Trend, Gauge } from 'k6/metrics';
import { hitInstallationReviewEndpoint } from './hit-installation-review-endpoint.ts';
import { wait } from './utils.ts';

const ENV = {
  KIBANA_URL: __ENV.KIBANA_URL,
  PASSWORD: __ENV.PASSWORD,
  TYPE: __ENV.TYPE,
  TARGET_USERS: Number(__ENV.TARGET_USERS),
  SMALL_PAGE_SIZE: Number(__ENV.SMALL_PAGE_SIZE),
  LARGE_PAGE_SIZE: Number(__ENV.LARGE_PAGE_SIZE),
};

Object.entries(ENV).forEach(([key, value]) => {
  if (!value) {
    throw new Error(`${key} environment variable must be set`);
  }
});

console.log('Starting test with the following parameters:', ENV);

const counters = {
  immediateSuccess: new Counter('immediate_success_count'),
  retryStart: new Counter('retry_start_count'),
  retrySuccess: new Counter('retry_success_count'),
  retryProgress: new Gauge('retry_progress'),
};

const context = {
  ...ENV,
  counters,
};

export const options = {
  systemTags: ['url', 'error', 'error_code', 'vu', 'iter'],
  scenarios: {
    my_test: {
      executor: 'ramping-vus',
      gracefulStop: '3s',
      stages: [
        { duration: `${35 * Math.PI}s`, target: ENV.TARGET_USERS },
        { duration: '12m', target: ENV.TARGET_USERS }, // Approximately 20 runs of a 35 second actions sequence for each VU
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<3000'],
  },
};

export default function () {
  const vuId = execution.vu.idInTest; // Unique VU ID across the test
  const iter = execution.vu.iterationInInstance; // Current iteration number

  console.log(`VU ID: ${vuId}, Iteration: ${iter}`);

  if (ENV.TYPE === 'main') {
    hitInstallationReviewEndpoint(context);
    sleep(35);
  } else {
    // Opens rule installation page and waits for it to load
    hitInstallationReviewEndpoint(context, {
      page: 1,
      per_page: ENV.SMALL_PAGE_SIZE,
    });
    wait({ min: 3, max: 4 });

    // Searches for "process", looks at results for 3 seconds
    hitInstallationReviewEndpoint(context, {
      page: 1,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { name: { values: { include: ['process'] } } },
      },
    });
    wait({ min: 3, max: 4 });

    // Sorts by severity: DESC and looks at results for 1 second
    hitInstallationReviewEndpoint(context, {
      page: 1,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { name: { values: { include: ['process'] } } },
      },
      sort: [{ field: 'severity', order: 'desc' }],
    });
    wait({ min: 3, max: 4 });

    // Sorts by severity: ASC and looks at results for 3 seconds
    hitInstallationReviewEndpoint(context, {
      page: 1,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { name: { values: { include: ['process'] } } },
      },
      sort: [{ field: 'severity', order: 'asc' }],
    });
    wait({ min: 3, max: 4 });

    // Goes to page 2 and looks at results for 3 seconds
    hitInstallationReviewEndpoint(context, {
      page: 2,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { name: { values: { include: ['process'] } } },
      },
      sort: [{ field: 'severity', order: 'asc' }],
    });
    wait({ min: 3, max: 4 });

    // Goes to page 3 and looks at results for 3 seconds
    hitInstallationReviewEndpoint(context, {
      page: 3,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { name: { values: { include: ['process'] } } },
      },
      sort: [{ field: 'severity', order: 'asc' }],
    });
    wait({ min: 3, max: 4 });

    // Removes the name filter, filters by tag "OS: Windows" instead, looks at results for 3 seconds
    hitInstallationReviewEndpoint(context, {
      page: 1,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { tags: { values: { include: ['OS: Windows'] } } },
      },
    });
    wait({ min: 3, max: 4 });

    // Goes to page 2, looks for 3 sec
    hitInstallationReviewEndpoint(context, {
      page: 2,
      per_page: ENV.SMALL_PAGE_SIZE,
      filter: {
        fields: { tags: { values: { include: ['OS: Windows'] } } },
      },
    });
    wait({ min: 3, max: 4 });

    // Clears all filters, sets page size to 100, looks for 3 sec
    hitInstallationReviewEndpoint(context, {
      page: 1,
      per_page: ENV.LARGE_PAGE_SIZE,
    });
    wait({ min: 3, max: 4 });

    // Goes to page 2, looks for 3 sec
    hitInstallationReviewEndpoint(context, {
      page: 2,
      per_page: ENV.LARGE_PAGE_SIZE,
    });
    wait({ min: 3, max: 4 });
  }
}
