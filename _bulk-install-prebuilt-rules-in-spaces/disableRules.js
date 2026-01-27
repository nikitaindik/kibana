#!/usr/bin/env node

/**
 * Standalone script to disable all enabled rules in every Kibana space.
 * No external dependencies - uses Node.js built-in modules only.
 *
 * Usage:
 *   KIBANA_URL=https://your-deployment.kb.region.aws.found.io:9243 \
 *   KIBANA_USERNAME=elastic \
 *   KIBANA_PASSWORD=yourpassword \
 *   # OR \
 *   KIBANA_API_KEY=your_api_key \
 *   node disableRules.js
 *
 * Environment Variables:
 *   KIBANA_URL        - Kibana deployment URL (required)
 *   KIBANA_USERNAME   - Username for Basic Auth (required if KIBANA_API_KEY not set)
 *   KIBANA_PASSWORD   - Password for Basic Auth (required if KIBANA_API_KEY not set)
 *   KIBANA_API_KEY    - API Key for Auth (alternative to username/password)
 *   PARALLEL_WORKERS  - Number of parallel workers (default: 4)
 *
 * Options:
 *   --spaces-file <path>  Path to a newline-separated file containing space IDs
 *                         to disable rules in. If not provided, disables rules
 *                         in all spaces.
 *   --dry-run             Show what would be disabled without actually disabling
 */

const https = require('https');
const http = require('http');
const fs = require('fs');

// Configuration from environment variables
const KIBANA_URL = process.env.KIBANA_URL;
const KIBANA_USERNAME = process.env.KIBANA_USERNAME;
const KIBANA_PASSWORD = process.env.KIBANA_PASSWORD;
const KIBANA_API_KEY = process.env.KIBANA_API_KEY;
const PARALLEL_WORKERS = parseInt(process.env.PARALLEL_WORKERS, 10) || 4;

// CLI arguments
const args = process.argv.slice(2);
const spacesFileIndex = args.indexOf('--spaces-file');
const SPACES_FILE = spacesFileIndex !== -1 ? args[spacesFileIndex + 1] : null;
const DRY_RUN = args.includes('--dry-run');

// Constants
const RETRY_DELAY_MS = 3000;
const MAX_RETRIES = 10;
const REQUEST_TIMEOUT_MS = 120000;

// API paths and versions
const SPACES_API = '/api/spaces/space';
const SPACES_API_VERSION = '2023-10-31';
const BULK_ACTION_API = '/api/detection_engine/rules/_bulk_action';
const FIND_RULES_API = '/api/detection_engine/rules/_find';
const DETECTION_ENGINE_API_VERSION = '2023-10-31';

// Validate required environment variables
if (!KIBANA_URL) {
  console.error('Error: KIBANA_URL environment variable is required');
  console.error('Example: https://your-deployment.kb.region.aws.found.io:9243');
  process.exit(1);
}

if (!KIBANA_API_KEY && (!KIBANA_USERNAME || !KIBANA_PASSWORD)) {
  console.error(
    'Error: Either KIBANA_API_KEY or (KIBANA_USERNAME and KIBANA_PASSWORD) is required'
  );
  process.exit(1);
}

// Parse the Kibana URL
const kibanaUrl = new URL(KIBANA_URL);

// Create Auth header
let authHeader;
if (KIBANA_API_KEY) {
  authHeader = `ApiKey ${KIBANA_API_KEY}`;
} else {
  const auth = Buffer.from(`${KIBANA_USERNAME}:${KIBANA_PASSWORD}`).toString('base64');
  authHeader = `Basic ${auth}`;
}

// Choose http or https based on protocol
const client = kibanaUrl.protocol === 'https:' ? https : http;

// Shared state for parallel workers
let spaceQueue = [];
let queueIndex = 0;
const results = [];

// Helper function to sleep
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Get current timestamp in HH:MM:SS format
function getTimestamp() {
  const now = new Date();
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  return `${hours}:${minutes}:${seconds}`;
}

// Logging functions with timestamp
function log(message) {
  console.log(`[${getTimestamp()}] ${message}`);
}

function logError(message) {
  console.error(`[${getTimestamp()}] ${message}`);
}

// Get next space from queue
function getNextSpace() {
  if (queueIndex >= spaceQueue.length) return null;
  const index = queueIndex++;
  return { spaceId: spaceQueue[index], index, total: spaceQueue.length };
}

// Generic HTTP request function
function makeRequest(method, path, body = null, apiVersion = DETECTION_ENGINE_API_VERSION) {
  return new Promise((resolve, reject) => {
    const requestBody = body ? JSON.stringify(body) : null;

    const options = {
      hostname: kibanaUrl.hostname,
      port: kibanaUrl.port || (kibanaUrl.protocol === 'https:' ? 443 : 80),
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true',
        'elastic-api-version': apiVersion,
        Authorization: authHeader,
        Connection: 'close',
      },
    };

    if (requestBody) {
      options.headers['Content-Length'] = Buffer.byteLength(requestBody);
    }

    const req = client.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        let responseBody;
        try {
          responseBody = JSON.parse(data);
        } catch (e) {
          responseBody = data;
        }

        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(responseBody);
        } else {
          const error = new Error(`Status ${res.statusCode}: ${JSON.stringify(responseBody)}`);
          error.statusCode = res.statusCode;
          reject(error);
        }
      });
    });

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Request timeout after ${REQUEST_TIMEOUT_MS / 1000} seconds`));
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (requestBody) {
      req.write(requestBody);
    }
    req.end();
  });
}

// Make request with retry logic
async function makeRequestWithRetry(
  method,
  path,
  body = null,
  apiVersion = DETECTION_ENGINE_API_VERSION,
  attempt = 1,
  workerId = null
) {
  try {
    return await makeRequest(method, path, body, apiVersion);
  } catch (error) {
    const is429 = error.statusCode === 429;
    const maxRetries = MAX_RETRIES;
    const jitter = Math.floor(Math.random() * 2000);
    const delay = RETRY_DELAY_MS + jitter;
    const prefix = workerId !== null ? `[Worker ${workerId}] ` : '';

    if (attempt < maxRetries) {
      if (is429) {
        log(
          `${prefix}  ⟳ Got 429 (Too Many Requests), attempt ${attempt}/${maxRetries}. Waiting ${(
            delay / 1000
          ).toFixed(1)}s...`
        );
      } else {
        log(`${prefix}  ⟳ Attempt ${attempt} failed: ${error.message}`);
        log(`${prefix}    Retrying in ${(delay / 1000).toFixed(1)} seconds...`);
      }
      await sleep(delay);
      return makeRequestWithRetry(method, path, body, apiVersion, attempt + 1, workerId);
    }
    throw error;
  }
}

// Get all spaces
async function getAllSpaces() {
  return makeRequestWithRetry('GET', SPACES_API, null, SPACES_API_VERSION);
}

// Read space IDs from a file (newline-separated)
function readSpacesFromFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

// Get space-scoped path
function getSpacePath(spaceId, apiPath) {
  if (spaceId === 'default') {
    return apiPath;
  }
  return `/s/${spaceId}${apiPath}`;
}

// Count enabled rules in a space
async function countEnabledRules(spaceId, workerId) {
  const path = getSpacePath(spaceId, FIND_RULES_API);
  const response = await makeRequestWithRetry(
    'GET',
    `${path}?filter=alert.attributes.enabled:true&per_page=1`,
    null,
    DETECTION_ENGINE_API_VERSION,
    1,
    workerId
  );
  return response.total || 0;
}

// Disable all rules in a space using bulk action
async function disableAllRules(spaceId, workerId) {
  const path = getSpacePath(spaceId, BULK_ACTION_API);
  // Use query to match only enabled rules
  return makeRequestWithRetry(
    'POST',
    path,
    {
      query: 'alert.attributes.enabled: true',
      action: 'disable',
    },
    DETECTION_ENGINE_API_VERSION,
    1,
    workerId
  );
}

// Worker function - picks spaces from queue and disables rules
async function worker(workerId) {
  while (true) {
    const item = getNextSpace();
    if (!item) break;

    const { spaceId, index, total } = item;
    const prefix = `[Worker ${workerId}]`;

    log(`${prefix} [${index + 1}/${total}] Processing space "${spaceId}"...`);

    try {
      // First, count how many enabled rules exist
      const enabledCount = await countEnabledRules(spaceId, workerId);

      if (enabledCount === 0) {
        log(`${prefix}   ✓ No enabled rules to disable`);
        results.push({ spaceId, disabled: 0, status: 'success' });
        continue;
      }

      log(`${prefix}   Found ${enabledCount} enabled rule(s)`);

      if (DRY_RUN) {
        log(`${prefix}   (dry-run) Would disable ${enabledCount} rule(s)`);
        results.push({ spaceId, disabled: enabledCount, status: 'dry-run' });
        continue;
      }

      // Disable all enabled rules
      const response = await disableAllRules(spaceId, workerId);
      const disabledCount = response.attributes?.summary?.succeeded || 0;
      const failedCount = response.attributes?.summary?.failed || 0;

      if (failedCount > 0) {
        log(`${prefix}   ⚠ Disabled ${disabledCount}, Failed ${failedCount}`);
        results.push({ spaceId, disabled: disabledCount, failed: failedCount, status: 'partial' });
      } else {
        log(`${prefix}   ✓ Disabled ${disabledCount} rule(s)`);
        results.push({ spaceId, disabled: disabledCount, status: 'success' });
      }
    } catch (error) {
      logError(`${prefix}   ✗ Failed: ${error.message}`);
      results.push({ spaceId, disabled: 0, status: 'error', error: error.message });
    }
  }
  log(`[Worker ${workerId}] No more spaces to process, exiting`);
}

// Main function
async function main() {
  log(`Disabling rules in all spaces at ${KIBANA_URL}\n`);
  log(`Workers: ${PARALLEL_WORKERS}`);
  if (DRY_RUN) {
    log('Mode: DRY RUN (no actual changes)\n');
  }

  // Get spaces (from file or API)
  let spaceIds;
  if (SPACES_FILE) {
    log(`Reading spaces from file: ${SPACES_FILE}`);
    try {
      spaceIds = readSpacesFromFile(SPACES_FILE);
      log(`Loaded ${spaceIds.length} space ID(s) from file\n`);
    } catch (error) {
      logError(`Failed to read spaces file: ${error.message}`);
      process.exit(1);
    }
  } else {
    log('Fetching spaces from Kibana...');
    try {
      const spaces = await getAllSpaces();
      spaceIds = spaces.map((s) => s.id);
      log(`Found ${spaces.length} space(s)\n`);
    } catch (error) {
      logError(`Failed to fetch spaces: ${error.message}`);
      process.exit(1);
    }
  }

  if (spaceIds.length === 0) {
    log('No spaces to process.');
    return;
  }

  // Initialize the queue
  spaceQueue = spaceIds;

  // Start workers
  log(`Starting ${PARALLEL_WORKERS} parallel workers...\n`);
  const startTime = Date.now();

  const workers = [];
  for (let i = 0; i < PARALLEL_WORKERS; i++) {
    workers.push(worker(i));
  }

  // Wait for all workers to complete
  await Promise.all(workers);

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  // Summary
  log('\n' + '='.repeat(50));
  log('SUMMARY');
  log('='.repeat(50));

  let totalDisabled = 0;
  let spacesWithErrors = 0;

  // Sort results by spaceId
  results.sort((a, b) => a.spaceId.localeCompare(b.spaceId));

  for (const result of results) {
    const status = result.status === 'error' ? '✗' : result.status === 'partial' ? '⚠' : '✓';
    log(
      `${status} Space "${result.spaceId}": Disabled ${result.disabled}${
        result.failed ? `, Failed ${result.failed}` : ''
      }`
    );
    totalDisabled += result.disabled;
    if (result.status === 'error' || result.status === 'partial') {
      spacesWithErrors++;
    }
  }

  log('-'.repeat(50));
  log(`Total rules disabled: ${totalDisabled}`);
  log(`Spaces with errors: ${spacesWithErrors}/${spaceIds.length}`);
  log(`Duration: ${duration} seconds`);

  if (spacesWithErrors > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  logError(`Unexpected error: ${error}`);
  process.exit(1);
});
