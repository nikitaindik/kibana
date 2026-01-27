#!/usr/bin/env node

/**
 * Standalone script to delete multiple spaces from Kibana Cloud in parallel.
 * No external dependencies - uses Node.js built-in modules only.
 *
 * WARNING: This is a destructive operation! Deleting a space will delete
 * ALL saved objects within that space (dashboards, rules, visualizations, etc.)
 *
 * Note: The "default" space cannot be deleted and will be skipped.
 *
 * Usage:
 *   KIBANA_URL=https://your-deployment.kb.region.aws.found.io:9243 \
 *   KIBANA_USERNAME=elastic \
 *   KIBANA_PASSWORD=yourpassword \
 *   # OR \
 *   KIBANA_API_KEY=your_api_key \
 *   node deleteSpaces.js
 *
 * For faster deletion with multiple workers:
 *   PARALLEL_WORKERS=4 node deleteSpaces.js
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
 *                         to delete. If not provided, deletes ALL non-default spaces.
 *   --dry-run             Show what would be deleted without actually deleting
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
const RETRY_DELAY_429_MS = 5000;
const MAX_RETRIES = 10;
const MAX_RETRIES_429 = 30;

// API paths and versions
const SPACES_API = '/api/spaces/space';
const SPACES_API_VERSION = '2023-10-31';

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
function makeRequest(method, path, body = null) {
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
        'elastic-api-version': SPACES_API_VERSION,
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
        } else if (res.statusCode === 404) {
          // Space already deleted
          resolve({ alreadyDeleted: true });
        } else {
          const error = new Error(`Status ${res.statusCode}: ${JSON.stringify(responseBody)}`);
          error.statusCode = res.statusCode;
          reject(error);
        }
      });
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
async function makeRequestWithRetry(method, path, body = null, attempt = 1, workerId = null) {
  try {
    return await makeRequest(method, path, body);
  } catch (error) {
    const is429 = error.statusCode === 429;
    const maxRetries = is429 ? MAX_RETRIES_429 : MAX_RETRIES;
    const baseDelay = is429 ? RETRY_DELAY_429_MS : RETRY_DELAY_MS;
    const jitter = Math.floor(Math.random() * 2000);
    const delay = baseDelay + jitter;
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
      return makeRequestWithRetry(method, path, body, attempt + 1, workerId);
    }
    throw error;
  }
}

// Get all spaces
async function getAllSpaces() {
  return makeRequestWithRetry('GET', SPACES_API);
}

// Read space IDs from a file (newline-separated)
function readSpacesFromFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

// Delete a single space
async function deleteSpace(spaceId, workerId) {
  const path = `${SPACES_API}/${encodeURIComponent(spaceId)}`;
  return makeRequestWithRetry('DELETE', path, null, 1, workerId);
}

// Worker function - picks spaces from queue and deletes them
async function worker(workerId) {
  while (true) {
    const item = getNextSpace();
    if (!item) break;

    const { spaceId, index, total } = item;
    const prefix = `[Worker ${workerId}]`;

    log(`${prefix} [${index + 1}/${total}] Deleting space "${spaceId}"...`);

    if (DRY_RUN) {
      log(`${prefix}   (dry-run) Would delete space "${spaceId}"`);
      results.push({ spaceId, status: 'dry-run' });
      continue;
    }

    try {
      const response = await deleteSpace(spaceId, workerId);
      if (response.alreadyDeleted) {
        log(`${prefix}   ⚠ Space "${spaceId}" was already deleted`);
        results.push({ spaceId, status: 'already-deleted' });
      } else {
        log(`${prefix}   ✓ Deleted space "${spaceId}"`);
        results.push({ spaceId, status: 'deleted' });
      }
    } catch (error) {
      logError(`${prefix}   ✗ Failed to delete space "${spaceId}": ${error.message}`);
      results.push({ spaceId, status: 'failed', error: error.message });
    }
  }
  log(`[Worker ${workerId}] No more spaces to process, exiting`);
}

// Main function
async function main() {
  log(`Deleting spaces from ${KIBANA_URL}\n`);
  log(`Workers: ${PARALLEL_WORKERS}`);
  if (DRY_RUN) {
    log('Mode: DRY RUN (no actual deletions)\n');
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
      // Extract IDs, excluding "default" space
      spaceIds = spaces.map((s) => s.id);
      log(`Found ${spaces.length} space(s)\n`);
    } catch (error) {
      logError(`Failed to fetch spaces: ${error.message}`);
      process.exit(1);
    }
  }

  // Filter out "default" space
  const defaultIndex = spaceIds.indexOf('default');
  if (defaultIndex !== -1) {
    spaceIds.splice(defaultIndex, 1);
    log('Note: "default" space cannot be deleted and will be skipped.\n');
  }

  if (spaceIds.length === 0) {
    log('No spaces to delete.');
    return;
  }

  log(`Will delete ${spaceIds.length} space(s):\n`);
  for (const id of spaceIds.slice(0, 10)) {
    log(`  - ${id}`);
  }
  if (spaceIds.length > 10) {
    log(`  ... and ${spaceIds.length - 10} more\n`);
  }

  // Confirmation pause (3 seconds) unless dry-run
  if (!DRY_RUN) {
    log('\n⚠️  WARNING: This will permanently delete all objects in these spaces!');
    log('Starting in 3 seconds... (Ctrl+C to abort)\n');
    await sleep(3000);
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

  const deleted = results.filter((r) => r.status === 'deleted').length;
  const alreadyDeleted = results.filter((r) => r.status === 'already-deleted').length;
  const failed = results.filter((r) => r.status === 'failed').length;
  const dryRun = results.filter((r) => r.status === 'dry-run').length;

  if (DRY_RUN) {
    log(`Would delete: ${dryRun}`);
  } else {
    log(`Deleted: ${deleted}`);
    log(`Already deleted: ${alreadyDeleted}`);
    log(`Failed: ${failed}`);
  }
  log(`Duration: ${duration} seconds`);

  // List failed spaces if any
  if (failed > 0) {
    log('\nFailed spaces:');
    for (const r of results.filter((r) => r.status === 'failed')) {
      log(`  - ${r.spaceId}: ${r.error}`);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  logError(`Unexpected error: ${error}`);
  process.exit(1);
});
