#!/usr/bin/env node

/**
 * Standalone script to create multiple spaces in Kibana Cloud
 * No external dependencies - uses Node.js built-in modules only
 *
 * Usage:
 *   KIBANA_URL=https://your-deployment.kb.region.aws.found.io:9243 \
 *   KIBANA_USERNAME=elastic \
 *   KIBANA_PASSWORD=yourpassword \
 *   # OR \
 *   KIBANA_API_KEY=your_api_key \
 *   SPACE_COUNT=10 \
 *   node createSpaces.js
 */

const https = require('https');
const http = require('http');

// Configuration from environment variables
const KIBANA_URL = process.env.KIBANA_URL;
const KIBANA_USERNAME = process.env.KIBANA_USERNAME;
const KIBANA_PASSWORD = process.env.KIBANA_PASSWORD;
const KIBANA_API_KEY = process.env.KIBANA_API_KEY;
const SPACE_COUNT = parseInt(process.env.SPACE_COUNT, 10) || 1;

// Retry configuration
const RETRY_DELAY_MS = 3000;
const MAX_RETRIES = 3;

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

// Helper function to sleep
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Function to create a single space
function createSpace(spaceId) {
  return new Promise((resolve, reject) => {
    const space = {
      id: spaceId,
      name: spaceId,
      description: 'Created by createSpaces.js script',
      disabledFeatures: [],
    };

    const requestBody = JSON.stringify(space);

    const options = {
      hostname: kibanaUrl.hostname,
      port: kibanaUrl.port || (kibanaUrl.protocol === 'https:' ? 443 : 80),
      path: '/api/spaces/space',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestBody),
        'kbn-xsrf': 'true',
        Authorization: authHeader,
      },
    };

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

        if (res.statusCode === 200) {
          resolve({ success: true, status: 'created', spaceId, responseBody });
        } else if (res.statusCode === 409) {
          resolve({ success: true, status: 'exists', spaceId, responseBody });
        } else {
          reject(new Error(`Status ${res.statusCode}: ${JSON.stringify(responseBody)}`));
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    req.write(requestBody);
    req.end();
  });
}

// Function to create a space with retries
async function createSpaceWithRetry(spaceId, attempt = 1) {
  try {
    const result = await createSpace(spaceId);
    return result;
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      console.log(`  ⟳ Attempt ${attempt} failed: ${error.message}`);
      console.log(`    Retrying in ${RETRY_DELAY_MS / 1000} seconds...`);
      await sleep(RETRY_DELAY_MS);
      return createSpaceWithRetry(spaceId, attempt + 1);
    }
    throw error;
  }
}

// Main function to create all spaces
async function main() {
  console.log(`Creating ${SPACE_COUNT} space(s) in ${KIBANA_URL}...\n`);

  let created = 0;
  let alreadyExists = 0;
  let failed = 0;

  for (let i = 1; i <= SPACE_COUNT; i++) {
    const spaceId = `space-${String(i).padStart(3, '0')}`;
    console.log(`[${i}/${SPACE_COUNT}] Creating space "${spaceId}"...`);

    try {
      const result = await createSpaceWithRetry(spaceId);

      if (result.status === 'created') {
        console.log(`  ✓ Successfully created space "${spaceId}"`);
        created++;
      } else if (result.status === 'exists') {
        console.log(`  ⚠ Space "${spaceId}" already exists`);
        alreadyExists++;
      }
    } catch (error) {
      console.error(`  ✗ Failed to create space "${spaceId}" after ${MAX_RETRIES} attempts`);
      console.error(`    Error: ${error.message}`);
      failed++;
    }
  }

  // Summary
  console.log('\n--- Summary ---');
  console.log(`Created: ${created}`);
  console.log(`Already existed: ${alreadyExists}`);
  console.log(`Failed: ${failed}`);

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Unexpected error:', error);
  process.exit(1);
});
