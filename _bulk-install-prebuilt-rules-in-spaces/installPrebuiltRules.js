#!/usr/bin/env node

/**
 * Standalone script to install all prebuilt rules in each Kibana space
 * No external dependencies - uses Node.js built-in modules only
 *
 * Usage:
 *   KIBANA_URL=https://your-deployment.kb.region.aws.found.io:9243 \
 *   KIBANA_USERNAME=elastic \
 *   KIBANA_PASSWORD=yourpassword \
 *   # OR \
 *   KIBANA_API_KEY=your_api_key \
 *   node installPrebuiltRules.js
 *
 * Options:
 *   --spaces-file <path>  Path to a newline-separated file containing space IDs
 *                         to install rules in. If not provided, installs rules
 *                         in all spaces. Useful for retrying failed spaces.
 *
 *   --no-enabled-rules    Skip installing prebuilt rules that have enabled: true.
 *                         These rules would start running immediately after
 *                         installation. Use this flag to install only rules
 *                         that are disabled by default.
 *
 * On failure, the script writes failed space IDs to 'failed-spaces.txt' which
 * can be passed to --spaces-file to retry only the failed spaces.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');

// Configuration from environment variables
const KIBANA_URL = process.env.KIBANA_URL;
const KIBANA_USERNAME = process.env.KIBANA_USERNAME;
const KIBANA_PASSWORD = process.env.KIBANA_PASSWORD;
const KIBANA_API_KEY = process.env.KIBANA_API_KEY;

// CLI arguments
const args = process.argv.slice(2);
const spacesFileIndex = args.indexOf('--spaces-file');
const SPACES_FILE = spacesFileIndex !== -1 ? args[spacesFileIndex + 1] : null;
const NO_ENABLED_RULES = args.includes('--no-enabled-rules');
const FAILED_SPACES_FILE = 'failed-spaces.txt';

// Constants
const PAGE_SIZE = 50;
const RETRY_DELAY_MS = 3000;
const MAX_RETRIES = 10;

// API paths and versions
const SPACES_API = '/api/spaces/space';
const SPACES_API_VERSION = '2023-10-31';
const BOOTSTRAP_PREBUILT_RULES_API = '/internal/detection_engine/prebuilt_rules/_bootstrap';
const REVIEW_INSTALLATION_API = '/internal/detection_engine/prebuilt_rules/installation/_review';
const PERFORM_INSTALLATION_API = '/internal/detection_engine/prebuilt_rules/installation/_perform';
const DETECTION_ENGINE_API_VERSION = '1';

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
        'x-elastic-internal-origin': 'installPrebuiltRules',
        Authorization: authHeader,
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
          reject(new Error(`Status ${res.statusCode}: ${JSON.stringify(responseBody)}`));
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
async function makeRequestWithRetry(
  method,
  path,
  body = null,
  apiVersion = DETECTION_ENGINE_API_VERSION,
  attempt = 1
) {
  try {
    return await makeRequest(method, path, body, apiVersion);
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      log(`    ⟳ Attempt ${attempt} failed: ${error.message}`);
      log(`      Retrying in ${RETRY_DELAY_MS / 1000} seconds...`);
      await sleep(RETRY_DELAY_MS);
      return makeRequestWithRetry(method, path, body, apiVersion, attempt + 1);
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
  const spaceIds = content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return spaceIds.map((id) => ({ id, name: id }));
}

// Bootstrap prebuilt rules (installs Fleet packages with rule definitions)
async function bootstrapPrebuiltRules() {
  return makeRequestWithRetry('POST', BOOTSTRAP_PREBUILT_RULES_API, {});
}

// Get space-scoped path
function getSpacePath(spaceId, apiPath) {
  if (spaceId === 'default') {
    return apiPath;
  }
  return `/s/${spaceId}${apiPath}`;
}

// Review rules available for installation in a space
async function reviewRulesForInstallation(spaceId, page = 1) {
  const path = getSpacePath(spaceId, REVIEW_INSTALLATION_API);
  return makeRequestWithRetry('POST', path, {
    page: page,
    per_page: PAGE_SIZE,
  });
}

// Install specific rules in a space
async function installRules(spaceId, rules) {
  const path = getSpacePath(spaceId, PERFORM_INSTALLATION_API);
  const ruleSpecs = rules.map((rule) => ({
    rule_id: rule.rule_id,
    version: rule.version,
  }));

  return makeRequestWithRetry('POST', path, {
    mode: 'SPECIFIC_RULES',
    rules: ruleSpecs,
  });
}

// Collect all rules available for installation by paginating through the review API
async function collectAllRulesForInstallation(spaceId) {
  const allRules = [];
  let page = 1;
  let totalExpected = null;

  while (true) {
    const reviewResponse = await reviewRulesForInstallation(spaceId, page);
    const { rules, stats } = reviewResponse;

    if (page === 1) {
      totalExpected = stats?.num_rules_to_install || 0;
      log(`  Found ${totalExpected} rules available for installation`);
    }

    if (rules.length === 0) {
      break;
    }

    allRules.push(...rules);
    log(
      `  Collected page ${page} (${rules.length} rules, ${allRules.length}/${totalExpected} total)`
    );

    // If we've collected all expected rules, stop
    if (allRules.length >= totalExpected) {
      break;
    }

    page++;
  }

  return allRules;
}

// Install all prebuilt rules in a single space
async function installPrebuiltRulesInSpace(spaceId) {
  log(`\n  Phase 1: Collecting all rules available for installation...`);

  // Phase 1: Collect all rules
  let allRules;
  try {
    allRules = await collectAllRulesForInstallation(spaceId);
  } catch (error) {
    logError(`  ✗ Failed to collect rules: ${error.message}`);
    return { installed: 0, skipped: 0, failed: -1, filteredByFlag: 0, error: true };
  }

  if (allRules.length === 0) {
    log(`  ✓ No rules to install`);
    return { installed: 0, skipped: 0, failed: 0, filteredByFlag: 0, error: false };
  }

  // Filter out enabled rules if --no-enabled-rules flag is set
  let rulesToInstall = allRules;
  let filteredByFlag = 0;
  if (NO_ENABLED_RULES) {
    rulesToInstall = allRules.filter((rule) => rule.enabled !== true);
    filteredByFlag = allRules.length - rulesToInstall.length;
    if (filteredByFlag > 0) {
      log(`  Filtered out ${filteredByFlag} rule(s) with enabled: true`);
    }
  }

  if (rulesToInstall.length === 0) {
    log(`  ✓ All ${filteredByFlag} rule(s) filtered out (enabled: true)`);
    return { installed: 0, skipped: 0, failed: 0, filteredByFlag, error: false };
  }

  log(`\n  Phase 2: Installing ${rulesToInstall.length} rules in batches of ${PAGE_SIZE}...`);

  // Phase 2: Install in batches
  let totalInstalled = 0;
  let totalSkipped = 0;
  let totalFailed = 0;
  const totalBatches = Math.ceil(rulesToInstall.length / PAGE_SIZE);

  for (let i = 0; i < rulesToInstall.length; i += PAGE_SIZE) {
    const batch = rulesToInstall.slice(i, i + PAGE_SIZE);
    const batchNum = Math.floor(i / PAGE_SIZE) + 1;

    log(`  Installing batch ${batchNum}/${totalBatches} (${batch.length} rules)...`);

    try {
      const installResponse = await installRules(spaceId, batch);
      const { summary } = installResponse;

      totalInstalled += summary.succeeded;
      totalSkipped += summary.skipped;
      totalFailed += summary.failed;

      log(
        `    ✓ Succeeded: ${summary.succeeded}, Skipped: ${summary.skipped}, Failed: ${summary.failed}`
      );

      if (installResponse.errors && installResponse.errors.length > 0) {
        for (const err of installResponse.errors) {
          log(`    ⚠ Error: ${err.message}`);
        }
      }
    } catch (error) {
      logError(`    ✗ Failed to install batch: ${error.message}`);
      totalFailed += batch.length;
      // Continue with next batch instead of breaking
    }
  }

  return {
    installed: totalInstalled,
    skipped: totalSkipped,
    failed: totalFailed,
    filteredByFlag,
    error: totalFailed > 0,
  };
}

// Main function
async function main() {
  log(`Installing prebuilt rules in all spaces at ${KIBANA_URL}\n`);
  log(`Page size: ${PAGE_SIZE}, Max retries: ${MAX_RETRIES}, Retry delay: ${RETRY_DELAY_MS}ms`);
  if (NO_ENABLED_RULES) {
    log(`--no-enabled-rules: Skipping rules with enabled: true`);
  }
  log('');

  // Bootstrap prebuilt rules (install Fleet packages with rule definitions)
  log('Bootstrapping prebuilt rules (installing Fleet packages)...');
  try {
    const bootstrapResponse = await bootstrapPrebuiltRules();
    log('Bootstrap completed:');
    for (const pkg of bootstrapResponse.packages || []) {
      log(`  - ${pkg.name}@${pkg.version}: ${pkg.status}`);
    }
    log('');
  } catch (error) {
    logError(`Failed to bootstrap prebuilt rules: ${error.message}`);
    logError('This is required to make rules available for installation.');
    process.exit(1);
  }

  // Get spaces (from file or API)
  let spaces;
  if (SPACES_FILE) {
    log(`Reading spaces from file: ${SPACES_FILE}`);
    try {
      spaces = readSpacesFromFile(SPACES_FILE);
      log(`Loaded ${spaces.length} space(s) from file\n`);
    } catch (error) {
      logError(`Failed to read spaces file: ${error.message}`);
      process.exit(1);
    }
  } else {
    log('Fetching spaces from Kibana...');
    try {
      spaces = await getAllSpaces();
      log(`Found ${spaces.length} space(s)\n`);
    } catch (error) {
      logError(`Failed to fetch spaces: ${error.message}`);
      process.exit(1);
    }
  }

  // Track overall statistics
  const results = [];

  // Process each space
  for (let i = 0; i < spaces.length; i++) {
    const space = spaces[i];
    log(`[${i + 1}/${spaces.length}] Processing space "${space.id}" (${space.name})`);

    const result = await installPrebuiltRulesInSpace(space.id);
    results.push({ spaceId: space.id, ...result });
  }

  // Summary
  log('\n' + '='.repeat(60));
  log('SUMMARY');
  log('='.repeat(60));

  let grandTotalInstalled = 0;
  let grandTotalSkipped = 0;
  let grandTotalFailed = 0;
  let grandTotalFilteredByFlag = 0;
  let spacesWithErrors = 0;

  for (const result of results) {
    const status = result.error ? '✗' : '✓';
    let resultLine = `${status} Space "${result.spaceId}": Installed ${result.installed}, Skipped ${result.skipped}, Failed ${result.failed}`;
    if (result.filteredByFlag > 0) {
      resultLine += `, Filtered (enabled): ${result.filteredByFlag}`;
    }
    log(resultLine);
    grandTotalInstalled += result.installed;
    grandTotalSkipped += result.skipped;
    grandTotalFilteredByFlag += result.filteredByFlag || 0;
    if (result.failed > 0 || result.error) {
      grandTotalFailed += Math.max(result.failed, 0);
      spacesWithErrors++;
    }
  }

  log('-'.repeat(60));
  let totalLine = `Total: Installed ${grandTotalInstalled}, Skipped ${grandTotalSkipped}, Failed ${grandTotalFailed}`;
  if (grandTotalFilteredByFlag > 0) {
    totalLine += `, Filtered (enabled): ${grandTotalFilteredByFlag}`;
  }
  log(totalLine);
  log(`Spaces with errors: ${spacesWithErrors}/${spaces.length}`);

  // Write failed space IDs to file for retry
  if (spacesWithErrors > 0) {
    const failedSpaceIds = results.filter((r) => r.error || r.failed > 0).map((r) => r.spaceId);

    fs.writeFileSync(FAILED_SPACES_FILE, failedSpaceIds.join('\n') + '\n');
    log(`\nFailed space IDs written to: ${FAILED_SPACES_FILE}`);
    log(`To retry: node installPrebuiltRules.js --spaces-file ${FAILED_SPACES_FILE}`);
    process.exit(1);
  }
}

main().catch((error) => {
  logError(`Unexpected error: ${error}`);
  process.exit(1);
});
