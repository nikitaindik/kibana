# TL;DR

To install all prebuilt rules in all spaces run:
```bash
KIBANA_URL="https://your-kibana-deployment.elastic-cloud.com" \
KIBANA_API_KEY="your_api_key" \
node installPrebuiltRules.js
```

To create 300 empty spaces run:
```bash
KIBANA_URL="https://your-kibana-deployment.elastic-cloud.com" \
KIBANA_API_KEY="your_api_key" \
SPACE_COUNT=300 \
node createSpaces.js
```

---

# Bulk Install Prebuilt Rules in Spaces Tools

This directory contains a set of standalone Node.js scripts to help manage Kibana Spaces and Detection Engine Rules at scale. These tools are useful for testing, benchmarking, or managing large multi-space environments.

## Prerequisites

- **Node.js**: These scripts are standalone and use built-in Node.js modules. They do not require `npm install`.

## Configuration & Authentication

All scripts require the Kibana URL and authentication credentials to be provided via environment variables.

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `KIBANA_URL` | The full URL to your Kibana instance (e.g., `https://my-deployment.kb.us-east-1.aws.found.io:9243`) | Yes |
| `KIBANA_API_KEY` | Kibana API Key (Base64 encoded) | Yes (or Username/Password) |
| `KIBANA_USERNAME` | Username for Basic Auth | Yes (if API Key not used) |
| `KIBANA_PASSWORD` | Password for Basic Auth | Yes (if API Key not used) |

### Authentication Example

You can use either an API Key or Basic Auth.

**Using API Key:**
```bash
export KIBANA_URL=https://your-deployment.kb.region.aws.found.io:9243
export KIBANA_API_KEY=your_base64_encoded_api_key
```

**Using Basic Auth:**
```bash
export KIBANA_URL=https://your-deployment.kb.region.aws.found.io:9243
export KIBANA_USERNAME=elastic
export KIBANA_PASSWORD=changeme
```

## Scripts

### 1. Create Spaces (`createSpaces.js`)

Creates a specified number of spaces with IDs in the format `space-001`, `space-002`, etc.

**Environment Variables:**
- `SPACE_COUNT`: Number of spaces to create (default: 1).

**Example:**
```bash
SPACE_COUNT=50 node createSpaces.js
```

### 2. Install Prebuilt Rules (`installPrebuiltRules.js`)

Installs prebuilt detection rules into spaces. It first bootstraps the Fleet packages if needed, then installs rules.

**Options:**
- `--spaces-file <path>`: Path to a file containing a newline-separated list of space IDs to process. If not provided, it fetches all spaces from Kibana.
- `--no-enabled-rules`: Skips installation of rules that are enabled by default. Useful if you only want to install disabled rules to avoid immediate execution.

**Output:**
- If errors occur, failed space IDs are written to `failed-spaces.txt`, which can be passed back to `--spaces-file` for retrying.

**Example:**
```bash
# Install in all spaces
node installPrebuiltRules.js

# Install only in specific spaces
node installPrebuiltRules.js --spaces-file failed-spaces.txt

# Install only disabled-by-default rules
node installPrebuiltRules.js --no-enabled-rules
```

### 3. Disable Rules (`disableRules.js`)

Disables all enabled rules in specified spaces. Useful for cleaning up or stopping rule execution in bulk. Uses parallel workers for speed.

**Environment Variables:**
- `PARALLEL_WORKERS`: Number of concurrent workers (default: 4).

**Options:**
- `--spaces-file <path>`: Path to file with space IDs. If omitted, processes all spaces.
- `--dry-run`: Show what would be disabled without actually disabling.

**Example:**
```bash
PARALLEL_WORKERS=8 node disableRules.js
```

### 4. Delete Spaces (`deleteSpaces.js`)

**WARNING**: Destructive operation. Deletes spaces and all their saved objects (dashboards, rules, etc.). The `default` space is never deleted.

**Environment Variables:**
- `PARALLEL_WORKERS`: Number of concurrent workers (default: 4).

**Options:**
- `--spaces-file <path>`: Path to file with space IDs. If omitted, attempts to delete ALL non-default spaces.
- `--dry-run`: List spaces to be deleted without taking action.

**Example:**
```bash
# Dry run to see what would be deleted
node deleteSpaces.js --dry-run

# Delete all spaces (with confirmation prompt)
node deleteSpaces.js
```
