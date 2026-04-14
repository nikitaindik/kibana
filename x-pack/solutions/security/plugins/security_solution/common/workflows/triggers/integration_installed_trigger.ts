/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import type { CommonTriggerDefinition } from '@kbn/workflows-extensions/common';

export const SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID =
  'security_integrations.installed' as const;

export const securityIntegrationInstalledEventSchema = z.object({
  package_name: z.string().describe('The Fleet package name (e.g. "endpoint", "okta", "aws").'),
  package_title: z.string().describe('Human-readable package title (e.g. "Elastic Defend").'),
  package_version: z.string().describe('Installed package version (semver).'),
  integration_count: z
    .number()
    .describe('Number of integrations within the package (e.g. AWS has many sub-integrations).'),
});

export type SecurityIntegrationInstalledEvent = z.infer<
  typeof securityIntegrationInstalledEventSchema
>;

export const commonSecurityIntegrationInstalledTriggerDefinition: CommonTriggerDefinition = {
  id: SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID,
  eventSchema: securityIntegrationInstalledEventSchema,
};
