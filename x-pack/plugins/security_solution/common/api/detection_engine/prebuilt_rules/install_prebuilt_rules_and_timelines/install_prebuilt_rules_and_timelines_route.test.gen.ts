/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * NOTICE: Do not edit this file manually.
 * This file is automatically generated by the OpenAPI Generator, @kbn/openapi-generator.
 */

import type { InstallPrebuiltRulesAndTimelinesResponse } from './install_prebuilt_rules_and_timelines_route.gen';

export const installPrebuiltRulesAndTimelines = (): Cypress.Chainable<
  Cypress.Response<InstallPrebuiltRulesAndTimelinesResponse>
> =>
  cy.request({
    method: 'PUT',
    url: '/api/detection_engine/rules/prepackaged',
    headers: {
      'kbn-xsrf': 'cypress-creds',
      'x-elastic-internal-origin': 'security-solution',
      'elastic-api-version': '2023-10-31',
    },
  });
