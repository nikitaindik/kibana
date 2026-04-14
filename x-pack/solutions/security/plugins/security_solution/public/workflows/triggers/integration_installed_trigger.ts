/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';
import type { PublicTriggerDefinition } from '@kbn/workflows-extensions/public';
import React from 'react';
import {
  SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID,
  commonSecurityIntegrationInstalledTriggerDefinition,
} from '../../../common/workflows/triggers';

export const securityIntegrationInstalledPublicDefinition: PublicTriggerDefinition = {
  ...commonSecurityIntegrationInstalledTriggerDefinition,
  title: i18n.translate('xpack.securitySolution.workflows.integrationInstalledTrigger.title', {
    defaultMessage: 'Security integration installed',
  }),
  description: i18n.translate(
    'xpack.securitySolution.workflows.integrationInstalledTrigger.description',
    {
      defaultMessage:
        'Emitted when a new Fleet integration package is installed. Use this to automatically set up detection rules for new data sources.',
    }
  ),
  icon: React.lazy(() =>
    import('@elastic/eui/es/components/icon/assets/package').then(({ icon }) => ({
      default: icon,
    }))
  ),
  documentation: {
    details: i18n.translate(
      'xpack.securitySolution.workflows.integrationInstalledTrigger.documentation.details',
      {
        defaultMessage:
          'Emitted when a Fleet integration package is installed. Use event properties to filter by package name or set up detection coverage automatically.',
      }
    ),
    examples: [
      i18n.translate(
        'xpack.securitySolution.workflows.integrationInstalledTrigger.documentation.exampleAny',
        {
          defaultMessage: `## Run on any new integration\n\`\`\`yaml\ntriggers:\n  - type: {triggerId}\n\`\`\``,
          values: { triggerId: SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID },
        }
      ),
      i18n.translate(
        'xpack.securitySolution.workflows.integrationInstalledTrigger.documentation.exampleSpecific',
        {
          defaultMessage: `## Only for specific packages\n\`\`\`yaml\ntriggers:\n  - type: {triggerId}\n    on:\n      condition: 'event.package_name: "okta" OR event.package_name: "aws"'\n\`\`\``,
          values: { triggerId: SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID },
        }
      ),
    ],
  },
  snippets: {
    condition: 'event.package_name: "endpoint"',
  },
};
