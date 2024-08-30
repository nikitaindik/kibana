/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { Story } from '@storybook/react';
import { RelatedIntegrationsReadOnly } from './related_integrations';
import { FinalReadOnlyStorybookProviders } from '../../storybook/final_readonly_storybook_providers';
import { FinalReadOnly } from '../../final_readonly';
import type { DiffableAllFields } from '../../../../../../../../../common/api/detection_engine';

export default {
  component: RelatedIntegrationsReadOnly,
  title:
    'Rule Management/Prebuilt Rules/Upgrade Flyout/ThreeWayDiff/FinalReadonly/related_integrations',
  argTypes: {
    finalDiffableRule: {
      control: 'object',
      description: 'Final value of the diffable rule',
    },
  },
};

const mockedIntegrationsData = [
  {
    package_name: 'endpoint',
    package_title: 'Elastic Defend',
    latest_package_version: '8.15.1',
    installed_package_version: '8.16.0-prerelease.1',
    is_installed: true,
    is_enabled: false,
  },
];

function MockRelatedIntegrationsData({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();

  queryClient.setQueryData(['integrations'], mockedIntegrationsData);

  return <>{children}</>;
}

interface TemplateProps {
  finalDiffableRule: Partial<DiffableAllFields>;
}

const Template: Story<TemplateProps> = (args) => {
  return (
    <FinalReadOnlyStorybookProviders>
      <MockRelatedIntegrationsData>
        <FinalReadOnly
          fieldName="related_integrations"
          finalDiffableRule={args.finalDiffableRule as DiffableAllFields}
        />
      </MockRelatedIntegrationsData>
    </FinalReadOnlyStorybookProviders>
  );
};

export const Default = Template.bind({});

Default.args = {
  finalDiffableRule: {
    related_integrations: [{ package: 'endpoint', version: '^8.2.0' }],
  },
};
