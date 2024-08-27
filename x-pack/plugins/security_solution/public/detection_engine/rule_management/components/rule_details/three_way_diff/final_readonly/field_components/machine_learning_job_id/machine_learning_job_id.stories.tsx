/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { Story } from '@storybook/react';
import { MachineLearningJobIdReadOnly } from './machine_learning_job_id';
import type { DiffableAllFields } from '../../../../../../../../../common/api/detection_engine';
import { FinalReadonly } from '../../final_readonly';
import { StorybookProviders } from '../../storybook/storybook_providers';
import { GET_MODULES_QUERY_KEY } from '../../../../../../../../common/components/ml_popover/hooks/use_fetch_modules_query';
import { GET_RECOGNIZER_QUERY_KEY } from '../../../../../../../../common/components/ml_popover/hooks/use_fetch_recognizer_query';
import { GET_JOBS_SUMMARY_QUERY_KEY } from '../../../../../../../../common/components/ml/hooks/use_fetch_jobs_summary_query';

export default {
  component: MachineLearningJobIdReadOnly,
  title:
    'Rule Management/Prebuilt Rules/Upgrade Flyout/ThreeWayDiff/FinalReadonly/machine_learning_job_id',
  argTypes: {
    finalDiffableRule: {
      control: 'object',
      description: 'Final value of the diffable rule',
    },
  },
};

const mockedModulesData = [
  {
    id: 'security_auth',
    jobs: [
      {
        id: 'auth_high_count_logon_events',
        config: {
          groups: [],
          custom_settings: {
            security_app_display_name: 'Spike in Logon Events',
          },
        },
      },
    ],
  },
];

const mockedCompatibleModules = [
  {
    id: 'security_auth',
  },
];

function MockMlData({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();

  queryClient.setQueryData([GET_JOBS_SUMMARY_QUERY_KEY, {}], []);

  queryClient.setQueryData([GET_MODULES_QUERY_KEY, {}], mockedModulesData);

  queryClient.setQueryData(
    [GET_RECOGNIZER_QUERY_KEY, { indexPatternName: undefined }],
    mockedCompatibleModules
  );

  return <>{children}</>;
}

interface TemplateProps {
  finalDiffableRule: Partial<DiffableAllFields>;
}

const Template: Story<TemplateProps> = (args) => {
  // console.log('dbg template', useSecurityJobs);

  return (
    <StorybookProviders kibanaServicesMock={args.kibanaServicesMock}>
      <MockMlData>
        <FinalReadonly
          fieldName="machine_learning_job_id"
          finalDiffableRule={args.finalDiffableRule as DiffableAllFields}
        />
      </MockMlData>
    </StorybookProviders>
  );
};

export const Default = Template.bind({});

Default.args = {
  finalDiffableRule: {
    // machine_learning_job_id: 'fake-ml-job-id',
    machine_learning_job_id: 'auth_high_count_logon_events',
  },
};

// Template.
