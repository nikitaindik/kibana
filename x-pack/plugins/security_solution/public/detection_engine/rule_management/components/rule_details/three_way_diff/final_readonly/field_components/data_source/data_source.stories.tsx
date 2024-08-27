/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import type { Story } from '@storybook/react';
import { FinalReadonly } from '../../final_readonly';
import type { DiffableAllFields } from '../../../../../../../../../common/api/detection_engine';

import { StorybookProviders } from '../../storybook/storybook_providers';
import { dataViewDataSource, indexPatternsDataSource } from '../../storybook/mocks';

export default {
  component: FinalReadonly,
  title: 'Rule Management/Prebuilt Rules/Upgrade Flyout/ThreeWayDiff/FinalReadonly/data_source',
  argTypes: {
    finalDiffableRule: {
      control: 'object',
      description: 'Final value of the diffable rule',
    },
  },
};

interface TemplateProps {
  finalDiffableRule: Partial<DiffableAllFields>;
  kibanaServicesMock?: Record<string, unknown>;
}

const Template: Story<TemplateProps> = (args) => {
  return (
    <StorybookProviders kibanaServicesMock={args.kibanaServicesMock}>
      <FinalReadonly
        fieldName="data_source"
        finalDiffableRule={args.finalDiffableRule as DiffableAllFields}
      />
    </StorybookProviders>
  );
};

export const DataSourceWithIndexPatterns = Template.bind({});

DataSourceWithIndexPatterns.args = {
  finalDiffableRule: {
    data_source: indexPatternsDataSource,
  },
};

export const DataSourceWithDataView = Template.bind({});

DataSourceWithDataView.args = {
  finalDiffableRule: {
    data_source: dataViewDataSource,
  },
  kibanaServicesMock: {
    data: {
      dataViews: {
        get: async () => ({ getIndexPattern: () => 'logs-*' }),
      },
    },
  },
};
