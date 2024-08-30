/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import type { Story } from '@storybook/react';
import { FinalReadOnly } from '../../final_readonly';
import type {
  DiffableAllFields,
  RuleKqlQuery,
} from '../../../../../../../../../common/api/detection_engine';
import { FinalReadOnlyStorybookProviders } from '../../storybook/final_readonly_storybook_providers';
import {
  dataSourceWithDataView,
  dataSourceWithIndexPatterns,
  inlineKqlQuery,
  mockDataView,
  savedKqlQuery,
  savedQueryResponse,
} from '../../storybook/mocks';

export default {
  component: FinalReadOnly,
  title: 'Rule Management/Prebuilt Rules/Upgrade Flyout/ThreeWayDiff/FinalReadonly/kql_query',
};

interface TemplateProps {
  finalDiffableRule: Partial<DiffableAllFields> | { kql_query: RuleKqlQuery };
  kibanaServicesMock?: Record<string, unknown>;
}

const Template: Story<TemplateProps> = (args) => {
  return (
    <FinalReadOnlyStorybookProviders kibanaServicesMock={args.kibanaServicesMock}>
      <FinalReadOnly
        fieldName="kql_query"
        finalDiffableRule={args.finalDiffableRule as DiffableAllFields}
      />
    </FinalReadOnlyStorybookProviders>
  );
};

export const InlineKqlQueryWithIndexPatterns = Template.bind({});

InlineKqlQueryWithIndexPatterns.args = {
  finalDiffableRule: {
    kql_query: inlineKqlQuery,
    data_source: dataSourceWithIndexPatterns,
  },
  kibanaServicesMock: {
    data: {
      dataViews: {
        create: async () => mockDataView(),
      },
    },
  },
};

export const InlineKqlQueryWithDataView = Template.bind({});

InlineKqlQueryWithDataView.args = {
  finalDiffableRule: {
    kql_query: inlineKqlQuery,
    data_source: dataSourceWithDataView,
  },
  kibanaServicesMock: {
    data: {
      dataViews: {
        get: async () => mockDataView(),
      },
    },
  },
};

export const SavedKqlQueryWithIndexPatterns = Template.bind({});

SavedKqlQueryWithIndexPatterns.args = {
  finalDiffableRule: {
    kql_query: savedKqlQuery,
    data_source: dataSourceWithIndexPatterns,
    type: 'saved_query',
  },
  kibanaServicesMock: {
    data: {
      dataViews: {
        create: async () => mockDataView(),
      },
    },
    http: {
      get: async () => savedQueryResponse,
    },
  },
};

export const SavedKqlQueryWithDataView = Template.bind({});

SavedKqlQueryWithDataView.args = {
  finalDiffableRule: {
    kql_query: savedKqlQuery,
    data_source: dataSourceWithDataView,
    type: 'saved_query',
  },
  kibanaServicesMock: {
    data: {
      dataViews: {
        get: async () => mockDataView(),
      },
    },
    http: {
      get: async () => savedQueryResponse,
    },
  },
};
