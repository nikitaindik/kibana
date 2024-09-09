/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import type { Story } from '@storybook/react';
import { DescriptionReadOnly } from './description';
import { FieldReadOnly } from '../../field_readonly';
import type { DiffableAllFields } from '../../../../../../../../../common/api/detection_engine';

export default {
  component: DescriptionReadOnly,
  title: 'Rule Management/Prebuilt Rules/Upgrade Flyout/ThreeWayDiff/FieldReadOnly/description',
};

interface TemplateProps {
  finalDiffableRule: Partial<DiffableAllFields>;
}

const Template: Story<TemplateProps> = (args) => {
  return (
    <FieldReadOnly
      fieldName="description"
      finalDiffableRule={args.finalDiffableRule as DiffableAllFields}
    />
  );
};

export const Default = Template.bind({});

Default.args = {
  finalDiffableRule: {
    description:
      "Identifies the occurrence of a security alert from the Google Workspace alerts center. Google Workspace's security alert center provides an overview of actionable alerts that may be affecting an organization's domain. An alert is a warning of a potential security issue that Google has detected.",
  },
};
