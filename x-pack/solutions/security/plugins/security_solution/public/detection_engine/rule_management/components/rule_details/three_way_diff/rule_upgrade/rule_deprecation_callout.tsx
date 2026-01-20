/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiCallOut, EuiSpacer } from '@elastic/eui';
import type { RuleDeprecationStage } from '../../../../../../../common/api/detection_engine/prebuilt_rules/common/rule_deprecation_info';
import * as i18n from './translations';

interface RuleDeprecationCalloutProps {
  stage: RuleDeprecationStage;
  reason?: string;
}

export const RuleDeprecationCallout = ({ stage, reason }: RuleDeprecationCalloutProps) => {
  const title =
    stage === 'deprecation_started'
      ? i18n.RULE_DEPRECATION_STARTED_TITLE
      : i18n.RULE_DEPRECATED_TITLE;

  return (
    <>
      <EuiSpacer size="m" />
      <EuiCallOut color="danger" size="s" title={title} iconType="warning">
        {reason && <p>{reason}</p>}
        <p>{i18n.RULE_DEPRECATION_DELETE_INSTRUCTION}</p>
      </EuiCallOut>
      <EuiSpacer size="s" />
    </>
  );
};
