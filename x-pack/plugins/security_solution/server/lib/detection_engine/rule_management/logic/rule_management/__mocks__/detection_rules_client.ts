/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { IDetectionRulesClient } from '../detection_rules_client';
import type { RulesClient } from '@kbn/alerting-plugin/server';
import type { RuleObjectId } from '../../../../../../../common/api/detection_engine';
import type { RuleAlertType } from '../../../../rule_schema';

export type DetectionRulesClientMock = jest.Mocked<IDetectionRulesClient>;

const createDetectionRulesClientMock = () => {
  const mocked: DetectionRulesClientMock = {
    createCustomRule: jest.fn(),
    createPrebuiltRule: jest.fn(),
    updateRule: jest.fn(),
    patchRule: jest.fn(),
    deleteRule: jest.fn(),
    upgradePrebuiltRule: jest.fn(),
    importRule: jest.fn(),
  };
  return mocked;
};

export const detectionRulesClientMock: {
  create: () => DetectionRulesClientMock;
} = {
  create: createDetectionRulesClientMock,
};

/* Mocks for internal methods */
export const _toggleRuleEnabledOnUpdate: jest.Mock<
  (rulesClient: RulesClient, existingRule: RuleAlertType, enabled: boolean) => Promise<void>
> = jest.fn();

export const _deleteRule: jest.Mock<
  (rulesClient: RulesClient, deleteRulePayload: { ruleId: RuleObjectId }) => Promise<void>
> = jest.fn();
