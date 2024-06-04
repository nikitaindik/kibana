/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RulesClient } from '@kbn/alerting-plugin/server';
import type { RuleCreateProps } from '../../../../../../common/api/detection_engine';
import type { MlAuthz } from '../../../../machine_learning/authz';
import type { RuleAlertType } from '../../../rule_schema';
import { withSecuritySpan } from '../../../../../utils/with_security_span';

import { _validateMlAuth, _createRule } from './utils';

export interface CreateCustomRuleProps {
  params: RuleCreateProps;
}

export const createCustomRule = async (
  rulesClient: RulesClient,
  createCustomRulePayload: CreateCustomRuleProps,
  mlAuthz: MlAuthz
): Promise<RuleAlertType> =>
  withSecuritySpan('DetectionRulesClient.createCustomRule', async () => {
    const { params } = createCustomRulePayload;
    await _validateMlAuth(mlAuthz, params.type);

    const rule = await _createRule(rulesClient, params, { immutable: false });
    return rule;
  });
