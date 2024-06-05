/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RulesClient } from '@kbn/alerting-plugin/server';
import type { MlAuthz } from '../../../../machine_learning/authz';
import type { RuleAlertType, RuleParams } from '../../../rule_schema';
import { withSecuritySpan } from '../../../../../utils/with_security_span';
import type { RuleToImport } from '../../../../../../common/api/detection_engine';
import { createBulkErrorObject } from '../../../routes/utils';
import { convertCreateAPIToInternalSchema } from '../../normalization/rule_converters';

import { _validateMlAuth, _updateRule } from './utils';

import { readRules } from './read_rules';

interface ImportRuleOptions {
  allowMissingConnectorSecrets?: boolean;
}

export interface ImportRuleProps {
  ruleToImport: RuleToImport;
  overwriteRules?: boolean;
  options: ImportRuleOptions;
}

export const importRule = async (
  rulesClient: RulesClient,
  importRulePayload: ImportRuleProps,
  mlAuthz: MlAuthz
): Promise<RuleAlertType> =>
  withSecuritySpan('DetectionRulesClient.importRule', async () => {
    const { ruleToImport, overwriteRules, options } = importRulePayload;

    await _validateMlAuth(mlAuthz, ruleToImport.type);

    const existingRule = await readRules({
      rulesClient,
      ruleId: ruleToImport.rule_id,
      id: undefined,
    });

    if (!existingRule) {
      const internalRule = convertCreateAPIToInternalSchema(ruleToImport, {
        immutable: false,
      });

      const rule = await rulesClient.create<RuleParams>({
        data: internalRule,
        allowMissingConnectorSecrets: options.allowMissingConnectorSecrets,
      });

      return rule;
    } else if (existingRule && overwriteRules) {
      return _updateRule(rulesClient, {
        existingRule,
        ruleUpdate: ruleToImport,
      });
    } else {
      throw createBulkErrorObject({
        ruleId: existingRule.params.ruleId,
        statusCode: 409,
        message: `rule_id: "${existingRule.params.ruleId}" already exists`,
      });
    }
  });
