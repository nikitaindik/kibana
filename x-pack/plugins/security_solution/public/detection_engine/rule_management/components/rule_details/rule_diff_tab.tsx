/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import { omit, pick } from 'lodash';
import stringify from 'json-stable-stringify';
import {
  EuiSpacer,
  EuiPanel,
  EuiHorizontalRule,
  EuiFlexGroup,
  EuiTitle,
  EuiIconTip,
} from '@elastic/eui';
import { parseDuration } from '@kbn/alerting-plugin/common';
import type { RuleResponse } from '../../../../../common/api/detection_engine/model/rule_schema/rule_schemas.gen';
import { DiffView } from './json_diff/diff_view';
import * as i18n from './json_diff/translations';

/* Inclding these properties in diff display might be confusing to users. */
const HIDDEN_PROPERTIES = [
  /*
    By default, prebuilt rules don't have any actions or exception lists. So if a user has defined actions or exception lists for a rule, it'll show up as diff. This looks confusing as the user might think that their actions and exceptions lists will get removed after the upgrade, which is not the case - they will be preserved.
  */
  'actions',
  'exceptions_list',

  /*
    Most prebuilt rules are installed as "disabled". Once user enables a rule, it'll show as diff, which doesn't add value.
  */
  'enabled',

  /* Technical property. Hidden because it can be confused with "version" by users. */
  'revision',

  /*
    This info is not yet exposed by prebuilt rules.
    Ticket to add support: https://github.com/elastic/detection-rules/issues/2826
  */
  'updated_at',
];

const sortAndStringifyJson = (jsObject: Record<string, unknown>): string =>
  stringify(jsObject, { space: 2 });

/**
 * Normalizes the representation of the 'from' property in rule responses.
 *
 * Helpful when different time units represent the same duration. For instance, 'now-1m' and 'now-60s'
 * both indicate a duration of one minute. If the durations represented by the 'from' properties in
 * oldRule and newRule are the same, the function updates the oldRule's 'from' property to match
 * that of newRule. This would ensure that the 'from' property is not shown as a diff in the UI.
 *
 * @param {RuleResponse} oldRule - The original rule.
 * @param {RuleResponse} newRule - The new rule to compare with.
 * @returns {RuleResponse} - The updated rule object with a potentially normalized 'from' property.
 */
const normalizeFromProperty = (oldRule: RuleResponse, newRule: RuleResponse): RuleResponse => {
  let oldRuleFrom = oldRule.from;

  if (
    oldRule.from.startsWith('now-') &&
    newRule.from.startsWith('now-') &&
    parseDuration(oldRule.from.slice('now-'.length)) ===
      parseDuration(newRule.from.slice('now-'.length))
  ) {
    oldRuleFrom = newRule.from;
  }

  return { ...oldRule, from: oldRuleFrom };
};

interface RuleDiffTabProps {
  oldRule: RuleResponse;
  newRule: RuleResponse;
}

export const RuleDiffTab = ({ oldRule, newRule }: RuleDiffTabProps) => {
  const [oldSource, newSource] = useMemo(() => {
    const visibleOldRuleProperties = omit(
      /* Only compare properties that are present in the update. */
      pick(normalizeFromProperty(oldRule, newRule), Object.keys(newRule)),
      ...HIDDEN_PROPERTIES
    );
    const visibleNewRuleProperties = omit(newRule, ...HIDDEN_PROPERTIES);

    return [
      sortAndStringifyJson(visibleOldRuleProperties),
      sortAndStringifyJson(visibleNewRuleProperties),
    ];
  }, [oldRule, newRule]);

  return (
    <>
      <EuiSpacer size="m" />
      <EuiPanel color="transparent" hasBorder>
        <EuiFlexGroup justifyContent="spaceBetween" alignItems="center">
          <EuiFlexGroup alignItems="baseline" gutterSize="xs">
            <EuiIconTip
              color="subdued"
              content={i18n.BASE_VERSION_DESCRIPTION}
              type="iInCircle"
              size="m"
              display="block"
            />
            <EuiTitle size="xxxs">
              <h6>{i18n.BASE_VERSION}</h6>
            </EuiTitle>
          </EuiFlexGroup>
          <EuiFlexGroup alignItems="baseline" gutterSize="xs">
            <EuiIconTip
              color="subdued"
              content={i18n.UPDATED_VERSION_DESCRIPTION}
              type="iInCircle"
              size="m"
            />
            <EuiTitle size="xxxs">
              <h6>{i18n.UPDATED_VERSION}</h6>
            </EuiTitle>
          </EuiFlexGroup>
        </EuiFlexGroup>
        <EuiHorizontalRule margin="s" size="full" />
        <DiffView oldSource={oldSource} newSource={newSource} />
      </EuiPanel>
    </>
  );
};
