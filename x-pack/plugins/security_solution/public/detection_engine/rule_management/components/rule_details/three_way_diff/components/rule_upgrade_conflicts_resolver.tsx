/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import type { RuleUpgradeState } from '../../../../model/prebuilt_rule_upgrade';
import { FieldUpgradeConflictsResolver } from './field_upgrade_conflicts_resolver';
import type { NonUpgradeableDiffableFields } from '../../../../model/prebuilt_rule_upgrade/types';
import { inNonUpgradeableFieldName } from '../../../../model/prebuilt_rule_upgrade/constants';

type FieldDiffEntries<FieldsDiff, ExcludedFields extends keyof FieldsDiff = never> = Array<
  [
    Exclude<keyof FieldsDiff, ExcludedFields>,
    Required<FieldsDiff>[Exclude<keyof FieldsDiff, ExcludedFields>]
  ]
>;

interface RuleUpgradeConflictsResolverProps {
  ruleUpgradeState: RuleUpgradeState;
}

export function RuleUpgradeConflictsResolver({
  ruleUpgradeState,
}: RuleUpgradeConflictsResolverProps): JSX.Element {
  const fieldDiffEntries = Object.entries(ruleUpgradeState.diff.fields) as FieldDiffEntries<
    typeof ruleUpgradeState.diff.fields
  >;

  const fields = fieldDiffEntries.filter(([fieldName]) => {
    return inNonUpgradeableFieldName(fieldName) === false;
  }) as FieldDiffEntries<typeof ruleUpgradeState.diff.fields, NonUpgradeableDiffableFields>;

  fields.map(([fieldName, fieldDiff]) => (
    <FieldUpgradeConflictsResolver
      key={fieldName}
      fieldName={fieldName}
      fieldUpgradeState={ruleUpgradeState.fieldsUpgradeState[fieldName]}
      fieldThreeWayDiff={fieldDiff}
    />
  ));

  return <>{fields}</>;
}
