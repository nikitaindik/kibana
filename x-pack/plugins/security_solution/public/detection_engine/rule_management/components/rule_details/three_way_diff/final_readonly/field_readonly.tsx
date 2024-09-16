/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import {
  DiffableCommonFields,
  DiffableCustomQueryFields,
} from '../../../../../../../common/api/detection_engine';
import type { DiffableRule } from '../../../../../../../common/api/detection_engine';
import { DataSourceReadOnly } from './fields/data_source/data_source';
import { NameReadOnly } from './fields/name/name';
import { TagsReadOnly } from './fields/tags/tags';
import { DescriptionReadOnly } from './fields/description/description';
import { assertUnreachable } from '../../../../../../../common/utility_types';

function CustomQueryRuleFieldReadOnly({
  fieldName,
  finalDiffableRule,
}: {
  fieldName: keyof DiffableCustomQueryFields;
  finalDiffableRule: DiffableCustomQueryFields;
}) {
  switch (fieldName) {
    case 'data_source':
      return <DataSourceReadOnly dataSource={finalDiffableRule.data_source} />;
    // ... More custom query fields
    default:
      return assertUnreachable(fieldName);
  }
}

function CommonRuleFieldsReadOnly({
  fieldName,
  finalDiffableRule,
}: {
  fieldName: keyof DiffableCommonFields;
  finalDiffableRule: DiffableCommonFields;
}) {
  switch (fieldName) {
    case 'name':
      return <NameReadOnly name={finalDiffableRule.name} />;
    case 'tags':
      return <TagsReadOnly tags={finalDiffableRule.tags} />;
    case 'description':
      return <DescriptionReadOnly description={finalDiffableRule.description} />;
    // ... More common fields
    default:
      return assertUnreachable(finalDiffableRule);
  }
}

interface FieldReadOnlyProps {
  fieldName: string;
  finalDiffableRule: DiffableRule;
}

export function FieldReadOnly({ fieldName, finalDiffableRule }: FieldReadOnlyProps) {
  /* First try to handle common fields */
  const isCommonFieldParseResult = DiffableCommonFields.keyof().safeParse(fieldName);

  if (isCommonFieldParseResult.success) {
    return (
      <CommonRuleFieldsReadOnly
        fieldName={isCommonFieldParseResult.data}
        finalDiffableRule={finalDiffableRule}
      />
    );
  }

  /* If it's not a common field, then it's a type-specific field */
  try {
    switch (finalDiffableRule.type) {
      case 'query':
        return (
          <CustomQueryRuleFieldReadOnly
            fieldName={DiffableCustomQueryFields.keyof().parse(fieldName)}
            finalDiffableRule={finalDiffableRule}
          />
        );
      case 'saved_query':
        return null;
      case 'eql':
        return null;
      case 'esql':
        return null;
      case 'threat_match':
        return null;
      case 'threshold':
        return null;
      case 'machine_learning':
        return null;
      case 'new_terms':
        return null;
      default:
        return assertUnreachable(finalDiffableRule);
    }
  } catch (error) {
    return null;
  }
}
