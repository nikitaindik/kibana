/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import { UseField } from '../../../../../../../../shared_imports';
import { NewTermsFieldsEdit } from '../../../../../../../rule_creation/components/new_terms_fields_edit';
import { useDiffableRuleDataView } from '../hooks/use_diffable_rule_data_view';
import type { DiffableRule } from '../../../../../../../../../common/api/detection_engine';
import { useTermsAggregationFields } from '../../../../../../../../common/hooks/use_terms_aggregation_fields';

interface NewTermsFieldsEditAdapterProps {
  finalDiffableRule: DiffableRule;
}

export function NewTermsFieldsEditAdapter({
  finalDiffableRule,
}: NewTermsFieldsEditAdapterProps): JSX.Element {
  const { dataView } = useDiffableRuleDataView(finalDiffableRule);
  const termsAggregationFields = useTermsAggregationFields(dataView?.fields || []);

  const componentProps = useMemo(
    () => ({
      browserFields: termsAggregationFields,
    }),
    [termsAggregationFields]
  );

  return (
    <UseField
      path="newTermsFields"
      component={NewTermsFieldsEdit}
      componentProps={componentProps}
    />
  );
}
