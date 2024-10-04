/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import { EuiButtonEmpty, EuiFlexGroup } from '@elastic/eui';
import { useForm, Form } from '../../../../../../shared_imports';
import type { FormSchema, FormData } from '../../../../../../shared_imports';
import type {
  DiffableAllFields,
  DiffableRule,
} from '../../../../../../../common/api/detection_engine';
import { useFinalEditContext } from './final_edit_context';
import { useDiffableRuleContext } from '../diffable_rule_context';

interface FieldFormWrapperProps {
  component: React.ComponentType<{
    finalDiffableRule: DiffableRule;
    setValidity: (isValid: boolean) => void;
    setFieldValue: (fieldName: string, fieldValue: unknown) => void;
  }>;
  fieldFormSchema: FormSchema;
  deserializer: (fieldValue: FormData, finalDiffableRule: DiffableRule) => FormData;
  serializer: (formData: FormData) => FormData;
}

/**
 * FieldFormWrapper component manages form state and renders "Save" and "Cancel" buttons.
 *
 * @param {Object} props - Component props.
 * @param {React.ComponentType} props.component - Field component to be wrapped.
 * @param {FormSchema} props.fieldFormSchema - Configuration schema for the field.
 * @param {Function} props.deserializer - Deserializer prepares initial form data. It converts field value from a DiffableRule format to a format used by the form.
 * @param {Function} props.serializer - Serializer prepares form data for submission. It converts form data back to a DiffableRule format.
 */
export function FieldFormWrapper({
  component: FieldComponent,
  fieldFormSchema,
  deserializer,
  serializer,
}: FieldFormWrapperProps) {
  const { fieldName, setReadOnlyMode } = useFinalEditContext();

  const { finalDiffableRule, setRuleFieldResolvedValue } = useDiffableRuleContext();

  const deserialize = (defaultValue: FormData): FormData => {
    if (deserializer) {
      const rule = finalDiffableRule as Record<string, unknown>;
      const fieldValue = rule[fieldName] as FormData;
      return deserializer(fieldValue, finalDiffableRule);
    }

    return defaultValue;
  };

  const { form } = useForm({
    schema: fieldFormSchema,
    defaultValue: getDefaultValue(fieldName, finalDiffableRule),
    deserializer: deserialize,
    serializer,
    onSubmit: async (formData, isValid) => {
      if (isValid) {
        setRuleFieldResolvedValue({
          fieldName: fieldName as keyof DiffableAllFields,
          resolvedValue: formData[fieldName],
        });
        setReadOnlyMode();
      }
    },
  });

  const [validity, setValidity] = useState<boolean | undefined>(undefined);

  const isValid = validity === undefined ? form.isValid : validity;

  return (
    <>
      <EuiFlexGroup justifyContent="flexEnd">
        <EuiButtonEmpty iconType="cross" onClick={setReadOnlyMode}>
          {'Cancel'}
        </EuiButtonEmpty>
        <EuiButtonEmpty iconType="save" onClick={form.submit} disabled={isValid === false}>
          {'Save'}
        </EuiButtonEmpty>
      </EuiFlexGroup>
      <Form form={form}>
        <FieldComponent
          finalDiffableRule={finalDiffableRule}
          setValidity={setValidity}
          setFieldValue={form.setFieldValue}
        />
      </Form>
    </>
  );
}

function getDefaultValue(fieldName: string, finalDiffableRule: DiffableRule): FormData {
  const rule = finalDiffableRule as Record<string, unknown>;

  return { [fieldName]: rule[fieldName] };
}
