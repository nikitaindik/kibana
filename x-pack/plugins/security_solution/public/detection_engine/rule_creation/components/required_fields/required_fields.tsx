/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiFormRow, EuiSpacer, EuiText } from '@elastic/eui';
import type { EuiComboBoxOptionOption } from '@elastic/eui';
import type { DataViewFieldBase } from '@kbn/es-query';
import { UseArray, useFormData } from '../../../../shared_imports';
import { RequiredFieldRow } from './required_fields_row';
import * as ruleDetailsI18n from '../../../rule_management/components/rule_details/translations';
import * as i18n from './translations';

import type { RequiredFieldWithOptionalEcs } from './types';

interface RequiredFieldsProps {
  path: string;
  indexPatternFields?: DataViewFieldBase[];
}

export const RequiredFields = ({ path, indexPatternFields = [] }: RequiredFieldsProps) => {
  const useFormDataResult = useFormData();
  const [_formData] = useFormDataResult;

  return (
    <UseArray path={path} initialNumberOfItems={0}>
      {({ items, addItem, removeItem, form }) => {
        const formData = form.getFormData();
        const fieldValue: RequiredFieldWithOptionalEcs[] = formData[path] ?? [];

        const selectedFieldNames = fieldValue.map(({ name }) => name);

        const fieldsWithTypes = indexPatternFields.filter(
          (indexPatternField) => indexPatternField.esTypes && indexPatternField.esTypes.length > 0
        );

        const allFieldNames = fieldsWithTypes.map(({ name }) => name);
        const availableFieldNames = allFieldNames.filter(
          (name) => !selectedFieldNames.includes(name)
        );

        const availableNameOptions: Array<EuiComboBoxOptionOption<undefined>> =
          availableFieldNames.map((availableFieldName) => ({
            label: availableFieldName,
          }));

        const typesByFieldName: Record<string, string[]> = fieldsWithTypes.reduce(
          (accumulator, browserField) => {
            if (browserField.esTypes) {
              accumulator[browserField.name] = browserField.esTypes;
            }
            return accumulator;
          },
          {} as Record<string, string[]>
        );

        const isEmptyRowDisplayed = !!fieldValue.find(({ name }) => name === '');

        const areIndexPatternFieldsAvailable = indexPatternFields.length > 0;

        const nameWarnings = fieldValue.reduce<Record<string, string>>((warnings, { name }) => {
          if (areIndexPatternFieldsAvailable && name !== '' && !allFieldNames.includes(name)) {
            warnings[name] = `Field "${name}" is not found within specified index patterns`;
          }
          return warnings;
        }, {});

        const typeWarnings = fieldValue.reduce<Record<string, string>>(
          (warnings, { name, type }) => {
            if (
              areIndexPatternFieldsAvailable &&
              name !== '' &&
              !typesByFieldName[name]?.includes(type)
            ) {
              warnings[
                name
              ] = `Field "${name}" with type "${type}" is not found within specified index patterns`;
            }
            return warnings;
          },
          {}
        );

        const getWarnings = (name: string) => ({
          nameWarning: nameWarnings[name] || '',
          typeWarning: typeWarnings[name] || '',
        });

        const hasWarnings =
          Object.keys(nameWarnings).length > 0 || Object.keys(typeWarnings).length > 0;

        return (
          <>
            {hasWarnings && (
              <EuiCallOut
                title={i18n.REQUIRED_FIELDS_GENERAL_WARNING_TITLE}
                color="warning"
                iconType="help"
              >
                <p>{i18n.REQUIRED_FIELDS_GENERAL_WARNING_DESCRIPTION}</p>
              </EuiCallOut>
            )}
            <EuiSpacer size="m" />
            <EuiFormRow
              fullWidth
              label={ruleDetailsI18n.REQUIRED_FIELDS_FIELD_LABEL}
              labelAppend={
                <EuiText color="subdued" size="xs">
                  {i18n.OPTIONAL}
                </EuiText>
              }
              helpText={i18n.REQUIRED_FIELDS_HELP_TEXT}
              hasChildLabel={false}
              labelType="legend"
            >
              <>
                {items.map((item) => (
                  <RequiredFieldRow
                    key={item.id}
                    item={item}
                    removeItem={removeItem}
                    getWarnings={getWarnings}
                    typesByFieldName={typesByFieldName}
                    availableFieldNames={availableFieldNames}
                  />
                ))}

                <EuiSpacer size="s" />
                <EuiButtonEmpty
                  size="xs"
                  iconType="plusInCircle"
                  onClick={addItem}
                  isDisabled={availableNameOptions.length === 0 || isEmptyRowDisplayed}
                >
                  {i18n.ADD_REQUIRED_FIELD}
                </EuiButtonEmpty>
              </>
            </EuiFormRow>
          </>
        );
      }}
    </UseArray>
  );
};
