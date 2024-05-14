/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiFormRow, EuiSpacer, EuiText } from '@elastic/eui';
import type { DataViewFieldBase } from '@kbn/es-query';
import type { RequiredFieldInput } from '../../../../../common/api/detection_engine';
import { UseArray, useFormData } from '../../../../shared_imports';
import type { FormHook, ArrayItem } from '../../../../shared_imports';
import { RequiredFieldsHelpInfo } from './required_fields_help_info';
import { RequiredFieldRow } from './required_fields_row';
import * as i18n from './translations';

interface RequiredFieldsComponentProps {
  path: string;
  indexPatternFields?: DataViewFieldBase[];
  isIndexPatternLoading?: boolean;
}

const RequiredFieldsComponent = ({
  path,
  indexPatternFields = [],
  isIndexPatternLoading = false,
}: RequiredFieldsComponentProps) => {
  return (
    <UseArray path={path} initialNumberOfItems={0}>
      {({ items, addItem, removeItem, form }) => (
        <RequiredFieldsList
          items={items}
          addItem={addItem}
          removeItem={removeItem}
          indexPatternFields={indexPatternFields}
          isIndexPatternLoading={isIndexPatternLoading}
          path={path}
          form={form}
        />
      )}
    </UseArray>
  );
};

interface RequiredFieldsListProps {
  items: ArrayItem[];
  addItem: () => void;
  removeItem: (id: number) => void;
  indexPatternFields: DataViewFieldBase[];
  isIndexPatternLoading: boolean;
  path: string;
  form: FormHook;
}

const RequiredFieldsList = ({
  items,
  addItem,
  removeItem,
  indexPatternFields,
  isIndexPatternLoading,
  path,
  form,
}: RequiredFieldsListProps) => {
  /*
    This component should only re-render when either the "index" form field (index patterns) or the required fields change. 

    By default, the `useFormData` hook triggers a re-render whenever any form field changes.
    It also allows optimization by passing a "watch" array of field names. The component then only re-renders when these specified fields change.

    Hovewer, it doesn't work with fields created using the `UseArray` component.
    In `useFormData`, these array fields are stored as "flattened" objects with numbered keys, like { "requiredFields[0]": { ... }, "requiredFields[1]": { ... } }.
    The "watch" feature of `useFormData` only works if you pass these "flattened" field names, such as ["requiredFields[0]", "requiredFields[1]", ...], not just "requiredFields".

    To work around this, we manually construct a list of "flattened" field names to watch, based on the current state of the form.
    This is a temporary solution and ideally, `useFormData` should be updated to handle this scenario.
  */

  /* `form.getFields` returns an object with "flattened" keys like "requiredFields[0]", "requiredFields[1]"... */
  const flattenedFieldNames = Object.keys(form.getFields());
  const flattenedRequiredFieldsFieldNames = flattenedFieldNames.filter((key) =>
    key.startsWith(path)
  );

  /*
    Not using "watch" for the initial render, to let row components render and initialize form fields.
    Then we can use the "watch" feature to track their changes.
  */
  const hasRenderedInitially = flattenedRequiredFieldsFieldNames.length > 0;
  const fieldsToWatch = hasRenderedInitially ? ['index', ...flattenedRequiredFieldsFieldNames] : [];

  const [formData] = useFormData({ watch: fieldsToWatch });

  const fieldValue: RequiredFieldInput[] = formData[path] ?? [];

  const fieldsWithTypes = useMemo(
    () =>
      indexPatternFields.filter((indexPatternField) => Boolean(indexPatternField.esTypes?.length)),
    [indexPatternFields]
  );

  const allFieldNames = useMemo(() => fieldsWithTypes.map(({ name }) => name), [fieldsWithTypes]);

  const selectedFieldNames = fieldValue.map(({ name }) => name);

  const availableFieldNames = allFieldNames.filter((name) => !selectedFieldNames.includes(name));

  const typesByFieldName: Record<string, string[]> = useMemo(
    () =>
      fieldsWithTypes.reduce((accumulator, browserField) => {
        if (browserField.esTypes) {
          accumulator[browserField.name] = browserField.esTypes;
        }
        return accumulator;
      }, {} as Record<string, string[]>),
    [fieldsWithTypes]
  );

  const nameWarnings = fieldValue
    /* Not creating a warning for empty "name" value */
    .filter(({ name }) => name !== '')
    .reduce<Record<string, string>>((warnings, { name }) => {
      if (!isIndexPatternLoading && !allFieldNames.includes(name)) {
        warnings[name] = i18n.FIELD_NAME_NOT_FOUND_WARNING(name);
      }
      return warnings;
    }, {});

  const typeWarnings = fieldValue
    /* Not creating a warning for "type" if there's no "name" value */
    .filter(({ name }) => name !== '')
    .reduce<Record<string, string>>((warnings, { name, type }) => {
      if (
        !isIndexPatternLoading &&
        typesByFieldName[name] &&
        !typesByFieldName[name].includes(type)
      ) {
        warnings[`${name}-${type}`] = i18n.FIELD_TYPE_NOT_FOUND_WARNING(name, type);
      }
      return warnings;
    }, {});

  const getWarnings = ({ name, type }: { name: string; type: string }) => ({
    nameWarning: nameWarnings[name] || '',
    typeWarning: typeWarnings[`${name}-${type}`] || '',
  });

  const hasEmptyFieldName = fieldValue.some(({ name }) => name === '');

  const hasWarnings = Object.keys(nameWarnings).length > 0 || Object.keys(typeWarnings).length > 0;

  return (
    <>
      {hasWarnings && (
        <EuiCallOut
          title={i18n.REQUIRED_FIELDS_GENERAL_WARNING_TITLE}
          color="warning"
          iconType="help"
          data-test-subj="requiredFieldsGeneralWarning"
        >
          <p>{i18n.REQUIRED_FIELDS_GENERAL_WARNING_DESCRIPTION}</p>
        </EuiCallOut>
      )}
      <EuiSpacer size="m" />
      <EuiFormRow
        fullWidth
        label={
          <>
            {i18n.REQUIRED_FIELDS_LABEL}
            <RequiredFieldsHelpInfo />
          </>
        }
        labelAppend={
          <EuiText color="subdued" size="xs">
            {i18n.OPTIONAL}
          </EuiText>
        }
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
              parentFieldPath={path}
            />
          ))}

          <EuiSpacer size="s" />
          <EuiButtonEmpty
            size="xs"
            iconType="plusInCircle"
            onClick={addItem}
            isDisabled={isIndexPatternLoading || hasEmptyFieldName}
            data-test-subj="addRequiredFieldButton"
          >
            {i18n.ADD_REQUIRED_FIELD}
          </EuiButtonEmpty>
        </>
      </EuiFormRow>
    </>
  );
};

export const RequiredFields = React.memo(RequiredFieldsComponent);
