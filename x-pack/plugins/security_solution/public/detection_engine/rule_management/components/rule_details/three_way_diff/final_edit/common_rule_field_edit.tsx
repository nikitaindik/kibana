/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { FieldFormWrapper } from './field_form_wrapper';
import type { UpgradeableCommonFields } from '../../../../model/prebuilt_rule_upgrade/fields';
import { DescriptionEdit, descriptionSchema } from './fields/description';
import { NameEdit, nameSchema } from './fields/name';
import { TagsEdit, tagsSchema } from './fields/tags';

interface CommonRuleFieldEditProps {
  fieldName: UpgradeableCommonFields;
}

export function CommonRuleFieldEdit({ fieldName }: CommonRuleFieldEditProps) {
  switch (fieldName) {
    case 'description':
      return <FieldFormWrapper component={DescriptionEdit} fieldFormSchema={descriptionSchema} />;
    case 'name':
      return <FieldFormWrapper component={NameEdit} fieldFormSchema={nameSchema} />;
    case 'tags':
      return <FieldFormWrapper component={TagsEdit} fieldFormSchema={tagsSchema} />;
    default:
      return null; // Will be replaced with `assertUnreachable(fieldName)` once all fields are implemented
  }
}
