/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import type { DiffableThreatMatchFields } from '../../../../../../../common/api/detection_engine';
import { FieldFormWrapper } from './field_form_wrapper';
import {
  KqlQueryEdit,
  kqlQuerySchema,
  kqlQuerySerializer,
  kqlQueryDeserializer,
} from './fields/kql_query';

interface ThreatMatchRuleFieldEditProps {
  fieldName: keyof DiffableThreatMatchFields;
}

export function ThreatMatchRuleFieldEdit({ fieldName }: ThreatMatchRuleFieldEditProps) {
  switch (fieldName) {
    case 'kql_query':
      return (
        <FieldFormWrapper
          component={KqlQueryEdit}
          fieldFormSchema={kqlQuerySchema}
          serializer={kqlQuerySerializer}
          deserializer={kqlQueryDeserializer}
        />
      );
    default:
      return null; // Will be replaced with `assertUnreachable(fieldName)` once all fields are implemented
  }
}
