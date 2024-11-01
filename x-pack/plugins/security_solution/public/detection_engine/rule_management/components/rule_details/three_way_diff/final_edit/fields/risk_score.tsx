/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { type FormData, type FieldHook, UseField } from '../../../../../../../shared_imports';
import type { RiskScore } from '../../../../../../../../common/api/detection_engine';
import {
  DefaultRiskScore,
  validateDefaultRiskScore,
} from '../../../../../../rule_creation_ui/components/risk_score_mapping/default_risk_score';

export const riskScoreSchema = {
  riskScore: {
    validations: [
      {
        validator: ({ path, value }: { path: string; value: unknown }) => {
          const errorMessage = validateDefaultRiskScore(value);

          if (errorMessage) {
            return {
              path,
              message: errorMessage,
            };
          }
        },
      },
    ],
  },
};

export function RiskScoreEdit(): JSX.Element {
  return <UseField path="riskScore" component={RiskScoreEditField} />;
}

interface RiskScoreEditFieldProps {
  field: FieldHook<RiskScore>;
}

function RiskScoreEditField({ field }: RiskScoreEditFieldProps) {
  const { value, setValue, errors } = field;
  const errorMessage = errors[0]?.message;

  return <DefaultRiskScore value={value} onChange={setValue} errorMessage={errorMessage} />;
}

export function riskScoreDeserializer(defaultValue: FormData) {
  return {
    riskScore: defaultValue.risk_score,
  };
}

export function riskScoreSerializer(formData: FormData): {
  risk_score: RiskScore;
} {
  return {
    risk_score: formData.riskScore,
  };
}
