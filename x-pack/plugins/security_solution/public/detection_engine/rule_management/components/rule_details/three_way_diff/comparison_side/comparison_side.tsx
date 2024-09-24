/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import { VersionsPicker } from '../versions_picker/versions_picker';
import type { Version } from '../versions_picker/constants';
import { SelectedVersions } from '../versions_picker/constants';
import { pickFieldValueForVersion } from './utils';
import type {
  DiffableAllFields,
  ThreeWayDiff,
} from '../../../../../../../common/api/detection_engine';
import { getSubfieldChanges } from './get_subfield_changes';
import { SubfieldChanges } from './subfield_changes';
import { SideHeader } from '../components/side_header';

interface ComparisonSideProps<FieldName extends keyof DiffableAllFields> {
  fieldName: FieldName;
  fieldThreeWayDiff: ThreeWayDiff<DiffableAllFields[FieldName]>;
  finalFieldValue: DiffableAllFields[FieldName];
}

export function ComparisonSide<FieldName extends keyof DiffableAllFields>({
  fieldName,
  fieldThreeWayDiff,
  finalFieldValue,
}: ComparisonSideProps<FieldName>) {
  const [selectedVersions, setSelectedVersions] = useState<SelectedVersions>(
    SelectedVersions.CurrentFinal
  );

  const [oldVersionType, newVersionType] = selectedVersions.split('_') as [Version, Version];

  const oldFieldValue = pickFieldValueForVersion(
    oldVersionType,
    fieldThreeWayDiff,
    finalFieldValue
  );

  const newFieldValue = pickFieldValueForVersion(
    newVersionType,
    fieldThreeWayDiff,
    finalFieldValue
  );

  const subfieldChanges = getSubfieldChanges(fieldName, oldFieldValue, newFieldValue);

  return (
    <>
      <SideHeader>
        <VersionsPicker
          hasBaseVersion={fieldThreeWayDiff.has_base_version}
          selectedVersions={selectedVersions}
          onChange={setSelectedVersions}
        />
      </SideHeader>
      <SubfieldChanges fieldName={fieldName} subfieldChanges={subfieldChanges} />
    </>
  );
}
