/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import type { RuleUpgradeState } from '../../../../rule_management_ui/components/rules_table/upgrade_prebuilt_rules_table/use_prebuilt_rules_upgrade_state';
import {
  UtilityBar,
  UtilityBarGroup,
  UtilityBarSection,
  UtilityBarText,
} from '../../../../../common/components/utility_bar';
import * as i18n from './translations';

interface UpgradeInfoBarProps {
  ruleUpgradeState: RuleUpgradeState;
}

export function UpgradeInfoBar({ ruleUpgradeState }: UpgradeInfoBarProps): JSX.Element {
  const numOfFieldsWithUpdates = ruleUpgradeState.diff.num_fields_with_updates;
  const numOfConflicts = ruleUpgradeState.diff.num_fields_with_conflicts;

  return (
    <UtilityBar>
      <UtilityBarSection>
        <UtilityBarGroup>
          <UtilityBarText dataTestSubj="showingRules">
            {i18n.NUM_OF_FIELDS_WITH_UPDATES(numOfFieldsWithUpdates)}
          </UtilityBarText>
        </UtilityBarGroup>
        <UtilityBarGroup>
          <UtilityBarText dataTestSubj="showingRules">
            {i18n.NUM_OF_CONFLICTS(numOfConflicts)}
          </UtilityBarText>
        </UtilityBarGroup>
      </UtilityBarSection>
      <UtilityBarSection>
        <UtilityBarGroup>
          <i18n.RuleUpgradeHelper />
        </UtilityBarGroup>
      </UtilityBarSection>
    </UtilityBar>
  );
}
