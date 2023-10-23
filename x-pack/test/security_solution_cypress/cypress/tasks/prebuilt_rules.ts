/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { capitalize } from 'lodash';
import type { ThreatMapping } from '@kbn/securitysolution-io-ts-alerting-types';
import type { Module } from '@kbn/ml-plugin/common/types/modules';
import type { AlertSuppression } from '@kbn/security-solution-plugin/common/api/detection_engine/model/rule_schema/specific_attributes/query_attributes';
import type { Filter } from '@kbn/es-query';
import type { PrebuiltRuleAsset } from '@kbn/security-solution-plugin/server/lib/detection_engine/prebuilt_rules';
import { RULES_ADD_PATH, RULES_UPDATES } from '@kbn/security-solution-plugin/common/constants';
import {
  ADD_ELASTIC_RULES_BTN,
  ADD_ELASTIC_RULES_TABLE,
  ALERT_SUPPRESSION_DURATION_TITLE,
  ALERT_SUPPRESSION_DURATION_VALUE,
  ALERT_SUPPRESSION_FIELD_TITLE,
  ALERT_SUPPRESSION_FIELD_VALUE,
  ALERT_SUPPRESSION_GROUP_BY_TITLE,
  ALERT_SUPPRESSION_GROUP_BY_VALUE_ITEM,
  ANOMALY_THRESHOLD_TITLE,
  ANOMALY_THRESHOLD_VALUE,
  AUTHOR_PROPERTY_TITLE,
  AUTHOR_PROPERTY_VALUE_ITEM,
  BUILDING_BLOCK_TITLE,
  BUILDING_BLOCK_VALUE,
  CUSTOM_QUERY_TITLE,
  CUSTOM_QUERY_VALUE,
  DATA_VIEW_ID_TITLE,
  DATA_VIEW_ID_VALUE,
  DATA_VIEW_INDEX_PATTERN_TITLE,
  DATA_VIEW_INDEX_PATTERN_VALUE,
  EQL_QUERY_TITLE,
  EQL_QUERY_VALUE,
  ESQL_QUERY_TITLE,
  ESQL_QUERY_VALUE,
  FALSE_POSITIVES_TITLE,
  FALSE_POSITIVES_VALUE_ITEM,
  FILTERS_TITLE,
  FILTERS_VALUE_ITEM,
  FLYOUT_CLOSE_BTN,
  FROM_TITLE,
  FROM_VALUE,
  getInstallSingleRuleLoadingSpinnerByRuleId,
  getUpgradeSingleRuleLoadingSpinnerByRuleId,
  INDEX_TITLE,
  INDEX_VALUE_ITEM,
  INSTALL_PREBUILT_RULE_PREVIEW,
  INTERVAL_TITLE,
  INTERVAL_VALUE,
  INVESTIGATION_FIELDS_TITLE,
  INVESTIGATION_FIELDS_VALUE_ITEM,
  LICENSE_TITLE,
  LICENSE_VALUE,
  MACHINE_LEARNING_JOB_TITLE,
  MACHINE_LEARNING_JOB_VALUE,
  NEW_TERMS_FIELDS_TITLE,
  NEW_TERMS_FIELDS_VALUE_ITEM,
  NEW_TERMS_WINDOW_SIZE_TITLE,
  NEW_TERMS_WINDOW_SIZE_VALUE,
  REFERENCES_TITLE,
  REFERENCES_VALUE_ITEM,
  RELATED_INTEGRATIONS_TITLE,
  RELATED_INTEGRATIONS_VALUE,
  REQUIRED_FIELDS_PROPERTY_TITLE,
  REQUIRED_FIELDS_PROPERTY_VALUE_ITEM,
  RISK_SCORE_MAPPING_TITLE,
  RISK_SCORE_MAPPING_VALUE_FIELD_NAME,
  RISK_SCORE_MAPPING_VALUE_OVERRIDE_NAME,
  RISK_SCORE_TITLE,
  RISK_SCORE_VALUE,
  RULE_NAME_OVERRIDE_TITLE,
  RULE_NAME_OVERRIDE_VALUE,
  RULES_MANAGEMENT_TABLE,
  RULES_UPDATES_TAB,
  RULES_UPDATES_TABLE,
  SAVED_QUERY_CONTENT_TITLE,
  SAVED_QUERY_CONTENT_VALUE,
  SAVED_QUERY_FILTERS_TITLE,
  SAVED_QUERY_FILTERS_VALUE,
  SAVED_QUERY_NAME_TITLE,
  SAVED_QUERY_NAME_VALUE,
  SEVERITY_MAPPING_TITLE,
  SEVERITY_MAPPING_VALUE_FIELD,
  SEVERITY_MAPPING_VALUE_SEVERITY,
  SEVERITY_MAPPING_VALUE_VALUE,
  SEVERITY_TITLE,
  SEVERITY_VALUE,
  TAGS_PROPERTY_TITLE,
  TAGS_PROPERTY_VALUE_ITEM,
  THREAT_FILTERS_TITLE,
  THREAT_FILTERS_VALUE_ITEM,
  THREAT_INDEX_TITLE,
  THREAT_INDEX_VALUE_ITEM,
  THREAT_MAPPING_TITLE,
  THREAT_MAPPING_VALUE,
  THREAT_QUERY_TITLE,
  THREAT_QUERY_VALUE,
  THREAT_TACTIC,
  THREAT_TITLE,
  THRESHOLD_TITLE,
  THRESHOLD_VALUE,
  TIMELINE_TEMPLATE_TITLE,
  TIMELINE_TEMPLATE_VALUE,
  TIMESTAMP_OVERRIDE_TITLE,
  TIMESTAMP_OVERRIDE_VALUE,
  TOASTER,
  UPDATE_PREBUILT_RULE_PREVIEW,
} from '../screens/alerts_detection_rules';
import { RULE_MANAGEMENT_PAGE_BREADCRUMB } from '../screens/breadcrumbs';
import type { SAMPLE_PREBUILT_RULE } from './api_calls/prebuilt_rules';

export const addElasticRulesButtonClick = () => {
  cy.get(ADD_ELASTIC_RULES_BTN).click();
  cy.location('pathname').should('include', RULES_ADD_PATH);
};

export const ruleUpdatesTabClick = () => {
  cy.get(RULES_UPDATES_TAB).click();
  cy.location('pathname').should('include', RULES_UPDATES);
};

export const assertInstallationRequestIsComplete = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  for (const rule of rules) {
    cy.get(getInstallSingleRuleLoadingSpinnerByRuleId(rule['security-rule'].rule_id)).should(
      'exist'
    );
  }
  for (const rule of rules) {
    cy.get(getInstallSingleRuleLoadingSpinnerByRuleId(rule['security-rule'].rule_id)).should(
      'not.exist'
    );
  }
};

export const assertUpgradeRequestIsComplete = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  for (const rule of rules) {
    cy.get(getUpgradeSingleRuleLoadingSpinnerByRuleId(rule['security-rule'].rule_id)).should(
      'exist'
    );
  }
  for (const rule of rules) {
    cy.get(getUpgradeSingleRuleLoadingSpinnerByRuleId(rule['security-rule'].rule_id)).should(
      'not.exist'
    );
  }
};

/**
 * Assert that when the rule installation succeeds, the toast is shown with the right message
 * -confirming the succesful install- and subsequently check that the rules available for installation
 * are not present in the Add Elastic Rules table anymore
 */
export const assertInstallationSuccess = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  const rulesString = rules.length > 1 ? 'rules' : 'rule';
  const toastMessage = `${rules.length} ${rulesString} installed successfully.`;
  cy.get(TOASTER).should('be.visible').should('have.text', toastMessage);

  // Go back to rules table and assert that the rules are installed
  cy.get(RULE_MANAGEMENT_PAGE_BREADCRUMB).click();
  for (const rule of rules) {
    cy.get(RULES_MANAGEMENT_TABLE).contains(rule['security-rule'].name);
  }
};

/**
 * Assert that when the rule installation fails, the toast is shown with the right message
 * -notifying that the installation failed- and subsequently check that the rules available for installation
 * are still present in the Rule Update table
 */
export const assertInstallationFailure = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  const rulesString = rules.length > 1 ? 'rules' : 'rule';
  const toastMessage = `${rules.length} ${rulesString} failed to install.`;
  cy.get(TOASTER).should('be.visible').should('have.text', toastMessage);

  // Check rules are still available for install
  for (const rule of rules) {
    cy.get(ADD_ELASTIC_RULES_TABLE).contains(rule['security-rule'].name);
  }
};

export const interceptInstallationRequestToFail = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  cy.intercept('POST', '/internal/detection_engine/prebuilt_rules/installation/_perform', {
    body: {
      summary: {
        succeeded: [],
        skipped: [],
        failed: rules.length,
      },
    },
    delay: 500, // Add delay to give Cypress time to find the loading spinner
  }).as('installPrebuiltRules');
};

/**
 * Assert that when the rule version upgrade succeeds, the toast is shown with the right message
 * -confirming the succesful upgrade- and subsequently check that the rules available for upgrade
 * are not present in the Rule Update table anymore
 */
export const assertUpgradeSuccess = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  const rulesString = rules.length > 1 ? 'rules' : 'rule';
  const toastMessage = `${rules.length} ${rulesString} updated successfully.`;
  cy.get(TOASTER).should('be.visible').should('have.text', toastMessage);
  for (const rule of rules) {
    cy.get(rule['security-rule'].name).should('not.exist');
  }
};

/**
 * Assert that when the rule version upgrade fails, the toast is shown with the right message
 * -notifying that the upgrade failed- and subsequently check that the rules available for upgrade
 * are still present in the Rule Update table
 */
export const assertUpgradeFailure = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  const rulesString = rules.length > 1 ? 'rules' : 'rule';
  const toastMessage = `${rules.length} ${rulesString} failed to update.`;
  cy.get(TOASTER).should('be.visible').should('have.text', toastMessage);

  for (const rule of rules) {
    cy.get(RULES_UPDATES_TABLE).contains(rule['security-rule'].name);
  }
};

export const interceptUpgradeRequestToFail = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  cy.intercept('POST', '/internal/detection_engine/prebuilt_rules/upgrade/_perform', {
    body: {
      summary: {
        succeeded: [],
        skipped: [],
        failed: rules.length,
      },
    },
    delay: 500, // Add delay to give Cypress time to find the loading spinner
  }).as('updatePrebuiltRules');
};

export const assertRuleInstallSuccessToastShown = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  const rulesString = rules.length > 1 ? 'rules' : 'rule';
  cy.get(TOASTER)
    .should('be.visible')
    .should('have.text', `${rules.length} ${rulesString} installed successfully.`);
};

export const assertRuleUpgradeSuccessToastShown = (rules: Array<typeof SAMPLE_PREBUILT_RULE>) => {
  const rulesString = rules.length > 1 ? 'rules' : 'rule';
  cy.get(TOASTER)
    .should('be.visible')
    .should('have.text', `${rules.length} ${rulesString} updated successfully.`);
};

export const assertRulePresentInInstalledRulesTable = (ruleName: string) => {
  cy.get(RULES_MANAGEMENT_TABLE).contains(ruleName);
};

export const assertRuleNotPresentInAddPrebuiltRulesTable = (ruleName: string) => {
  cy.get(ADD_ELASTIC_RULES_TABLE).contains(ruleName).should('not.exist');
};

export const assertRuleNotPresentInRuleUpdatesTable = (ruleName: string) => {
  cy.get(RULES_UPDATES_TABLE).contains(ruleName).should('not.exist');
};

export const openRuleInstallPreview = (ruleName: string) => {
  cy.contains(ruleName).click();
  cy.get(INSTALL_PREBUILT_RULE_PREVIEW).should('be.visible');
};

export const openRuleUpdatePreview = (ruleName: string) => {
  cy.contains(ruleName).click();
  cy.get(UPDATE_PREBUILT_RULE_PREVIEW).should('be.visible');
};

export const closeRulePreview = () => {
  cy.get(FLYOUT_CLOSE_BTN).click();
  cy.get(INSTALL_PREBUILT_RULE_PREVIEW).should('not.exist');
};

export const assertCommonPropertiesDisplayedCorrectly = (
  commonProperties: Partial<PrebuiltRuleAsset>
) => {
  cy.get(AUTHOR_PROPERTY_TITLE).should('have.text', 'Author');
  cy.get(AUTHOR_PROPERTY_VALUE_ITEM).then((items) => {
    const authorItems = items.map((index, item) => item.textContent).toArray();
    cy.wrap(authorItems).should('deep.equal', commonProperties.author);
  });

  cy.get(BUILDING_BLOCK_TITLE).should('have.text', 'Building block');
  cy.get(BUILDING_BLOCK_VALUE).should(
    'have.text',
    'All generated alerts will be marked as "building block" alerts'
  );

  cy.get(SEVERITY_TITLE).should('have.text', 'Severity');
  cy.get(SEVERITY_VALUE).should('have.text', capitalize(commonProperties.severity));

  cy.get(SEVERITY_MAPPING_TITLE).should('have.text', 'Severity override');
  commonProperties.severity_mapping?.forEach((severityMapping, index) => {
    cy.get(SEVERITY_MAPPING_VALUE_FIELD).eq(index).should('have.text', `${severityMapping.field}:`);
    cy.get(SEVERITY_MAPPING_VALUE_VALUE).eq(index).should('have.text', severityMapping.value);
    cy.get(SEVERITY_MAPPING_VALUE_SEVERITY)
      .eq(index)
      .should('have.text', capitalize(severityMapping.severity));
  });

  cy.get(RISK_SCORE_TITLE).should('have.text', 'Risk score');
  cy.get(RISK_SCORE_VALUE).should('have.text', commonProperties.risk_score);

  cy.get(RISK_SCORE_MAPPING_TITLE).should('have.text', 'Risk score override');
  commonProperties.risk_score_mapping?.forEach((riskScoreMapping, index) => {
    cy.get(RISK_SCORE_MAPPING_VALUE_FIELD_NAME)
      .eq(index)
      .should('have.text', riskScoreMapping.field);
    cy.get(RISK_SCORE_MAPPING_VALUE_OVERRIDE_NAME)
      .eq(index)
      .should('have.text', 'kibana.alert.risk_score');
  });

  cy.get(REFERENCES_TITLE).should('have.text', 'Reference URLs');
  cy.get(`${REFERENCES_VALUE_ITEM} a`).then((items) => {
    const referenceUrls = (items as JQuery<HTMLLinkElement>)
      .map((index, item) => item.href)
      .toArray();
    cy.wrap(referenceUrls).should('deep.equal', commonProperties.references);
  });

  cy.get(FALSE_POSITIVES_TITLE).should('have.text', 'False positive examples');
  cy.get(FALSE_POSITIVES_VALUE_ITEM).then((items) => {
    const falsePositives = items.map((index, item) => item.textContent).toArray();
    cy.wrap(falsePositives).should('deep.equal', commonProperties.false_positives);
  });

  cy.get(INVESTIGATION_FIELDS_TITLE).should('have.text', 'Custom highlighted fields');
  cy.get(INVESTIGATION_FIELDS_VALUE_ITEM).then((items) => {
    const investigationFields = items.map((index, item) => item.textContent).toArray();
    cy.wrap(investigationFields).should(
      'deep.equal',
      commonProperties.investigation_fields?.field_names
    );
  });

  cy.get(LICENSE_TITLE).should('have.text', 'License');
  cy.get(LICENSE_VALUE).should('have.text', commonProperties.license);

  cy.get(RULE_NAME_OVERRIDE_TITLE).should('have.text', 'Rule name override');
  cy.get(RULE_NAME_OVERRIDE_VALUE).should('have.text', commonProperties.rule_name_override);

  cy.get(THREAT_TITLE).should('have.text', 'MITRE ATT&CK™');
  commonProperties.threat?.forEach((threatItem, index) => {
    cy.get(THREAT_TACTIC).eq(index).should('contain', threatItem.tactic.id);
  });

  cy.get(TIMESTAMP_OVERRIDE_TITLE).should('have.text', 'Timestamp override');
  cy.get(TIMESTAMP_OVERRIDE_VALUE).should('have.text', commonProperties.timestamp_override);

  cy.get(TAGS_PROPERTY_TITLE).should('have.text', 'Tags');
  cy.get(TAGS_PROPERTY_VALUE_ITEM).then((items) => {
    const tags = items.map((index, item) => item.textContent).toArray();
    cy.wrap(tags).should('deep.equal', commonProperties.tags);
  });

  cy.get(RELATED_INTEGRATIONS_TITLE).should('have.text', 'Related integrations');
  commonProperties.related_integrations?.forEach((relatedIntegration, index) => {
    cy.get(RELATED_INTEGRATIONS_VALUE)
      .eq(index)
      .invoke('attr', 'data-test-subj')
      .should('contain', relatedIntegration.package);
  });

  cy.get(REQUIRED_FIELDS_PROPERTY_TITLE).should('have.text', 'Required fields');
  commonProperties.required_fields?.forEach((requiredField, index) => {
    cy.get(REQUIRED_FIELDS_PROPERTY_VALUE_ITEM).eq(index).should('contain', requiredField.name);
  });

  cy.get(TIMELINE_TEMPLATE_TITLE).should('have.text', 'Timeline template');
  cy.get(TIMELINE_TEMPLATE_VALUE).should('have.text', commonProperties.timeline_title);

  cy.get(INTERVAL_TITLE).should('have.text', 'Runs every');
  cy.get(INTERVAL_VALUE).should('have.text', commonProperties.interval);

  cy.get(FROM_TITLE).should('have.text', 'Additional look-back time');
  cy.get(FROM_VALUE).invoke('attr', 'data-test-subj').should('contain', commonProperties.from);
};

export const assertIndexPropertyDisplayed = (index: string[]) => {
  cy.get(INDEX_TITLE).should('have.text', 'Index patterns');
  cy.get(INDEX_VALUE_ITEM).then((items) => {
    const indexPatternItems = items.map((itemIndex, item) => item.textContent).toArray();
    cy.wrap(indexPatternItems).should('deep.equal', index);
  });
};

export const assertCustomQueryPropertyDisplayed = (query: string) => {
  cy.get(CUSTOM_QUERY_TITLE).should('have.text', 'Custom query');
  cy.get(CUSTOM_QUERY_VALUE).should('have.text', query);
};

export const assertFiltersPropertyDisplayed = (queryFilters: Filter[]) => {
  cy.get(FILTERS_TITLE).should('have.text', 'Filters');
  queryFilters.forEach((filter, filterIndex) => {
    cy.get(FILTERS_VALUE_ITEM)
      .eq(filterIndex)
      .invoke('attr', 'data-test-subj')
      .should('contain', filter.meta.key);
  });
};

export const assertAlertSuppressionPropertiesDisplayed = (alertSuppression: AlertSuppression) => {
  cy.get(ALERT_SUPPRESSION_GROUP_BY_TITLE).should('contain', 'Suppress alerts by');
  cy.get(ALERT_SUPPRESSION_GROUP_BY_VALUE_ITEM).then((items) => {
    const groupByItems = items.map((itemIndex, item) => item.textContent).toArray();
    cy.wrap(groupByItems).should('deep.equal', alertSuppression.group_by);
  });

  const { duration } = alertSuppression as { duration: { value: number; unit: string } };
  cy.get(ALERT_SUPPRESSION_DURATION_TITLE).should('contain', 'Suppress alerts for');
  cy.get(ALERT_SUPPRESSION_DURATION_VALUE).should('contain', `${duration.value}${duration.unit}`);

  cy.get(ALERT_SUPPRESSION_FIELD_TITLE).should('contain', 'If a suppression field is missing');
  cy.get(ALERT_SUPPRESSION_FIELD_VALUE).should(
    'contain',
    'Suppress and group alerts for events with missing fields'
  );
};

export const assertDataViewPropertiesDisplayed = (
  dataViewId: string,
  dataViewIndexPattern: string
) => {
  cy.get(DATA_VIEW_ID_TITLE).should('have.text', 'Data view ID');
  cy.get(DATA_VIEW_ID_VALUE).should('have.text', dataViewId);
  cy.get(DATA_VIEW_INDEX_PATTERN_TITLE).should('have.text', 'Data view index pattern');
  cy.get(DATA_VIEW_INDEX_PATTERN_VALUE).should('have.text', dataViewIndexPattern);
};

export const assertSavedQueryPropertiesDisplayed = (
  query: string,
  filterKey: string,
  name: string
) => {
  cy.get(SAVED_QUERY_CONTENT_TITLE).should('have.text', 'Saved query');
  cy.get(SAVED_QUERY_CONTENT_VALUE).should('have.text', query);

  cy.get(SAVED_QUERY_FILTERS_TITLE).should('have.text', 'Saved query filters');
  cy.get(SAVED_QUERY_FILTERS_VALUE).should('contain', filterKey);

  cy.get(SAVED_QUERY_NAME_TITLE).should('have.text', 'Saved query name');
  cy.get(SAVED_QUERY_NAME_VALUE).should('have.text', name);
};

export const assertMachineLearningPropertiesDisplayed = (
  anomalyThreshold: number,
  machineLearningJobIds: string[],
  mlModules: Module[]
) => {
  const mlJobs = mlModules.map((mlModule: Module) => mlModule.jobs).flat();
  const mlJobNameById: Record<string, string> = mlJobs.reduce((nameById, job) => {
    return {
      ...nameById,
      [job.id]: job.config?.custom_settings?.security_app_display_name || '',
    };
  }, {});

  cy.get(ANOMALY_THRESHOLD_TITLE).should('have.text', 'Anomaly score threshold');
  cy.get(ANOMALY_THRESHOLD_VALUE).should('have.text', anomalyThreshold);

  cy.get(MACHINE_LEARNING_JOB_TITLE).should('have.text', 'Machine Learning job');
  machineLearningJobIds.forEach((jobId, jobIndex) => {
    cy.get(MACHINE_LEARNING_JOB_VALUE).eq(jobIndex).should('contain', mlJobNameById[jobId]);
  });
};

export const assertThresholdPropertyDisplayed = (thresholdValue: number) => {
  cy.get(THRESHOLD_TITLE).should('have.text', 'Threshold');
  cy.get(THRESHOLD_VALUE).should('contain', thresholdValue);
};

export const assertEqlQueryPropertyDisplayed = (query: string) => {
  cy.get(EQL_QUERY_TITLE).should('have.text', 'EQL query');
  cy.get(EQL_QUERY_VALUE).should('have.text', query);
};

interface ThreatMatchQueryProperties {
  threatIndex: string[];
  threatMapping: ThreatMapping;
  threatFilters: Filter[];
  threatQuery: string;
}

export const assertThreatMatchQueryPropertiesDisplayed = ({
  threatIndex,
  threatMapping,
  threatFilters,
  threatQuery,
}: ThreatMatchQueryProperties) => {
  cy.get(THREAT_INDEX_TITLE).should('have.text', 'Indicator index patterns');
  cy.get(THREAT_INDEX_VALUE_ITEM).then((items) => {
    const indexItems = items.map((index, item) => item.textContent).toArray();
    cy.wrap(indexItems).should('deep.equal', threatIndex);
  });

  cy.get(THREAT_MAPPING_TITLE).should('have.text', 'Indicator mapping');
  threatMapping.forEach((threatMappingItem) => {
    threatMappingItem.entries.forEach((entry) => {
      cy.get(THREAT_MAPPING_VALUE).should('contain', entry.value);
    });
  });

  cy.get(THREAT_FILTERS_TITLE).should('have.text', 'Indicator filters');
  threatFilters.forEach((filter, filterIndex) => {
    cy.get(THREAT_FILTERS_VALUE_ITEM)
      .eq(filterIndex)
      .invoke('attr', 'data-test-subj')
      .should('contain', filter.meta.key);
  });

  cy.get(THREAT_QUERY_TITLE).should('have.text', 'Indicator index query');
  cy.get(THREAT_QUERY_VALUE).should('have.text', threatQuery);
};

export const assertNewTermsFieldsPropertyDisplayed = (newTermsFields: string[]) => {
  cy.get(NEW_TERMS_FIELDS_TITLE).should('have.text', 'Fields');
  cy.get(NEW_TERMS_FIELDS_VALUE_ITEM).then((items) => {
    const fieldItems = items.map((index, item) => item.textContent).toArray();
    cy.wrap(fieldItems).should('deep.equal', newTermsFields);
  });
};

export const assertWindowSizePropertyDisplayed = (historyWindowStart: string) => {
  cy.get(NEW_TERMS_WINDOW_SIZE_TITLE).should('have.text', 'History Window Size');
  cy.get(NEW_TERMS_WINDOW_SIZE_VALUE)
    .invoke('attr', 'data-test-subj')
    .should('contain', historyWindowStart);
};

export const assertEsqlQueryPropertyDisplayed = (query: string) => {
  cy.get(ESQL_QUERY_TITLE).should('have.text', 'ES|QL query');
  cy.get(ESQL_QUERY_VALUE).should('have.text', query);
};
