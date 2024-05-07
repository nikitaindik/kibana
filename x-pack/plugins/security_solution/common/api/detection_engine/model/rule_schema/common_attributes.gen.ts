/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from 'zod';
import { isValidDateMath } from '@kbn/zod-helpers';

/*
 * NOTICE: Do not edit this file manually.
 * This file is automatically generated by the OpenAPI Generator, @kbn/openapi-generator.
 *
 * info:
 *   title: Common Rule Attributes
 *   version: not applicable
 */

import { UUID, NonEmptyString } from '../../../model/primitives.gen';

export type RuleObjectId = z.infer<typeof RuleObjectId>;
export const RuleObjectId = UUID;

/**
 * Could be any string, not necessarily a UUID
 */
export type RuleSignatureId = z.infer<typeof RuleSignatureId>;
export const RuleSignatureId = z.string();

export type RuleName = z.infer<typeof RuleName>;
export const RuleName = z.string().min(1);

export type RuleDescription = z.infer<typeof RuleDescription>;
export const RuleDescription = z.string().min(1);

/**
 * The rule's version number.
 */
export type RuleVersion = z.infer<typeof RuleVersion>;
export const RuleVersion = z.number().int().min(1);

export type QueryLanguage = z.infer<typeof QueryLanguage>;
export const QueryLanguage = z.enum(['kuery', 'lucene', 'eql', 'esql']);
export type QueryLanguageEnum = typeof QueryLanguage.enum;
export const QueryLanguageEnum = QueryLanguage.enum;

export type KqlQueryLanguage = z.infer<typeof KqlQueryLanguage>;
export const KqlQueryLanguage = z.enum(['kuery', 'lucene']);
export type KqlQueryLanguageEnum = typeof KqlQueryLanguage.enum;
export const KqlQueryLanguageEnum = KqlQueryLanguage.enum;

/**
 * This field determines whether the rule is a prebuilt Elastic rule. It will be replaced with the `rule_source` field.
 * @deprecated
 */
export type IsRuleImmutable = z.infer<typeof IsRuleImmutable>;
export const IsRuleImmutable = z.boolean();

/**
 * Determines whether an external/prebuilt rule has been customized by the user (i.e. any of its fields have been modified and diverged from the base value).
 */
export type IsExternalRuleCustomized = z.infer<typeof IsExternalRuleCustomized>;
export const IsExternalRuleCustomized = z.boolean();

/**
 * Type of rule source for internally sourced rules, i.e. created within the Kibana apps.
 */
export type InternalRuleSource = z.infer<typeof InternalRuleSource>;
export const InternalRuleSource = z.object({
  type: z.literal('internal'),
});

/**
 * Type of rule source for externally sourced rules, i.e. rules that have an external source, such as the Elastic Prebuilt rules repo.
 */
export type ExternalRuleSource = z.infer<typeof ExternalRuleSource>;
export const ExternalRuleSource = z.object({
  type: z.literal('external'),
  is_customized: IsExternalRuleCustomized,
});

/**
 * Discriminated union that determines whether the rule is internally sourced (created within the Kibana app) or has an external source, such as the Elastic Prebuilt rules repo.
 */
export type RuleSource = z.infer<typeof RuleSource>;
export const RuleSource = z.discriminatedUnion('type', [ExternalRuleSource, InternalRuleSource]);

/**
 * Determines whether the rule is enabled.
 */
export type IsRuleEnabled = z.infer<typeof IsRuleEnabled>;
export const IsRuleEnabled = z.boolean();

/**
 * Frequency of rule execution, using a date math range. For example, "1h" means the rule runs every hour. Defaults to 5m (5 minutes).
 */
export type RuleInterval = z.infer<typeof RuleInterval>;
export const RuleInterval = z.string();

/**
 * Time from which data is analyzed each time the rule executes, using a date math range. For example, now-4200s means the rule analyzes data from 70 minutes before its start time. Defaults to now-6m (analyzes data from 6 minutes before the start time).
 */
export type RuleIntervalFrom = z.infer<typeof RuleIntervalFrom>;
export const RuleIntervalFrom = z.string().superRefine(isValidDateMath);

export type RuleIntervalTo = z.infer<typeof RuleIntervalTo>;
export const RuleIntervalTo = z.string();

/**
 * Risk score (0 to 100)
 */
export type RiskScore = z.infer<typeof RiskScore>;
export const RiskScore = z.number().int().min(0).max(100);

/**
 * Overrides generated alerts' risk_score with a value from the source event
 */
export type RiskScoreMapping = z.infer<typeof RiskScoreMapping>;
export const RiskScoreMapping = z.array(
  z.object({
    field: z.string(),
    operator: z.literal('equals'),
    value: z.string(),
    risk_score: RiskScore.optional(),
  })
);

/**
 * Severity of the rule
 */
export type Severity = z.infer<typeof Severity>;
export const Severity = z.enum(['low', 'medium', 'high', 'critical']);
export type SeverityEnum = typeof Severity.enum;
export const SeverityEnum = Severity.enum;

/**
 * Overrides generated alerts' severity with values from the source event
 */
export type SeverityMapping = z.infer<typeof SeverityMapping>;
export const SeverityMapping = z.array(
  z.object({
    field: z.string(),
    operator: z.literal('equals'),
    severity: Severity,
    value: z.string(),
  })
);

/**
 * String array containing words and phrases to help categorize, filter, and search rules. Defaults to an empty array.
 */
export type RuleTagArray = z.infer<typeof RuleTagArray>;
export const RuleTagArray = z.array(z.string());

export type RuleMetadata = z.infer<typeof RuleMetadata>;
export const RuleMetadata = z.object({}).catchall(z.unknown());

/**
 * The rule's license.
 */
export type RuleLicense = z.infer<typeof RuleLicense>;
export const RuleLicense = z.string();

export type RuleAuthorArray = z.infer<typeof RuleAuthorArray>;
export const RuleAuthorArray = z.array(z.string());

export type RuleFalsePositiveArray = z.infer<typeof RuleFalsePositiveArray>;
export const RuleFalsePositiveArray = z.array(z.string());

export type RuleReferenceArray = z.infer<typeof RuleReferenceArray>;
export const RuleReferenceArray = z.array(z.string());

/**
 * Notes to help investigate alerts produced by the rule.
 */
export type InvestigationGuide = z.infer<typeof InvestigationGuide>;
export const InvestigationGuide = z.string();

export type SetupGuide = z.infer<typeof SetupGuide>;
export const SetupGuide = z.string();

/**
 * Determines if the rule acts as a building block. By default, building-block alerts are not displayed in the UI. These rules are used as a foundation for other rules that do generate alerts. Its value must be default.
 */
export type BuildingBlockType = z.infer<typeof BuildingBlockType>;
export const BuildingBlockType = z.string();

/**
 * (deprecated) Has no effect.
 * @deprecated
 */
export type AlertsIndex = z.infer<typeof AlertsIndex>;
export const AlertsIndex = z.string();

/**
 * Has no effect.
 */
export type AlertsIndexNamespace = z.infer<typeof AlertsIndexNamespace>;
export const AlertsIndexNamespace = z.string();

export type MaxSignals = z.infer<typeof MaxSignals>;
export const MaxSignals = z.number().int().min(1);

export type ThreatSubtechnique = z.infer<typeof ThreatSubtechnique>;
export const ThreatSubtechnique = z.object({
  /**
   * Subtechnique ID
   */
  id: z.string(),
  /**
   * Subtechnique name
   */
  name: z.string(),
  /**
   * Subtechnique reference
   */
  reference: z.string(),
});

export type ThreatTechnique = z.infer<typeof ThreatTechnique>;
export const ThreatTechnique = z.object({
  /**
   * Technique ID
   */
  id: z.string(),
  /**
   * Technique name
   */
  name: z.string(),
  /**
   * Technique reference
   */
  reference: z.string(),
  /**
   * Array containing more specific information on the attack technique
   */
  subtechnique: z.array(ThreatSubtechnique).optional(),
});

export type ThreatTactic = z.infer<typeof ThreatTactic>;
export const ThreatTactic = z.object({
  /**
   * Tactic ID
   */
  id: z.string(),
  /**
   * Tactic name
   */
  name: z.string(),
  /**
   * Tactic reference
   */
  reference: z.string(),
});

export type Threat = z.infer<typeof Threat>;
export const Threat = z.object({
  /**
   * Relevant attack framework
   */
  framework: z.string(),
  tactic: ThreatTactic,
  /**
   * Array containing information on the attack techniques (optional)
   */
  technique: z.array(ThreatTechnique).optional(),
});

export type ThreatArray = z.infer<typeof ThreatArray>;
export const ThreatArray = z.array(Threat);

export type IndexPatternArray = z.infer<typeof IndexPatternArray>;
export const IndexPatternArray = z.array(z.string());

export type DataViewId = z.infer<typeof DataViewId>;
export const DataViewId = z.string();

export type SavedQueryId = z.infer<typeof SavedQueryId>;
export const SavedQueryId = z.string();

export type RuleQuery = z.infer<typeof RuleQuery>;
export const RuleQuery = z.string();

export type RuleFilterArray = z.infer<typeof RuleFilterArray>;
export const RuleFilterArray = z.array(z.unknown());

/**
 * Sets the source field for the alert's signal.rule.name value
 */
export type RuleNameOverride = z.infer<typeof RuleNameOverride>;
export const RuleNameOverride = z.string();

/**
 * Sets the time field used to query indices
 */
export type TimestampOverride = z.infer<typeof TimestampOverride>;
export const TimestampOverride = z.string();

/**
 * Disables the fallback to the event's @timestamp field
 */
export type TimestampOverrideFallbackDisabled = z.infer<typeof TimestampOverrideFallbackDisabled>;
export const TimestampOverrideFallbackDisabled = z.boolean();

/**
 * Describes an Elasticsearch field that is needed for the rule to function
 */
export type RequiredField = z.infer<typeof RequiredField>;
export const RequiredField = z.object({
  /**
   * Name of an Elasticsearch field
   */
  name: NonEmptyString,
  /**
   * Type of the Elasticsearch field
   */
  type: NonEmptyString,
  /**
   * Whether the field is an ECS field
   */
  ecs: z.boolean(),
});

/**
 * Input parameters to create a RequiredField. Does not include the `ecs` field, because `ecs` is calculated on the backend based on the field name and type.
 */
export type RequiredFieldInput = z.infer<typeof RequiredFieldInput>;
export const RequiredFieldInput = z.object({
  /**
   * Name of an Elasticsearch field
   */
  name: NonEmptyString,
  /**
   * Type of the Elasticsearch field
   */
  type: NonEmptyString,
});

export type RequiredFieldArray = z.infer<typeof RequiredFieldArray>;
export const RequiredFieldArray = z.array(RequiredField);

/**
 * Timeline template ID
 */
export type TimelineTemplateId = z.infer<typeof TimelineTemplateId>;
export const TimelineTemplateId = z.string();

/**
 * Timeline template title
 */
export type TimelineTemplateTitle = z.infer<typeof TimelineTemplateTitle>;
export const TimelineTemplateTitle = z.string();

export type SavedObjectResolveOutcome = z.infer<typeof SavedObjectResolveOutcome>;
export const SavedObjectResolveOutcome = z.enum(['exactMatch', 'aliasMatch', 'conflict']);
export type SavedObjectResolveOutcomeEnum = typeof SavedObjectResolveOutcome.enum;
export const SavedObjectResolveOutcomeEnum = SavedObjectResolveOutcome.enum;

export type SavedObjectResolveAliasTargetId = z.infer<typeof SavedObjectResolveAliasTargetId>;
export const SavedObjectResolveAliasTargetId = z.string();

export type SavedObjectResolveAliasPurpose = z.infer<typeof SavedObjectResolveAliasPurpose>;
export const SavedObjectResolveAliasPurpose = z.enum([
  'savedObjectConversion',
  'savedObjectImport',
]);
export type SavedObjectResolveAliasPurposeEnum = typeof SavedObjectResolveAliasPurpose.enum;
export const SavedObjectResolveAliasPurposeEnum = SavedObjectResolveAliasPurpose.enum;

export type RelatedIntegration = z.infer<typeof RelatedIntegration>;
export const RelatedIntegration = z.object({
  package: NonEmptyString,
  version: NonEmptyString,
  integration: NonEmptyString.optional(),
});

export type RelatedIntegrationArray = z.infer<typeof RelatedIntegrationArray>;
export const RelatedIntegrationArray = z.array(RelatedIntegration);

export type InvestigationFields = z.infer<typeof InvestigationFields>;
export const InvestigationFields = z.object({
  field_names: z.array(NonEmptyString).min(1),
});

/**
 * Defines the interval on which a rule's actions are executed.
 */
export type RuleActionThrottle = z.infer<typeof RuleActionThrottle>;
export const RuleActionThrottle = z.union([
  z.enum(['no_actions', 'rule']),
  z.string().regex(/^[1-9]\d*[smhd]$/),
]);

/**
 * The condition for throttling the notification: `onActionGroupChange`, `onActiveAlert`,  or `onThrottleInterval`
 */
export type RuleActionNotifyWhen = z.infer<typeof RuleActionNotifyWhen>;
export const RuleActionNotifyWhen = z.enum([
  'onActiveAlert',
  'onThrottleInterval',
  'onActionGroupChange',
]);
export type RuleActionNotifyWhenEnum = typeof RuleActionNotifyWhen.enum;
export const RuleActionNotifyWhenEnum = RuleActionNotifyWhen.enum;

/**
 * The action frequency defines when the action runs (for example, only on rule execution or at specific time intervals).
 */
export type RuleActionFrequency = z.infer<typeof RuleActionFrequency>;
export const RuleActionFrequency = z.object({
  /**
   * Action summary indicates whether we will send a summary notification about all the generate alerts or notification per individual alert
   */
  summary: z.boolean(),
  notifyWhen: RuleActionNotifyWhen,
  throttle: RuleActionThrottle.nullable(),
});

export type RuleActionAlertsFilter = z.infer<typeof RuleActionAlertsFilter>;
export const RuleActionAlertsFilter = z.object({}).catchall(z.unknown());

/**
 * Object containing the allowed connector fields, which varies according to the connector type.
 */
export type RuleActionParams = z.infer<typeof RuleActionParams>;
export const RuleActionParams = z.object({}).catchall(z.unknown());

/**
 * Optionally groups actions by use cases. Use `default` for alert notifications.
 */
export type RuleActionGroup = z.infer<typeof RuleActionGroup>;
export const RuleActionGroup = z.string();

/**
 * The connector ID.
 */
export type RuleActionId = z.infer<typeof RuleActionId>;
export const RuleActionId = z.string();

export type RuleAction = z.infer<typeof RuleAction>;
export const RuleAction = z.object({
  /**
   * The action type used for sending notifications.
   */
  action_type_id: z.string(),
  group: RuleActionGroup,
  id: RuleActionId,
  params: RuleActionParams,
  uuid: NonEmptyString.optional(),
  alerts_filter: RuleActionAlertsFilter.optional(),
  frequency: RuleActionFrequency.optional(),
});

/**
 * The exception type
 */
export type ExceptionListType = z.infer<typeof ExceptionListType>;
export const ExceptionListType = z.enum([
  'detection',
  'rule_default',
  'endpoint',
  'endpoint_trusted_apps',
  'endpoint_events',
  'endpoint_host_isolation_exceptions',
  'endpoint_blocklists',
]);
export type ExceptionListTypeEnum = typeof ExceptionListType.enum;
export const ExceptionListTypeEnum = ExceptionListType.enum;

export type RuleExceptionList = z.infer<typeof RuleExceptionList>;
export const RuleExceptionList = z.object({
  /**
   * ID of the exception container
   */
  id: NonEmptyString,
  /**
   * List ID of the exception container
   */
  list_id: NonEmptyString,
  type: ExceptionListType,
  /**
   * Determines the exceptions validity in rule's Kibana space
   */
  namespace_type: z.enum(['agnostic', 'single']),
});

export type AlertSuppressionDuration = z.infer<typeof AlertSuppressionDuration>;
export const AlertSuppressionDuration = z.object({
  value: z.number().int().min(1),
  unit: z.enum(['s', 'm', 'h']),
});

/**
  * Describes how alerts will be generated for documents with missing suppress by fields:
doNotSuppress - per each document a separate alert will be created
suppress - only alert will be created per suppress by bucket
  */
export type AlertSuppressionMissingFieldsStrategy = z.infer<
  typeof AlertSuppressionMissingFieldsStrategy
>;
export const AlertSuppressionMissingFieldsStrategy = z.enum(['doNotSuppress', 'suppress']);
export type AlertSuppressionMissingFieldsStrategyEnum =
  typeof AlertSuppressionMissingFieldsStrategy.enum;
export const AlertSuppressionMissingFieldsStrategyEnum = AlertSuppressionMissingFieldsStrategy.enum;

export type AlertSuppressionGroupBy = z.infer<typeof AlertSuppressionGroupBy>;
export const AlertSuppressionGroupBy = z.array(z.string()).min(1).max(3);

export type AlertSuppression = z.infer<typeof AlertSuppression>;
export const AlertSuppression = z.object({
  group_by: AlertSuppressionGroupBy,
  duration: AlertSuppressionDuration.optional(),
  missing_fields_strategy: AlertSuppressionMissingFieldsStrategy.optional(),
});

export type AlertSuppressionCamel = z.infer<typeof AlertSuppressionCamel>;
export const AlertSuppressionCamel = z.object({
  groupBy: AlertSuppressionGroupBy,
  duration: AlertSuppressionDuration.optional(),
  missingFieldsStrategy: AlertSuppressionMissingFieldsStrategy.optional(),
});
