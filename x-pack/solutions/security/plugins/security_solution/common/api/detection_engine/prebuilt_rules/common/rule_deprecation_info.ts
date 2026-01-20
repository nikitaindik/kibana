/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Deprecation stage for a prebuilt rule.
 * - 'deprecation_started': Rule is in the process of being deprecated but still available
 * - 'deprecated': Rule has been fully deprecated and may be removed in future versions
 */
export type RuleDeprecationStage = 'deprecation_started' | 'deprecated';

/**
 * Deprecation information for a prebuilt rule.
 */
export interface RuleDeprecationInfo {
  /**
   * The deprecation stage indicating how far along the deprecation process the rule is.
   */
  stage: RuleDeprecationStage;

  /**
   * Optional reason explaining why the rule is deprecated and any recommended actions.
   */
  reason?: string;
}

/**
 * Entry for a single rule in the deprecations map.
 */
export interface RuleDeprecationEntry {
  /**
   * Deprecation information for this rule.
   * Wrapped in an object to allow for future extensibility.
   */
  deprecation: RuleDeprecationInfo;
}
