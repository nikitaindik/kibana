/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// TODO: Uncomment these imports when removing the mock data
// import { v5 as uuidv5 } from 'uuid';
import type { SavedObjectsClientContract } from '@kbn/core/server';
import type { PackageClient } from '@kbn/fleet-plugin/server';
// import { ASSETS_SAVED_OBJECT_TYPE } from '@kbn/fleet-plugin/common';
// import type { PackageAsset } from '@kbn/fleet-plugin/server/services/epm/archive/storage';
import { withSecuritySpan } from '../../../../../utils/with_security_span';
// import { PREBUILT_RULES_PACKAGE_NAME } from '../../../../../../common/detection_engine/constants';

// TODO: Uncomment when removing mock data
// /**
//  * Path to the deprecations file within the package.
//  * This path is relative to the package root.
//  */
// const DEPRECATIONS_FILE_PATH = 'deprecations.json';

/**
 * Deprecation stage for a prebuilt rule.
 * - 'deprecation_started': Rule is in the process of being deprecated but still available
 * - 'deprecated': Rule has been fully deprecated and may be removed in future versions
 */
export type RuleDeprecationStage = 'deprecation_started' | 'deprecated';

/**
 * Deprecation information for a single rule.
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

/**
 * Map of rule_id to deprecation entry.
 */
export type RuleDeprecationsMap = Record<string, RuleDeprecationEntry>;

export interface IRuleDeprecationsClient {
  /**
   * Fetches rule deprecation information from the installed package.
   * Returns an empty map if the package is not installed or no deprecations file exists.
   */
  fetchRuleDeprecations(): Promise<RuleDeprecationsMap>;
}

// TODO: Uncomment when removing mock data
// /**
//  * Converts an asset path to its saved object ID.
//  * This replicates the logic from Fleet's storage.ts to ensure consistent IDs.
//  */
// function assetPathToObjectId(assetPath: string): string {
//   // uuid v5 requires a SHA-1 UUID as a namespace
//   // used to ensure same input produces the same id
//   return uuidv5(assetPath, '71403015-cdd5-404b-a5da-6c43f35cad84');
// }

/**
 * Creates a client for fetching rule deprecation information from the prebuilt rules package.
 *
 * The deprecation data is stored as a JSON file (deprecations.json) in the Fleet package
 * and is automatically updated when the package is installed or upgraded.
 */
/**
 * TODO: Remove this mock data once the deprecations.json file is available in the package.
 * This is temporary mock data for testing the deprecation workflow.
 */
const MOCK_DEPRECATIONS: RuleDeprecationsMap = {
  // Example rule with deprecation_started - still shown but with warning
  '000047bb-b27a-47ec-8b62-ef1a5d2c9e19': { // Rule name: "Attempt to Modify an Okta Policy Rule"
    deprecation: {
      stage: 'deprecation_started',
      reason:
        'This rule is being deprecated and will be removed in a future release. Please migrate to the new rule.',
    },
  },
  // Example rule with deprecated - excluded from installation
  '0022d47d-39c7-4f69-a232-4fe9dc7a3acd': { // Rule name: "System Shells via Services"
    deprecation: {
      stage: 'deprecated',
      reason: 'This rule has been deprecated and replaced by a newer detection method.',
    },
  },
};

export const createRuleDeprecationsClient = (
  // TODO: Remove underscores when removing mock data
  _savedObjectsClient: SavedObjectsClientContract,
  _packageClient: PackageClient
): IRuleDeprecationsClient => {
  return {
    fetchRuleDeprecations: (): Promise<RuleDeprecationsMap> => {
      return withSecuritySpan('IRuleDeprecationsClient.fetchRuleDeprecations', async () => {
        // TODO: Remove this mock and uncomment the real implementation below
        // once the deprecations.json file is available in the package.
        return MOCK_DEPRECATIONS;

        /*
        // Get the installed package version
        const installation = await packageClient.getInstallation(PREBUILT_RULES_PACKAGE_NAME);

        if (!installation) {
          // Package not installed, return empty map
          return {};
        }

        const { name: pkgName, version: pkgVersion } = installation;
        const assetPath = `${pkgName}-${pkgVersion}/${DEPRECATIONS_FILE_PATH}`;

        try {
          // Fetch the asset directly from the epm-packages-assets saved object
          const assetSavedObject = await savedObjectsClient.get<PackageAsset>(
            ASSETS_SAVED_OBJECT_TYPE,
            assetPathToObjectId(assetPath)
          );

          const storedAsset = assetSavedObject?.attributes;
          if (!storedAsset?.data_utf8) {
            // Asset not found or empty
            return {};
          }

          // Parse the JSON content
          const deprecations = JSON.parse(storedAsset.data_utf8) as RuleDeprecationsMap;
          return deprecations;
        } catch (error) {
          // Asset not found is expected if no rules are deprecated
          if (error?.output?.statusCode === 404 || error?.statusCode === 404) {
            return {};
          }
          throw error;
        }
        */
      });
    },
  };
};
