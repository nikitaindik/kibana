/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FakeRawRequest } from '@kbn/core-http-server';
import { kibanaRequestFactory } from '@kbn/core-http-server-utils';
import { addSpaceIdToPath } from '@kbn/spaces-plugin/server';
import type { ElasticsearchServiceStart, HttpServiceSetup, Logger, KibanaRequest } from '@kbn/core/server';
import type { WorkflowsExtensionsServerPluginStart } from '@kbn/workflows-extensions/server';
import type { SecurityIntegrationInstalledEvent } from '../../../common/workflows/triggers';
import { SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID } from '../../../common/workflows/triggers';

export type EmitIntegrationInstalledEvent = (params: {
  spaceId: string;
  event: SecurityIntegrationInstalledEvent;
  request?: KibanaRequest;
}) => Promise<void>;

export const createEmitIntegrationInstalledEvent = ({
  getWorkflowsExtensionsStart,
  getElasticsearch,
  http,
  logger,
}: {
  getWorkflowsExtensionsStart: () => Promise<WorkflowsExtensionsServerPluginStart | undefined>;
  getElasticsearch: () => Promise<ElasticsearchServiceStart>;
  http: HttpServiceSetup;
  logger: Logger;
}): EmitIntegrationInstalledEvent => {
  return async ({ spaceId, event, request }) => {
    try {
      const workflowsExtensions = await getWorkflowsExtensionsStart();
      if (!workflowsExtensions) {
        return;
      }

      // Use the real request if available (has auth for workflow scheduling).
      // Otherwise, create a fake request with a generated API key so the
      // workflow task manager can schedule the execution.
      let effectiveRequest: KibanaRequest;
      if (request) {
        effectiveRequest = request;
      } else {
        const path = addSpaceIdToPath('/', spaceId);

        // Create an API key via ES internal client so the task manager
        // can authenticate the workflow execution
        const elasticsearch = await getElasticsearch();
        const apiKeyResponse = await elasticsearch.client.asInternalUser.security.grantApiKey({
          grant_type: 'password',
          username: 'elastic',
          password: 'changeme',
          api_key: {
            name: `workflow-trigger-${SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID}-${Date.now()}`,
            role_descriptors: {},
            metadata: {
              managed: true,
              source: 'security_solution_workflow_trigger',
            },
          },
        });

        const encodedApiKey = Buffer.from(
          `${apiKeyResponse.id}:${apiKeyResponse.api_key}`
        ).toString('base64');

        const fakeRawRequest: FakeRawRequest = {
          headers: {
            authorization: `ApiKey ${encodedApiKey}`,
          },
          path,
          url: new URL(`https://fake-request${path}`),
        };
        effectiveRequest = kibanaRequestFactory(fakeRawRequest);
        http.basePath.set(effectiveRequest, path);
      }

      await workflowsExtensions.emitEvent({
        triggerId: SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID,
        spaceId,
        payload: event as unknown as Record<string, unknown>,
        request: effectiveRequest,
      });

      logger.info(
        `Emitted ${SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID} for package "${event.package_name}" v${event.package_version}`
      );
    } catch (err) {
      logger.warn(
        `Failed to emit ${SECURITY_INTEGRATION_INSTALLED_TRIGGER_ID} workflow event: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }
  };
};
