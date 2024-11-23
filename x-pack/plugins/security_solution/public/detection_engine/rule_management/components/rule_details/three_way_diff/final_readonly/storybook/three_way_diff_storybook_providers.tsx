/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { configureStore } from '@reduxjs/toolkit';
import { merge } from 'lodash';
import { Subject } from 'rxjs';
import { Provider as ReduxStoreProvider } from 'react-redux';
import type { CoreStart } from '@kbn/core/public';
import type { UpsellingService } from '@kbn/security-solution-upselling/service';
import { createKibanaReactContext } from '@kbn/kibana-react-plugin/public';
import type { UpgradeableDiffableFields } from '../../../../../model/prebuilt_rule_upgrade/fields';
import { ReactQueryClientProvider } from '../../../../../../../common/containers/query_client/query_client_provider';
import { UpsellingProvider } from '../../../../../../../common/components/upselling_provider';
import { DiffableRuleContextProvider } from '../../diffable_rule_context';
import type { DiffableRule } from '../../../../../../../../common/api/detection_engine';
import { FieldFinalSideContextProvider } from '../../field_final_side/context/field_final_side_context';
import { mockCustomQueryRule } from './mocks';
import { FieldFinalSideMode } from '../../field_final_side';

function createKibanaServicesMock(overrides?: Partial<CoreStart>) {
  const baseMock = {
    data: {
      dataViews: {
        create: async () => {},
        get: async () => {},
      },
    },
    http: {
      get: async () => {},
      basePath: {
        get: () => '',
      },
    },
    notifications: {
      toasts: {
        addError: () => {},
        addSuccess: () => {},
        addWarning: () => {},
        remove: () => {},
      },
    },
    settings: {
      client: {
        get: (key: string, defaultOverride?: unknown) => defaultOverride,
        get$: () => new Subject(),
        set: () => {},
      },
    },
    uiSettings: {},
    upsellingService: {
      messages$: new Subject(),
      getMessagesValue: () => new Map(),
    } as unknown as UpsellingService,
  };

  return merge(baseMock, overrides);
}

function createMockStore() {
  const store = configureStore({
    reducer: {
      app: () => ({
        enableExperimental: {
          prebuiltRulesCustomizationEnabled: true,
        },
      }),
    },
  });

  return store;
}

const setRuleFieldResolvedValueMock = () => {};

interface StorybookProvidersProps {
  children: React.ReactNode;
  kibanaServicesOverrides?: Record<string, unknown>;
  finalDiffableRule?: DiffableRule;
  fieldName: string;
}

export function ThreeWayDiffStorybookProviders({
  children,
  kibanaServicesOverrides,
  finalDiffableRule = mockCustomQueryRule(),
  fieldName,
}: StorybookProvidersProps) {
  const kibanaServicesMock = createKibanaServicesMock(kibanaServicesOverrides);
  const KibanaReactContext = createKibanaReactContext(kibanaServicesMock);

  const store = createMockStore();

  return (
    <KibanaReactContext.Provider>
      <ReactQueryClientProvider>
        <ReduxStoreProvider store={store}>
          <UpsellingProvider upsellingService={kibanaServicesMock.upsellingService}>
            <DiffableRuleContextProvider
              finalDiffableRule={finalDiffableRule}
              setRuleFieldResolvedValue={setRuleFieldResolvedValueMock}
            >
              <FieldFinalSideContextProvider
                fieldName={fieldName as UpgradeableDiffableFields}
                initialMode={FieldFinalSideMode.Readonly}
              >
                {children}
              </FieldFinalSideContextProvider>
            </DiffableRuleContextProvider>
          </UpsellingProvider>
        </ReduxStoreProvider>
      </ReactQueryClientProvider>
    </KibanaReactContext.Provider>
  );
}
