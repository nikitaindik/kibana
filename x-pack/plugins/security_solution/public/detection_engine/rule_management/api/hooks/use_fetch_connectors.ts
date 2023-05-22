/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useQuery } from '@tanstack/react-query';
import { BASE_ACTION_API_PATH } from '@kbn/actions-plugin/common';
import { useAppToasts } from '../../../../common/hooks/use_app_toasts';
// import * as i18n from './translations';
import { fetchConnectors, fetchConnectorTypes } from '../api';

export const useFetchConnectors = () => {
  const { addError } = useAppToasts();

  return useQuery(
    ['GET', BASE_ACTION_API_PATH, 'connectors'],
    ({ signal }) => fetchConnectors(signal),
    {
      refetchInterval: 60000,
      onError: (error) => {
        addError(error, {
          title: 'i18n.FETCH_ERROR',
          toastMessage: 'i18n.FETCH_ERROR_DESCRIPTION',
        });
      },
    }
  );
};

export const useFetchConnectorTypes = () => {
  const { addError } = useAppToasts();

  return useQuery(
    ['GET', BASE_ACTION_API_PATH, 'connector_types', 'siem'],
    ({ signal }) => fetchConnectorTypes(signal),
    {
      refetchInterval: 60000,
      onError: (error) => {
        addError(error, {
          title: 'i18n.FETCH_ERROR',
          toastMessage: 'i18n.FETCH_ERROR_DESCRIPTION',
        });
      },
    }
  );
};
