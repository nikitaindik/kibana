/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiDescriptionList } from '@elastic/eui';
import type { EuiDescriptionListProps } from '@elastic/eui';
import { DataSourceType } from '../../../../../../../../../common/api/detection_engine';
import type {
  SavedKqlQuery,
  DiffableRule,
  DiffableAllFields,
} from '../../../../../../../../../common/api/detection_engine';
import { Query, SavedQueryName, Filters } from '../../../../rule_definition_section';
import * as ruleDetailsI18n from '../../../../translations';
import * as descriptionStepI18n from '../../../../../../../rule_creation_ui/components/description_step/translations';
import { useGetSavedQuery } from '../../../../../../../../detections/pages/detection_engine/rules/use_get_saved_query';
import { getQueryLanguageLabel } from '../../../../helpers';

interface SavedQueryProps {
  kqlQuery: SavedKqlQuery;
  dataSource?: DiffableAllFields['data_source'];
  ruleType: DiffableRule['type'];
}

export function SavedKqlQueryReadOnly({ kqlQuery, dataSource, ruleType }: SavedQueryProps) {
  const { savedQuery } = useGetSavedQuery({
    savedQueryId: kqlQuery.saved_query_id,
    ruleType,
  });

  if (!savedQuery) {
    return null;
  }

  const listItems: EuiDescriptionListProps['listItems'] = [
    {
      title: descriptionStepI18n.SAVED_QUERY_NAME_LABEL,
      description: <SavedQueryName savedQueryName={savedQuery.attributes.title} />,
    },
    {
      title: ruleDetailsI18n.SAVED_QUERY_LANGUAGE_LABEL,
      description: getQueryLanguageLabel(savedQuery.attributes.query.language),
    },
  ];

  if (typeof savedQuery.attributes.query.query === 'string') {
    listItems.push({
      title: descriptionStepI18n.SAVED_QUERY_LABEL,
      description: <Query query={savedQuery.attributes.query.query} />,
    });
  }

  if (savedQuery.attributes.filters) {
    const index =
      dataSource?.type === DataSourceType.index_patterns ? dataSource.index_patterns : undefined;

    const dataViewId =
      dataSource?.type === DataSourceType.data_view ? dataSource.data_view_id : undefined;

    listItems.push({
      title: descriptionStepI18n.SAVED_QUERY_FILTERS_LABEL,
      description: (
        <Filters filters={savedQuery.attributes.filters} index={index} dataViewId={dataViewId} />
      ),
    });
  }

  return <EuiDescriptionList listItems={listItems} />;
}
