/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import ReactDiffViewer from 'react-diff-viewer-continued';
import {
  EuiSpacer,
  EuiAccordion,
  EuiTitle,
  EuiFlexGroup,
  EuiHorizontalRule,
  useGeneratedHtmlId,
} from '@elastic/eui';
import type { RuleFieldsDiff } from '../../../../../common/api/detection_engine/prebuilt_rules/model/diff/rule_diff/rule_diff';

import * as i18n from './translations';

const HIDDEN_FIELDS = ['meta', 'rule_schedule', 'version'];

const FIELD_CONFIG_BY_NAME = {
  eql_query: {
    label: 'EQL query',
    compareMethod: 'diffWordsWithSpace',
  },
  kql_query: {
    label: 'KQL query',
    compareMethod: 'diffWordsWithSpace',
  },
  description: {
    label: 'Description',
    compareMethod: 'diffWordsWithSpace',
  },
  name: {
    label: 'Name',
    compareMethod: 'diffWordsWithSpace',
  },
  note: {
    label: 'Investigation guide',
    compareMethod: 'diffWordsWithSpace',
  },
  references: {
    label: i18n.REFERENCES_FIELD_LABEL,
    compareMethod: 'diffJson',
  },
  risk_score: {
    // JSON.stringify(fields.risk_score.current_version)
    label: i18n.RISK_SCORE_FIELD_LABEL,
    compareMethod: 'diffJson',
  },
  threat: {
    label: 'THREAT',
    compareMethod: 'diffJson',
  },
  severity: {
    label: 'Severity',
    compareMethod: 'diffWords',
  },
};

interface FieldsProps {
  fields: Partial<RuleFieldsDiff>;
  openSections: Record<string, boolean>;
  toggleSection: (sectionName: string) => void;
}

const Fields = ({ fields, openSections, toggleSection }: FieldsProps) => {
  const visibleFields = Object.keys(fields).filter(
    (fieldName) => !HIDDEN_FIELDS.includes(fieldName)
  );

  return (
    <>
      {visibleFields.map((fieldName) => {
        return (
          <>
            <ExpandableSection
              title={FIELD_CONFIG_BY_NAME[fieldName]?.label ?? fieldName.toUpperCase()}
              isOpen={openSections[fieldName]}
              toggle={() => {
                toggleSection(fieldName);
              }}
            >
              <ReactDiffViewer
                oldValue={
                  typeof fields[fieldName].current_version === 'string'
                    ? fields[fieldName].current_version
                    : JSON.stringify(fields[fieldName].current_version, null, 2)
                }
                newValue={
                  typeof fields[fieldName].merged_version === 'string'
                    ? fields[fieldName].merged_version
                    : JSON.stringify(fields[fieldName].merged_version, null, 2)
                }
                splitView={true}
                hideLineNumbers={true}
                compareMethod={FIELD_CONFIG_BY_NAME[fieldName]?.compareMethod ?? 'diffChars'}
              />
            </ExpandableSection>
            <EuiHorizontalRule margin="m" />
          </>
        );
      })}
    </>
  );
};

interface ExpandableSectionProps {
  title: string;
  isOpen: boolean;
  toggle: () => void;
  children: React.ReactNode;
}

const ExpandableSection = ({ title, isOpen, toggle, children }: ExpandableSectionProps) => {
  const accordionId = useGeneratedHtmlId({ prefix: 'accordion' });

  return (
    <EuiAccordion
      forceState={isOpen ? 'open' : 'closed'}
      onToggle={toggle}
      paddingSize="none"
      id={accordionId}
      buttonContent={
        <EuiTitle size="s">
          <h3>{title}</h3>
        </EuiTitle>
      }
      initialIsOpen={true}
    >
      <EuiSpacer size="m" />
      <EuiFlexGroup gutterSize="none" direction="column">
        {children}
      </EuiFlexGroup>
    </EuiAccordion>
  );
};

const WholeObjectDiff = ({ currentRule, mergedRule, openSections, toggleSection }) => {
  return (
    <>
      <ExpandableSection
        title={'Whole object diff'}
        isOpen={openSections.whole}
        toggle={() => {
          toggleSection('whole');
        }}
      >
        <ReactDiffViewer
          oldValue={JSON.stringify(currentRule, Object.keys(currentRule).sort(), 2)}
          newValue={JSON.stringify(mergedRule, Object.keys(mergedRule).sort(), 2)}
          splitView={true}
          hideLineNumbers={true}
          compareMethod={'diffJson'}
        />
      </ExpandableSection>
      <EuiHorizontalRule margin="m" />
    </>
  );
};

interface RuleDiffTabProps {
  fields: Partial<RuleFieldsDiff>;
}

export const RuleDiffTab = ({ fields, currentRule, mergedRule }: RuleDiffTabProps) => {
  const [openSections, setOpenSections] = useState<Record<string, boolean>>(
    Object.keys(fields).reduce((sections, fieldName) => ({ ...sections, [fieldName]: true }), {})
  );

  const toggleSection = (sectionName: string) => {
    setOpenSections((prevOpenSections) => ({
      ...prevOpenSections,
      [sectionName]: !prevOpenSections[sectionName],
    }));
  };

  return (
    <>
      <EuiSpacer size="m" />
      <WholeObjectDiff
        currentRule={currentRule}
        mergedRule={mergedRule}
        openSections={openSections}
        toggleSection={toggleSection}
      />
      <Fields fields={fields} openSections={openSections} toggleSection={toggleSection} />
    </>
  );
};
