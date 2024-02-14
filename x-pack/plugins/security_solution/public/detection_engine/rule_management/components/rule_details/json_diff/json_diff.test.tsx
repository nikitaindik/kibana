/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, within, screen } from '@testing-library/react';
import type { Matcher } from '@testing-library/react';
import { escapeRegExp } from 'lodash';

import { RuleDiffTab } from '../rule_diff_tab';
import { savedRuleMock } from '../../../logic/mock';
import type { RuleResponse } from '../../../../../../common/api/detection_engine/model/rule_schema/rule_schemas.gen';

/**
 * Creates a matcher function designed to determine if an element contains specific text content in specific order.
 * It returns true if the element itself contains the strings (matching all strings in the specified order) without
 * any of its children containing all of these strings. This is useful for finding elements with text content that
 * is split across multiple child elements.
 *
 * @param {string[]} strings - An array of strings to be matched within the content.
 * @returns {Function} A Matcher function that returns a boolean indicating whether the element matches the
 * specified text conditions: the element contains the text specified by `strings` and none of its children
 * contain this text.
 *
 * The Matcher function itself has the following signature:
 * @param {string} content - The content string to be checked. Not directly used in the current implementation
 * but is required for the matcher's signature.
 * @param {Element|null} element - The DOM element to check for the text content. If null, the matcher will
 * return false.
 *
 * @returns {boolean} `true` if the element contains the specified text and none of its children do,
 * otherwise `false`.
 * Utilizes Lodash's `escapeRegExp` to handle special characters in the `strings` array.
 */
const matchInOrder =
  (strings: string[]): Matcher =>
  (content: string, element: Element | null) => {
    if (element) {
      const hasText = (node: Element): boolean => {
        const regex = new RegExp(strings.map((string) => escapeRegExp(string)).join('.*?'));
        return regex.test(node.textContent || '');
      };

      const nodeHasText = hasText(element);
      const childrenDontHaveText = Array.from(element.children).every((child) => !hasText(child));

      return nodeHasText && childrenDontHaveText;
    }

    return false;
  };

describe('Rule upgrade workflow: viewing rule changes in JSON diff view', () => {
  it('User can see precisely how property values would change after upgrade', () => {
    const removedBackgroundColor = 'rgb(255, 235, 233)';
    const removedAccentColor = 'rgba(255, 129, 130, 0.4)';
    const addedBackgroundColor = 'rgb(230, 255, 236)';
    const addedAccentColor = 'rgb(171, 242, 188)';

    const oldRule: RuleResponse = {
      ...savedRuleMock,
    };

    const newRule: RuleResponse = {
      ...savedRuleMock,
    };

    /* Changes to test line update */
    oldRule.version = 1;
    newRule.version = 2;

    /* Changes to test line removal */
    oldRule.author = ['Alice', 'Bob', 'Charlie'];
    newRule.author = ['Alice', 'Charlie'];

    /* Changes to test line addition */
    delete oldRule.license;
    newRule.license = 'GPLv3';

    const { getByText } = render(<RuleDiffTab oldRule={oldRule} newRule={newRule} />);

    /* LINE UPDATE */
    const updatedLine = getByText(matchInOrder(['-', 'version', '1', '+', 'version', '2']));

    const updatedLineBefore = within(updatedLine).getByText(matchInOrder(['version', '1']));
    expect(updatedLineBefore).toHaveStyle(`background: ${removedBackgroundColor}`);

    const updatedWordBefore = within(updatedLineBefore).getByText('1');
    expect(updatedWordBefore).toHaveStyle(`background: ${removedAccentColor}`);

    const updatedLineAfter = within(updatedLine).getByText(matchInOrder(['version', '2']));
    expect(updatedLineAfter).toHaveStyle(`background: ${addedBackgroundColor}`);

    const updatedWordAfter = within(updatedLineAfter).getByText('2');
    expect(updatedWordAfter).toHaveStyle(`background: ${addedAccentColor}`);

    /* LINE REMOVAL */
    /* Check that the removed line is displayed only once */
    expect(screen.queryAllByText(matchInOrder(['Bob']))).toHaveLength(1);

    /* Removed line appears in the "before" column */
    const removedLine = getByText(matchInOrder(['-', 'Bob']));

    const removedLineBefore = within(removedLine).getByText(matchInOrder(['Bob']));
    expect(removedLineBefore).toHaveStyle(`background: ${removedBackgroundColor}`);

    /* LINE ADDITION */
    /* Check that the added line is displayed only once */
    expect(screen.queryAllByText(matchInOrder(['GPLv3']))).toHaveLength(1);

    /* Added line appears in the "after" column */
    const addedLine = getByText(matchInOrder(['+', 'license', 'GPLv3']));

    const addedLineAfter = within(addedLine).getByText(matchInOrder(['license', 'GPLv3']));
    expect(addedLineAfter).toHaveStyle(`background: ${addedBackgroundColor}`);
  });

  it('Rule actions and exception lists should not be shown as modified', () => {
    const testAction = {
      group: 'default',
      id: 'my-action-id',
      params: { body: '{"test": true}' },
      action_type_id: '.webhook',
      uuid: '1ef8f105-7d0d-434c-9ba1-2e053edddea8',
      frequency: {
        summary: true,
        notifyWhen: 'onActiveAlert',
        throttle: null,
      },
    } as const;

    const oldRule: RuleResponse = {
      ...savedRuleMock,
      version: 1,
      actions: [testAction],
    };

    const newRule: RuleResponse = {
      ...savedRuleMock,
      version: 2,
    };

    /* Case: rule update doesn't have the "actions" property */
    const { rerender } = render(<RuleDiffTab oldRule={{ ...oldRule }} newRule={{ ...newRule }} />);
    expect(screen.queryAllByText(matchInOrder(['actions']))).toHaveLength(0);

    /* Case: rule update has "actions" equal to an empty array */
    rerender(<RuleDiffTab oldRule={{ ...oldRule }} newRule={{ ...newRule, actions: [] }} />);
    expect(screen.queryAllByText(matchInOrder(['actions']))).toHaveLength(0);

    /* Case: rule update has an action */
    rerender(
      <RuleDiffTab
        oldRule={{ ...oldRule }}
        newRule={{ ...newRule, actions: [{ ...testAction, id: 'my-other-action' }] }}
      />
    );
    expect(screen.queryAllByText(matchInOrder(['actions']))).toHaveLength(0);
  });
});
