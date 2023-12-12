/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import classNames from 'classnames';
import { css, Global } from '@emotion/react';
import {
  Diff,
  useSourceExpansion,
  useMinCollapsedLines,
  parseDiff,
  tokenize,
} from 'react-diff-view';
import 'react-diff-view/style/index.css';
import type {
  RenderGutter,
  HunkData,
  TokenizeOptions,
  DiffProps,
  HunkTokens,
} from 'react-diff-view';
import unidiff from 'unidiff';
import { useEuiTheme, hexToRgb, EuiRadioGroup } from '@elastic/eui';
import { Hunks } from './hunks';
import { markEdits, DiffMethod } from './mark_edits';

interface UseExpandReturn {
  expandRange: (start: number, end: number) => void;
  hunks: HunkData[];
}

/**
 * @param {HunkData[]} hunks - An array of hunk objects representing changes in a section of a string. Sections normally span multiple lines.
 * @param {string} oldSource - Original string, before changes
 * @returns {UseExpandReturn} - "expandRange" is function that triggers expansion, "hunks" is an array of hunks with hidden section expanded.
 *
 * @description
 * Sections of diff without changes are hidden by default, because they are not present in the "hunks" array.
 * "useExpand" allows to show these hidden sections when user clicks on "Expand hidden <number> lines" button.
 * Calling "expandRange" basically merges two adjacent hunks into one:
 * - takes first hunk
 * - appends all the lines between the first hunk and the second hunk
 * - finally appends the second hunk
 * returned "hunks" is the resulting array of hunks with hidden section expanded.
 */
const useExpand = (hunks: HunkData[], oldSource: string): UseExpandReturn => {
  const [hunksWithSourceExpanded, expandRange] = useSourceExpansion(hunks, oldSource);
  const hunksWithMinLinesCollapsed = useMinCollapsedLines(0, hunksWithSourceExpanded, oldSource);

  return {
    expandRange,
    hunks: hunksWithMinLinesCollapsed,
  };
};

const useTokens = (
  hunks: HunkData[],
  diffMethod: DiffMethod,
  oldSource: string
): HunkTokens | undefined => {
  if (!hunks) {
    return undefined;
  }

  const options: TokenizeOptions = {
    oldSource,
    highlight: false,
    enhancers: [
      /*
        This custom "markEdits" function is a slightly modified version of "markEdits" 
        enhancer from react-diff-view with added support for word-level highlighting.
      */
      markEdits(hunks, diffMethod),
    ],
  };

  try {
    /*
      Synchroniously apply all the enhancers to the hunks and return an array of tokens.
    */
    return tokenize(hunks, options);
  } catch (ex) {
    return undefined;
  }
};

const renderGutter: RenderGutter = ({ change }) => {
  /*
    Custom gutter: rendering "+" or "-" so the diff is readable by colorblind people.
  */
  if (change.type === 'insert') {
    return <span>{'+'}</span>;
  }

  if (change.type === 'delete') {
    return <span>{'-'}</span>;
  }

  return null;
};

const convertToDiffFile = (oldSource: string, newSource: string) => {
  /*
    "diffLines" call converts two strings of text into an array of Change objects.
  */
  const changes = unidiff.diffLines(oldSource, newSource);

  /*
    Then "formatLines" takes an array of Change objects and turns it into a single "unified diff" string.
    More info about the "unified diff" format: https://en.wikipedia.org/wiki/Diff_utility#Unified_format
    Unified diff is a string with change markers added. Looks something like:
    `
      @@ -3,16 +3,15 @@
         "author": ["Elastic"],
      -  "from": "now-540s",
      +  "from": "now-9m",
         "history_window_start": "now-14d",
    `
  */
  const unifiedDiff: string = unidiff.formatLines(changes, {
    context: 3,
  });

  /*
    "parseDiff" converts a unified diff string into a gitdiff-parser File object.

    File object contains some metadata and the "hunks" property - an array of Hunk objects.
    Hunks represent changed lines of code plus a few unchanged lines above and below for context.
  */
  const [diffFile] = parseDiff(unifiedDiff, {
    nearbySequences: 'zip',
  });

  return diffFile;
};

const TABLE_CLASS_NAME = 'rule-update-diff-table';
const CODE_CLASS_NAME = 'rule-update-diff-code';
const GUTTER_CLASS_NAME = 'rule-update-diff-gutter';
const DARK_THEME_CLASS_NAME = 'rule-update-diff-dark-theme';

const GITHUB_STYLES_CLASS_NAME = 'NIKITA-DONT-FORGET-TO-REMOVE-THIS-CLASS';

const CustomStyles: React.FC = ({ children }) => {
  const { euiTheme } = useEuiTheme();

  const insertionRgb = hexToRgb(euiTheme.colors.successText);
  const deletionRgb = hexToRgb(euiTheme.colors.dangerText);

  const customCss = css`
    .${TABLE_CLASS_NAME} .diff-gutter-col {
      width: ${euiTheme.size.xl};
    }

    .${CODE_CLASS_NAME}.diff-code, .${GUTTER_CLASS_NAME}.diff-gutter {
      background: transparent;
    }

    .${GUTTER_CLASS_NAME}:nth-child(3) {
      border-left: 1px solid ${euiTheme.colors.mediumShade};
    }

    .${CODE_CLASS_NAME}.diff-code {
      padding: 0 ${euiTheme.size.l} 0 ${euiTheme.size.m};
    }

    //

    .${GUTTER_CLASS_NAME}.diff-gutter-delete {
      color: ${euiTheme.colors.dangerText};
      font-weight: bold;
    }
    .${GITHUB_STYLES_CLASS_NAME} .${GUTTER_CLASS_NAME}.diff-gutter-delete {
      background: rgb(255, 215, 213);
    }
    .${DARK_THEME_CLASS_NAME}.${GITHUB_STYLES_CLASS_NAME} .${GUTTER_CLASS_NAME}.diff-gutter-delete {
      background: rgba(248, 81, 73, 0.3);
    }

    .${GUTTER_CLASS_NAME}.diff-gutter-insert {
      color: ${euiTheme.colors.successText};
      font-weight: bold;
    }
    .${GITHUB_STYLES_CLASS_NAME} .${GUTTER_CLASS_NAME}.diff-gutter-insert {
      background: rgb(204, 255, 216);
    }
    .${DARK_THEME_CLASS_NAME}.${GITHUB_STYLES_CLASS_NAME} .${GUTTER_CLASS_NAME}.diff-gutter-insert {
      background: rgba(63, 185, 80, 0.3);
    }

    //

    .${CODE_CLASS_NAME}.diff-code-delete {
      background: transparent;
    }
    .${GITHUB_STYLES_CLASS_NAME} .${CODE_CLASS_NAME}.diff-code-delete {
      background: rgb(255, 235, 233);
    }
    .${DARK_THEME_CLASS_NAME}.${GITHUB_STYLES_CLASS_NAME} .${CODE_CLASS_NAME}.diff-code-delete {
      background: rgba(248, 81, 73, 0.1);
    }

    .${CODE_CLASS_NAME}.diff-code-insert {
      background: transparent;
    }
    .${GITHUB_STYLES_CLASS_NAME} .${CODE_CLASS_NAME}.diff-code-insert {
      background: rgb(230, 255, 236);
    }
    .${DARK_THEME_CLASS_NAME}.${GITHUB_STYLES_CLASS_NAME} .${CODE_CLASS_NAME}.diff-code-insert {
      background: rgba(46, 160, 67, 0.15);
    }

    //

    .${CODE_CLASS_NAME}.diff-code-delete .diff-code-edit {
      color: ${euiTheme.colors.dangerText};
      text-decoration: line-through;
      background: rgba(${deletionRgb.join()}, 0.05);
    }
    .${GITHUB_STYLES_CLASS_NAME} .${CODE_CLASS_NAME}.diff-code-delete .diff-code-edit {
      color: unset;
      text-decoration: none;
      background: rgba(255, 129, 130, 0.4);
    }
    .${DARK_THEME_CLASS_NAME}.${GITHUB_STYLES_CLASS_NAME}
      .${CODE_CLASS_NAME}.diff-code-delete
      .diff-code-edit {
      color: unset;
      text-decoration: none;
      background: rgba(248, 81, 73, 0.4);
    }

    .${CODE_CLASS_NAME}.diff-code-insert .diff-code-edit {
      color: ${euiTheme.colors.successText};
      text-decoration: underline;
      background: rgba(${insertionRgb.join()}, 0.05);
    }
    .${GITHUB_STYLES_CLASS_NAME} .${CODE_CLASS_NAME}.diff-code-insert .diff-code-edit {
      color: unset;
      text-decoration: none;
      background: rgb(171, 242, 188);
    }
    .${DARK_THEME_CLASS_NAME}.${GITHUB_STYLES_CLASS_NAME}
      .${CODE_CLASS_NAME}.diff-code-insert
      .diff-code-edit {
      color: unset;
      text-decoration: none;
      background: rgba(46, 160, 67, 0.4);
    }
  `;

  return (
    <>
      <Global styles={customCss} />
      {children}
    </>
  );
};

interface DiffViewProps extends Partial<DiffProps> {
  oldSource: string;
  newSource: string;
  diffMethod?: DiffMethod;
}

export const DiffView = ({
  oldSource,
  newSource,
  diffMethod = DiffMethod.WORDS,
}: DiffViewProps) => {
  /*
    "react-diff-view" components consume diffs not as a strings, but as something they call "hunks".
    So we first need to convert our "before" and "after" strings into these "hunk" objects.
    "hunks" describe changed sections of code plus a few unchanged lines above and below for context.
  */

  /*
    "diffFile" is essentially an object containing an array of hunks plus some metadata.
  */
  const diffFile = useMemo(() => convertToDiffFile(oldSource, newSource), [oldSource, newSource]);

  /*
    Sections of diff without changes are hidden by default, because they are not present in the "hunks" array.
    "useExpand" allows to show these hidden sections when a user clicks on "Expand hidden <number> lines" button.
  */
  const { expandRange, hunks } = useExpand(diffFile.hunks, oldSource);

  /*
    Go over each hunk and extract tokens from it. For example, split strings into words or characters,
    so we can highlight them later.
  */
  const tokens = useTokens(hunks, diffMethod, oldSource);

  const { colorMode } = useEuiTheme();

  const [selectedStyle, setSelectedStyle] = React.useState('our-styles');

  const tableClassName = classNames(TABLE_CLASS_NAME, {
    [DARK_THEME_CLASS_NAME]: colorMode === 'DARK',
    [GITHUB_STYLES_CLASS_NAME]: selectedStyle === 'github-styles',
  });

  return (
    <CustomStyles>
      <EuiRadioGroup
        options={[
          {
            id: 'our-styles',
            label: 'Our styles with added line highlighting',
          },
          {
            id: 'github-styles',
            label: 'GitHub styles',
          },
        ]}
        idSelected={selectedStyle}
        onChange={(optionId) => {
          setSelectedStyle(optionId);
        }}
        legend={{
          children: <span>{'Highlighting style (also try with dark theme)'}</span>,
        }}
      />
      <Diff
        /*
          "diffType": can be either 'add', 'delete', 'modify', 'rename' or 'copy'.
          Passing 'add' or 'delete' would skip rendering one of the sides in split view.
        */
        diffType={diffFile.type}
        hunks={hunks}
        renderGutter={renderGutter}
        tokens={tokens}
        className={tableClassName}
        gutterClassName={GUTTER_CLASS_NAME}
        codeClassName={CODE_CLASS_NAME}
      >
        {/* eslint-disable-next-line @typescript-eslint/no-shadow */}
        {(hunks) => <Hunks hunks={hunks} oldSource={oldSource} expandRange={expandRange} />}
      </Diff>
    </CustomStyles>
  );
};
