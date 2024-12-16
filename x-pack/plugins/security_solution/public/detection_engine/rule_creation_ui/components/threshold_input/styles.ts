/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { css, cx } from '@emotion/css';
import { euiThemeVars } from '@kbn/ui-theme';

const CONTAINER_BREAKPOINT = 500;
const OPERATOR_WIDTH = 40;
const INPUT_WIDTH = 100;

export const mainContainer = css`
  container-type: inline-size;
`;

const baseStyle = css`
  flex-basis: 100%;
`;

export const dropdownContainer = cx(
  baseStyle,
  css`
    @container (min-width: ${CONTAINER_BREAKPOINT}px) {
      flex: 1;
      max-width: calc(
        100% - ${OPERATOR_WIDTH}px - ${INPUT_WIDTH}px - ${euiThemeVars.euiSizeL} -
          ${euiThemeVars.euiSizeL}
      );
    }
  `
);

export const operatorContainer = cx(
  baseStyle,
  css`
    justify-content: center;
    text-align: center;

    @container (min-width: ${CONTAINER_BREAKPOINT}px) {
      margin-top: ${euiThemeVars.euiSizeXL};
      justify-content: flex-start;
      flex: 0 0 40px;
    }
  `
);

export const input = cx(
  baseStyle,
  css`
    @container (min-width: ${CONTAINER_BREAKPOINT}px) {
      flex: 0 0 100px;
    }
  `
);

export const fieldSection = css`
  flex-wrap: wrap;
  gap: ${euiThemeVars.euiSizeS};

  @container (min-width: ${CONTAINER_BREAKPOINT}px) {
    gap: ${euiThemeVars.euiSizeL};
  }
`;
