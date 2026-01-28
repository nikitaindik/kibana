import { sleep } from 'k6';

export function wait({ min, max }: { min: number; max: number }) {
  return sleep(Math.random() * (max - min) + min);
}

const MAX_BACKOFF = 30000;

/**
 * Calculates a backoff delay using an exponential growth formula, capped by a
 * predefined maximum value.
 *
 * @param failedAttempts - The number of consecutive failed attempts.
 * @returns The calculated backoff delay, in milliseconds.
 */
export function cappedExponentialBackoff(failedAttempts: number) {
  const backoff = Math.min(1000 * 2 ** failedAttempts, MAX_BACKOFF);
  return backoff;
}
