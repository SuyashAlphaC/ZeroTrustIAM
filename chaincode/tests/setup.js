// Global Jest teardown to avoid fake timers and mocks leaking between files.
'use strict';

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});
