import { beforeEach } from "node:test";

import {
  enablePrivateSdkForTests,
  resetProcessResourcesForTests,
} from "../src/process-resources.js";

enablePrivateSdkForTests();
beforeEach(() => resetProcessResourcesForTests());
