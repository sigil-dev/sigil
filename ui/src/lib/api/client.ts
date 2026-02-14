// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import createClient from "openapi-fetch";
import type { paths } from "./generated/schema";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:18789";

export const api = createClient<paths>({
  baseUrl: API_BASE,
});
