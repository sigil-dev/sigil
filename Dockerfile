# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
FROM gcr.io/distroless/base-debian12
COPY sigil /usr/local/bin/sigil
USER nonroot:nonroot

# Recommended runtime flags for production deployments:
#   --cap-drop=ALL                       Drop all Linux capabilities
#   --read-only                          Mount root filesystem as read-only
#   --tmpfs /tmp                         Writable tmpfs if /tmp is needed
#   --security-opt=no-new-privileges     Prevent privilege escalation

# Note: distroless/base does not include wget or curl.
# Use an external liveness probe (e.g. Kubernetes httpGet on /health).

ENTRYPOINT ["/usr/local/bin/sigil"]
CMD ["start"]
