# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
FROM gcr.io/distroless/base-debian12
COPY sigil /usr/local/bin/sigil
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/sigil"]
CMD ["start"]
