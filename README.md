# Qualref

Evaluate Qualification requests directly from the specification, using
exact selected evidence and a separate clock solver. The reference accepts
one JSON request on standard input and emits one JSON response.

```sh
qualref serve-process --clockcheck /path/to/clockcheck < request.json
qualref serve-process --spec-dir /path/to/qualification/schema < request.json
```

The specification dependency supplies the schemas and contexts.
For development, a trusted local schema directory can also be supplied. The reference uses the standard
library. It compiles clock evidence to the Clockcheck process format and
checks returned assignments against the submitted bounds. It uses the
`clockcheck` executable from PATH by default. A timed input can remain
unresolved if the solver is unavailable or exceeds its allowance.

The process also evaluates bound use transfer and verifies the fixed JSON
and RDF envelopes. Install matching drafts of the specification and native
Clockcheck when running the conformance suite.

Apache-2.0.

Copyright 2026 Mariia Steeghs-Turchina
