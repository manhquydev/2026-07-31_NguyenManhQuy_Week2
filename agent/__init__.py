"""Sentinel Recon & Analysis agent (Week 4).

Read-only reconnaissance: consumes the SAST/DAST lake and the threat-intel RAG, reaches the
target only through the Kong agent-recon identity, and emits a schema-validated Attack Surface
Map. All model access goes through the provenance-aware client so target-derived content stays
labelled as untrusted data.
"""
