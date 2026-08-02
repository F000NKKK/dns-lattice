# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-02

- Stage 0.2 (resolver engine and static split DNS): `dns-lattice`'s new
  `engine` module (`Resolver`, `ResolverBuilder`) — in-process
  construct/resolve, static split-DNS routing via `SplitDnsPolicy`, a new
  `dns_lattice_core::Error::NoRoute` variant for unroutable queries, and an
  in-memory TTL-respecting answer cache including RFC 2308 negative
  caching. No real network transport yet.

## [0.1.0] - 2026-08-02

- Repository bootstrap: workflow, policies, and packaging scaffolding.
- Stage 0.1 (core model): `dns-lattice-core` (shared `Error`/`Result`) and
  `dns-lattice-model` (DNS message, zone/domain matcher, split-DNS policy
  types) crates, with `dns-lattice` as the facade crate re-exporting them.
