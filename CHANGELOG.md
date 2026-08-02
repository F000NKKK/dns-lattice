# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Repository bootstrap: workflow, policies, and packaging scaffolding.
- Stage 0.1 (core model): `dns-lattice-core` (shared `Error`/`Result`) and
  `dns-lattice-model` (DNS message, zone/domain matcher, split-DNS policy
  types) crates, with `dns-lattice` as the facade crate re-exporting them.
