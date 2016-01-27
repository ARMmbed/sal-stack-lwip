# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
## [1.1.4] - 2016-01-27
### Fixed
- Removed a race condition that was present on disconnect
- Call ```tcp_accepted``` with the correct pcb (#33)
- sal tests working again
### Added
- New accept API that uses both listener and new pcb
## [1.1.3] - 2016-01-22
### Fixed
- Receives of fragmented UDP packets are now handled correctly (#41)

## [1.1.2] - 2016-01-22
### Workaround
- Fix fast TCP output buffer race condition (#46)
- Fixes ARMmbed/sockets#41

## [1.1.1] - 2016-01-18
### Added
- Loopback defines for testing in testOptions.cmake

### Fixed
- C++11 compilation warnings
