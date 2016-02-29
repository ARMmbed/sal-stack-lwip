# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [1.3.0]
### Improved
- Replaced `__get_PRIMASK()` and `__set_PRIMASK()` with `core_util_critical_section_enter()` and `core_util_critical_section_exit()`

### Fixed
- The ARM ABI requires that memory is aligned to 8 bytes. Change LwIP's `MEM_ALIGNMENT` define to 8 to match this requirement

### Added
- targetDependency on `sal-driver-lwip-nuvoton` meta module which will select the correct target dependency for nuvoton platforms

## [1.2.0]
### Fixed
- When saving UDP packets in interrupt context, do not call `pbuf_cat`, simply link the current pbuf to the last pbuf instead.

### Added
- As a convenience, when `recv` is called with `*len=0`, len is modified to the length of the available data (for TCP) or the length of the next datagram (for UDP)

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

[Unreleased]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/ARMmbed/sal-stack-lwip/compare/v1.1.0...v1.1.1
