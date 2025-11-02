# Changelog

All notable changes to this project will be documented in this file.

## [0.2.5](https://github.com/stack-rs/mitosis/compare/v0.2.4..v0.2.5) - 2025-11-02

### Features

- *(api)* Support reporter_uuid in task relevant interfaces - ([0ba07c2](https://github.com/stack-rs/mitosis-python-sdk/commit/0ba07c22e99321da369c033c306c501cbc346539))
- *(api)* Support batch operation for artifacts, attachments and tasks - ([ab47dd6](https://github.com/stack-rs/mitosis-python-sdk/commit/ab47dd6072791ca719573731ff32ed593e8f5d3f))
- *(api)* Support batch cancellation of tasks and workers by uuid - ([989bbac](https://github.com/stack-rs/mitosis-python-sdk/commit/989bbac2c17124cc6967b79b53146d9ff75a5343))
- *(api)* Support batch download of artifacts and attachments - ([1e3fc0a](https://github.com/stack-rs/mitosis-python-sdk/commit/1e3fc0acd917f90abcc54dc3e7200fea3816cc15))
- *(api)* Support batch cancellation of tasks and workers - ([252cf84](https://github.com/stack-rs/mitosis-python-sdk/commit/252cf841e7ab7d23faa8aee6ec8d1a18eae4b105))

### Refactor

- *(schema)* [**breaking**] Rename key_prefix to key in query - ([da71099](https://github.com/stack-rs/mitosis-python-sdk/commit/da710998e74d2a0b22b179cb9bc6cf0c18f6a2ff))

### Documentation

- *(readme)* Update support version table - ([ca72cc9](https://github.com/stack-rs/mitosis-python-sdk/commit/ca72cc97f7d049adc8ae554c852c843269c1a0b7))

### Miscellaneous Tasks

- Add bump script - ([fe7b9a8](https://github.com/stack-rs/mitosis-python-sdk/commit/fe7b9a8ec090eacead686e231f89bdbf44e38760))

## [0.2.4](https://github.com/stack-rs/mitosis/compare/v0.2.3..v0.2.4) - 2025-10-20

### Features

- *(schema)* Support labels in workers query interface - ([84c1621](https://github.com/stack-rs/mitosis-python-sdk/commit/84c1621d4b79bd005b5008e0c575f8658fd8b23b))

## [0.2.3](https://github.com/stack-rs/mitosis/compare/v0.2.2..v0.2.3) - 2025-09-26

### Features

- *(api)* Support the change user group-quota API - ([b898e17](https://github.com/stack-rs/mitosis-python-sdk/commit/b898e17fd63606edc3c3573f6d463dc6a354432a))

## [0.2.2](https://github.com/stack-rs/mitosis/compare/v0.2.1..v0.2.2) - 2025-09-15

### Features

- *(schema)* Add new fields to task query result - ([3801f0e](https://github.com/stack-rs/mitosis-python-sdk/commit/3801f0e3807ae3a370b68ff61645d98e4d50676f))

## [0.2.1](https://github.com/stack-rs/mitosis/compare/v0.2.0..v0.2.1) - 2025-09-11

### Bug Fixes

- Delete redundant print - ([da26809](https://github.com/stack-rs/mitosis-python-sdk/commit/da2680902b261892dc5daa93dbd4573390998df2))

## [0.2.0](https://github.com/stack-rs/mitosis/compare/v0.1.3..v0.2.0) - 2025-09-11

### Features

- *(api)* Support new worker update labels api - ([5bfbe27](https://github.com/stack-rs/mitosis-python-sdk/commit/5bfbe270f9e003fd2f63445b55eecffb3fbcb2b0))
- *(api)* Update delete operations to latest netmito - ([a74aaa3](https://github.com/stack-rs/mitosis-python-sdk/commit/a74aaa37c17ba00a3ab76eb840d201747c869126))

## [0.1.3](https://github.com/stack-rs/mitosis/compare/v0.1.2..v0.1.3) - 2025-09-05

### Documentation

- *(readme)* Add usage guidance - ([9676e41](https://github.com/stack-rs/mitosis-python-sdk/commit/9676e4118e56e0af3fee29c474c1d04d16655b57))

## [0.1.2](https://github.com/stack-rs/mitosis/compare/v0.1.1..v0.1.2) - 2025-09-05

### Bug Fixes

- *(types)* Resolve json serialization errors - ([05ba93a](https://github.com/stack-rs/mitosis-python-sdk/commit/05ba93ab7384c8b0a3827c95b6ef426572b3fb94))

## [0.1.1](https://github.com/stack-rs/mitosis/compare/v0.1.0..v0.1.1) - 2025-09-05

### Bug Fixes

- *(schema)* Resolve TasksQueryReq (de)serde issue - ([1c7505b](https://github.com/stack-rs/mitosis-python-sdk/commit/1c7505be60dce85fdb8b4a3319c27c2f5e83f180))

## [0.1.0](https://github.com/stack-rs/mitosis/compare/v0.0.3..v0.1.0) - 2025-09-05

### Features

- *(schema)* Replace str field with enum class - ([f673bc7](https://github.com/stack-rs/mitosis-python-sdk/commit/f673bc70cc6f85734510964cd6920a3f7ff8035a))

## [0.0.3](https://github.com/stack-rs/mitosis/compare/v0.0.2..v0.0.3) - 2025-09-05

### Features

- *(schema)* Add more SDK interfaces - ([49ca526](https://github.com/stack-rs/mitosis-python-sdk/commit/49ca5267b25d79f75421f15cf9bfc1097d456ad3))

## [0.0.2](https://github.com/stack-rs/mitosis/compare/v0.0.1..v0.0.2) - 2025-09-04

### Features

- *(schema)* Add (de)serialization for timedelta fields - ([0abaa12](https://github.com/stack-rs/mitosis-python-sdk/commit/0abaa12274246ac64ababc3b76585343557ad5dc))
- *(schema)* Add (de)serialization for datetime fields - ([4445391](https://github.com/stack-rs/mitosis-python-sdk/commit/4445391be40c053035abea26273f3dc6a5453f51))

### Miscellaneous Tasks

- *(publish)* Adjust publishing params - ([c1a2a05](https://github.com/stack-rs/mitosis-python-sdk/commit/c1a2a059ee1adfb5bd7f0dd54bd18717504b1239))
- *(release)* Use static version instead of dynamic - ([761644f](https://github.com/stack-rs/mitosis-python-sdk/commit/761644fc5a3a888a89bca82aefd177941ef37946))

## [0.0.1](https://github.com/stack-rs/mitosis/releases/tag/v0.0.1) - 2025-09-03

### Features

- Add basic client SDK for core APIs - ([decaf80](https://github.com/stack-rs/mitosis-python-sdk/commit/decaf80d049f3419a5cae7612462a05455e2a82e))

### Miscellaneous Tasks

- Add publish utilities - ([d9a7ca0](https://github.com/stack-rs/mitosis-python-sdk/commit/d9a7ca03108b6ad5c0676bc508040968f580ab02))

