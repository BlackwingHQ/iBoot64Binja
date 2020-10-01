# iBoot64Binja (v1.0)

_Binary View for loading iBoot, SecureROM, etc. firmware_

![](https://user-images.githubusercontent.com/6217759/94852197-83531e00-03f7-11eb-95c7-0f0f500fb004.png)

## Description 
Binary Ninja Binary View plugin for analyzing iBoot, SecureROM, etc. heavily inspired by [argp's iBoot64helper IDA loader](https://github.com/argp/iBoot64helper).	
- Identifies iBoot / SecureROM firmwares	
- Finds target load address and performs rebase for accurate analysis	
- Restores some interesting symbols based on various heuristics

## Installation Instructions

### Darwin

Copy to `~/Library/Application Support/Binary Ninja/plugins/` or use Plugin Manager

### Windows

Copy to `%APPDATA%\Binary Ninja\plugins` or use Plugin Manager

### Linux

Copy to `~/.binaryninja/plugins/` or use Plugin Manager

## Minimum Version

This plugin has been tested with the following minimum version of Binary Ninja:

* 2.1.2263

## Documentation

Documentation on current heuristics, etc. is [here](docs/docs.md).

## License

This plugin is released under a MIT license.

## Acknowledgments

- Argp's [iBoot64Helper](https://github.com/argp/iBoot64helper) iBoot loader for IDA Pro inspired the initial development of this plugin
- [binja_sigmaker](https://github.com/apekros/binja_sigmaker) inspired the current wildcard signature matching for the `bytesig` heuristic
