# iBoot64Binja

## Introduction
Binary Ninja Binary View plugin for analyzing iBoot, SecureROM, etc. heavily inspired by @argp's iBoot64helper IDA loader (https://github.com/argp/iBoot64helper).

- Identifies iBoot / SecureROM firmwares
- Finds target load address and performs rebase for accurate analysis
- Restores some interesting symbols based on various heuristics

## Installation

### Direct Copy Into Binja Plugin Directory

Copy iBoot64Binja directory to Binja plugin directory
- OS X: `~/Library/Application Support/Binary Ninja/plugins/`
- Linux: `~/.binaryninja/plugins/`
- Windows: `%APPDATA%\Binary Ninja\plugins`

### Binary Ninja Plugin Manager GUI (Not yet supported)

- (Linux/Windows) `[CTRL-SHIFT-M]`
- (MacOS) `[CMD-SHIFT-M]`

