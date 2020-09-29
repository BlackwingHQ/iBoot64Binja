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


## Symbol Definitions

Symbol definitions are in `defs.json` under the `data/` directory. Each symbol is modeled as a JSON object with the following properties:

- `fname`: Symbol name
- `type`: Symbol type (currently only `function`)
- `identifier`: Identifier to use to resolve symbol
- `heuristic`: Heuristic to use for symbol resolution (Currently supported heuristics are detailed below)
- `comment`: Symbol comment

The following heuristics are currently supported (will continue to support more):

### String reference (`stringref`)
Simple heuristic finds first occurance of `identifier` with cross-references, and names referenced function with `fname`.

Example:
```json
{
    "fname": "_do_go",
    "identifier": "Memory image not valid",
    "heuristic": "stringref"
}
```

### Byte Signature (`bytesig`)
Names first function containing signature defined in `identifier` (hex encoded sequence of bytes) as `fname`.
**Note:** `identifier` _must_ be a hex encoded sequence of bytes enclosed in quotation marks.

Example:
```json
{
    "fname": "_usb_dfu_init",
    "identifier": "E0031532020080D2",
    "heuristic": "bytesig"
}
```

### Constant (`constant`)
Names first function containing constant defined in `identifier` as `fname`.
**Note:** `identifier` can be one of the following:
- Numeric literal (e.g. 1234567)
- String containing 16, 32, or 64 bit hex number (e.g. "0xFACF", "0xFEEDFACF", "0xDEADBEEFFEEDFACF")

Examples:
```json
{
    "fname": "_macho_valid",
    "identifier": "0xFEEDFACF",
    "heuristic": "constant"
                
}
```
```json
{
    "fname": "_another_func",
    "identifier": 2293171722,
    "heuristic": "constant"
                
}
```


