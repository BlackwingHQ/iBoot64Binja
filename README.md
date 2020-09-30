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

### n String Refs (`nstringrefs`)
Names function with exactly `refcount` number of references to string `identifier` as `fname`.
**Note:** This heuristic is pretty weak. It will fail if the target refcount changes. 
**Note 2:** Binary Ninja's `get_code_refs()` uses a different method for counting Xrefs to a data address than IDA's `XrefsTo()`. 
`XrefsTo(addr)` returns direct references to the specified address, whereas `get_code_refs(addr)` also returns indirect references (i.e. via registers).
Therefore, xref counts will differ between IDA and Binja.

IDA's `XrefsTo`:

```python
Python>len([ref.frm for ref in idautils.XrefsTo(0x180108088)])
0x3
```

**First ref:**
![](https://user-images.githubusercontent.com/6217759/94699047-e8c7e180-0307-11eb-914e-ddae3de0746a.png)

**Second ref:**
![](https://user-images.githubusercontent.com/6217759/94699171-07c67380-0308-11eb-9129-18da15557f56.png)

**Third ref:**
![](https://user-images.githubusercontent.com/6217759/94699379-41977a00-0308-11eb-8b6f-8b1c3708b715.png)

Binary Ninja's `get_code_refs`:

```python
>>> len([ref.address for ref in bv.get_code_refs(0x180108088)])
8
```

![](https://user-images.githubusercontent.com/6217759/94697288-07c57400-0306-11eb-8d38-fb821bd0b779.png)

![](https://user-images.githubusercontent.com/6217759/94697475-3cd1c680-0306-11eb-83e6-bbaadc19dfd2.png)

![](https://user-images.githubusercontent.com/6217759/94697741-88847000-0306-11eb-84db-6f0bd3770137.png)

Example:
```json
{
    "fname": "_macho_load",
    "type": "function",
    "identifier": "__PAGEZERO",
    "refcount": 5,
    "comment": "",
    "heuristic": "nstringrefs"
}
```

