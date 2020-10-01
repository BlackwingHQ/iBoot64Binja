# iBoot64Binja (v0.1.0)

_Binary View for loading iBoot, SecureROM, etc. firmware_

![](https://user-images.githubusercontent.com/6217759/94852197-83531e00-03f7-11eb-95c7-0f0f500fb004.png)

## Description 
Binary Ninja Binary View plugin for analyzing iBoot, SecureROM, etc. heavily inspired by @argp's iBoot64helper IDA loader (https://github.com/argp/iBoot64helper).	
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

## License

This plugin is released under a MIT license.

## Symbol Definitions

Symbol definitions are in `defs.json` under the `data/` directory. Each symbol is modeled as a JSON object with the following properties:

- `name`: Symbol name
- `type`: Symbol type (currently only `function`)
- `identifier`: Identifier to use to resolve symbol
- `heuristic`: Heuristic to use for symbol resolution (Currently supported heuristics are detailed below)
- `comment`: Symbol comment

The following heuristics are currently supported (will continue to support more):

### String reference (`stringref`)
Simple heuristic finds first occurance of `identifier` with cross-references, and names referenced function with `name`.

Example:
```json
{
    "name": "_do_go",
    "identifier": "Memory image not valid",
    "heuristic": "stringref"
}
```

### Byte Signature (`bytesig`)
Names first function containing signature defined in `identifier` (hex encoded sequence of bytes) as `name`.
**Note:** `identifier` _must_ be a hex encoded sequence of bytes enclosed in quotation marks.

Example:
```json
{
    "name": "_usb_dfu_init",
    "identifier": "E0031532020080D2",
    "heuristic": "bytesig"
}
```

### Constant (`constant`)
Names first function containing constant defined in `identifier` as `name`.
**Note:** `identifier` can be one of the following:
- Numeric literal (e.g. 1234567)
- String containing 16, 32, or 64 bit hex number (e.g. "0xFACF", "0xFEEDFACF", "0xDEADBEEFFEEDFACF")

Examples:
```json
{
    "name": "_macho_valid",
    "identifier": "0xFEEDFACF",
    "heuristic": "constant"
                
}
```
```json
{
    "name": "_another_func",
    "identifier": 2293171722,
    "heuristic": "constant"
                
}
```

### n String Refs (`nstringref`)
Names function with exactly `occurances` number of references to string `identifier` as `name`.
**Note:** This heuristic is pretty weak. It will fail if the target refcount changes. 
**Note 2:** Binary Ninja's `get_code_refs()` uses a different method for counting Xrefs to a data address than IDA's `XrefsTo()`. 
`XrefsTo(addr)` returns direct references to the specified address, whereas `get_code_refs(addr)` also returns indirect references (i.e. via registers).
Therefore, xref counts will differ between IDA and Binja.

Example:
```json
{
    "name": "_macho_load",
    "type": "function",
    "identifier": "__PAGEZERO",
    "refcount": 5,
    "comment": "",
    "heuristic": "nstringrefs"
}
```

**Note:** This heuristic is pretty weak. It will fail if the target refcount changes. 

**Note 2:** Binary Ninja's `get_code_refs()` uses a different method for counting Xrefs to a data address than IDA's `XrefsTo()`. 
`XrefsTo(addr)` returns direct references to the specified address, whereas `get_code_refs(addr)` also returns indirect references (i.e. via registers).
Therefore, xref counts will differ between IDA and Binja.

IDA's `XrefsTo`:

```python
Python>len([ref.frm for ref in idautils.XrefsTo(0x180108088)])
0x3
```

**Direct Reference**

![](https://user-images.githubusercontent.com/6217759/94699047-e8c7e180-0307-11eb-914e-ddae3de0746a.png)


Binary Ninja's `get_code_refs` (same binary):

```python
>>> len([ref.address for ref in bv.get_code_refs(0x180108088)])
8
```

**Direct Reference**

![](https://user-images.githubusercontent.com/6217759/94697288-07c57400-0306-11eb-8d38-fb821bd0b779.png)

**Indirect Reference**

![](https://user-images.githubusercontent.com/6217759/94697475-3cd1c680-0306-11eb-83e6-bbaadc19dfd2.png)

**Indirect Reference**

![](https://user-images.githubusercontent.com/6217759/94697741-88847000-0306-11eb-84db-6f0bd3770137.png)



