# Copyright (c) 2020 Blackwing Intelligence
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from io import open

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, BinaryReader, BinaryWriter
from binaryninja.enums import SymbolType, SegmentFlag
from binaryninja.types import Symbol, Type
from binaryninja import Endianness, log_info, log_error
from binaryninja.typeparser import TypeParser
from binaryninja.settings import Settings, SettingsScope
import binascii
import json
import os
import struct
import traceback
import urllib.request
import ssl
import yaml

CUR_FILE_PATH = os.path.dirname(os.path.abspath(__file__))
IBOOT_H_PATH = os.path.join(CUR_FILE_PATH, '..', 'data', 'iboot.h')
REGISTERS_PATH = os.path.join(CUR_FILE_PATH, '..', 'data', 'registers.yaml')
DEFS_JSON = os.path.join(CUR_FILE_PATH, '..', 'data', 'defs.json')


def load_datafile(url, file_path):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with urllib.request.urlopen(url, context=ctx) as u, open(file_path, 'wb') as f:
        f.write(u.read())


load_datafile("https://raw.githubusercontent.com/hack-different/symbol-server/main/shared/iboot.h", IBOOT_H_PATH)
load_datafile("https://raw.githubusercontent.com/hack-different/apple-knowledge/main/_data/registers.yaml",
              REGISTERS_PATH)

use_default_loader_settings = True


class iBoot64View(BinaryView):
    name: str = "iBoot64Binja"
    long_name: str = "iBoot64 View"
    load_address = 0x0
    PROLOGUES = [b"\xBD\xA9", b"\xBF\xA9"]

    def __init__(self, data):
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        self.writer = BinaryWriter(data, Endianness.LittleEndian)
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data
        self.parser = TypeParser['ClangTypeParser']
        self.settings = Settings()
        self.registers = {}

    def init(self):
        self.set_analysis_hold(True)

        self.settings.set_integer('analysis.hlil.maxIntermediateConditionComplexity', 4048586, self,
                                  SettingsScope.SettingsResourceScope)
        self.settings.set_bool('analysis.linearSweep.permissive', True, self, SettingsScope.SettingsResourceScope)

        self.raw = self.data
        self.add_analysis_completion_event(self.on_complete)
        try:
            self.isSecureROM = self.raw.read(0x200, 9) == b"SecureROM"

            self.log(f"Loading {'SecureROM' if self.isSecureROM else 'iBoot'}")

            load_settings = self.get_load_settings(self.name)
            if load_settings is None:
                print("Load Settings is None")
                self.arch = Architecture['aarch64']
                self.platform = self.arch.standalone_platform
                # return True
                self.load_address = self.find_reset(self.data)
                if self.load_address == -1:
                    print("Error: Could not find reset vector!")
                    self.load_address = 0
                print("LOAD ADDRESS: " + hex(self.load_address))
                # self.add_auto_segment(0, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable)
            else:
                print("Load Settings: ")
                print(load_settings)
                arch = load_settings.get_string("loader.architecture", self)
                self.arch = Architecture[arch]
                self.platform = self.arch.standalone_platform
                # self.platform = Architecture['aarch64'].standalone_platform
                self.load_address = int(load_settings.get_string("loader.imageBase", self))

            self.add_auto_segment(self.load_address, self.parent_view.length, 0, self.parent_view.length,
                                  SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_entry_point(self.load_address)
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.load_address, '_start'))

            self.set_analysis_hold(False)
            self.update_analysis()

            return True
        except:
            print(traceback.format_exc())
            return False

    def log(self, msg, error=False):
        msg = f"[iBoot-Loader] {msg}"
        if not error:
            log_info(msg)
        else:
            log_error(msg)

    @classmethod
    def is_valid_for_data(cls, data):
        try:
            version_offset = 0x280
            if (
                    data.read(version_offset, 5) == b'iBoot'
                    or data.read(version_offset, 4) == (b'iBEC' or b'iBSS')
                    or data.read(version_offset, 9) == b'SecureROM'
                    or data.read(version_offset, 9) == b'AVPBooter'
            ):
                return True
            return False
        except AttributeError:
            return False

    @classmethod
    def get_load_settings_for_data(cls, data):
        load_settings = Settings("mapped_load_settings")
        if use_default_loader_settings:
            load_settings = cls.registered_view_type.get_default_load_settings_for_data(data)
            # specify default load settings that can be overridden (from the UI)
            overrides = ["loader.architecture", "loader.platform", "loader.entryPoint", "loader.imageBase",
                         "loader.segments", "loader.sections"]
            for override in overrides:
                if load_settings.contains(override):
                    load_settings.update_property(override, json.dumps({'readOnly': False}))

            # override default setting value
            load_settings.update_property("loader.imageBase", json.dumps({'default': 0}))
            load_settings.update_property("loader.entryPoint", json.dumps({'default': 0}))

            # # add custom arch setting
            # load_settings.register_setting("loader.my_custom_arch.customLoadSetting",
            #     '{"title" : "My Custom Load Setting",\
            #     "type" : "boolean",\
            #     "default" : false,\
            #     "description" : "My custom load setting description."}')

        return load_settings

    def perform_get_entry_point(self):
        return self.load_address

    def perform_is_executable(self):
        return True

    def perform_is_relocatable(self):
        return True

    def perform_get_address_size(self):
        return self.arch.address_size

    # def find_reset_capstone(self, data):
    #     CODE = data[:1000]
    #     md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    #     md.detail = True
    #     for i in md.disasm(CODE, 0x0):
    #         if i.mnemonic == 'ldr':
    #             offset = int(i.operands[1].value.imm)
    #             return struct.unpack("Q", CODE[offset:offset + 8])[0]

    def load_defs(self):
        cur_file_path = os.path.dirname(os.path.abspath(__file__))
        symbol_file_path = os.path.join(cur_file_path, '..', 'data', 'defs.json')
        print("Trying to load defs file at: {}".format(symbol_file_path))
        with open(symbol_file_path, 'r') as f:
            return json.load(f)

    def on_complete(self) -> None:
        print("[+] Analysis complete. Finding interesting functions...")
        self.find_interesting()

    def resolve_string_refs(self, defs):
        string_refs = list([sym for sym in defs['symbol'] if sym['heuristic'] == "stringref"])
        for sym in string_refs:
            if self.define_func_from_stringref(sym['identifier'], sym['name']) is None:
                print("[!] Can't find function {}".format(sym['name']))

    def resolve_n_string_refs(self, defs):
        stringrefs = list([sym for sym in defs['symbol'] if sym['heuristic'] == "nstringrefs"])
        for sym in stringrefs:
            try:
                refcount = sym['refcount']
                if isinstance(refcount, int):
                    if self.define_func_from_n_stringrefs(sym['identifier'], sym['name'], sym['refcount']) is None:
                        print("[!] Can't find function {}".format(sym['name']))
            except:
                print("[!] Bad refcount for symbol {}: {}".format(sym['name'], sym['refcount']))
                continue

    def resolve_byte_sig_pattern(self, identifier):
        pattern = []
        for byte in identifier.split(' '):
            if byte == '?':
                pattern.append(byte)
            elif byte != '':
                pattern.append(int(byte, 16))
        br = BinaryReader(self)
        result = 0
        length = len(pattern) - 1
        for function in self.functions:
            br.seek(function.start)

            while self.get_functions_containing(
                    br.offset + length) is not None and function in self.get_functions_containing(br.offset + length):
                found = True
                count = 0
                for entry in pattern:
                    byte = br.read8()
                    count += 1
                    if entry != byte and entry != '?':
                        found = False
                        break

                br.offset -= count

                if found:
                    result = br.offset
                    break

                instruction_length = self.get_instruction_length(br.offset)
                # account for unknown or bad instruction
                if instruction_length == 0:
                    break
                br.offset += instruction_length

            if result != 0:
                break
        if result == 0:
            return None
        else:
            return self.get_functions_containing(result)[0].lowest_address

    def resolve_byte_sigs(self, defs):
        bytesigs = [sym for sym in defs['symbol'] if sym['heuristic'] == "bytesig"]
        for sym in bytesigs:
            if "?" in sym['identifier']:
                addr = self.resolve_byte_sig_pattern(sym['identifier'])
                if addr:
                    self.define_function_at_address(addr, sym['name'])
                else:
                    print("[!] Can't find function {}".format(sym['name']))
            else:
                try:
                    signature = binascii.unhexlify(sym['identifier'])
                except binascii.Error:
                    print("[!] Bad Signature for {}! Must be hex encoded string, got: {}.".format(sym['name'],
                                                                                                  sym['identifier']))
                    return
                if self.define_func_from_bytesignature(signature, sym['name']) is None:
                    print("[!] Can't find function {}".format(sym['name']))

    def resolve_constants(self, defs):
        constants = [sym for sym in defs['symbol'] if sym['heuristic'] == "constant"]
        for sym in constants:
            const = self.convert_const(sym['identifier'])
            if const is None:
                print("[!] Bad constant definition for symbol {}: {}".format(sym['name'], sym['identifier']))
            elif self.define_func_from_constant(const, sym['name']) is None:
                print("[!] Can't find function {}".format(sym['name']))

    def resolve_xrefs_to(self, defs):
        xrefs = [sym for sym in defs['symbol'] if sym['heuristic'] == "xrefsto"]
        for sym in xrefs:
            if self.define_func_from_xref_to(sym['identifier'], sym['name']) is None:
                print("[!] Can't find function {}".format(sym['name']))

    @staticmethod
    def convert_const(const):
        try:
            if isinstance(const, int):
                return const
            bin_const = binascii.unhexlify(const.replace('0x', ''))
            if len(bin_const) == 2:
                fmt = ">H"
            elif len(bin_const) == 4:
                fmt = ">I"
            elif len(bin_const) == 8:
                fmt = ">Q"
            else:
                return None
            return struct.unpack(fmt, bin_const)[0]
        except:
            return None

    def find_interesting(self):
        defs = self.load_defs()

        self.resolve_string_refs(defs)

        self.resolve_byte_sigs(defs)

        self.resolve_constants(defs)

        self.resolve_n_string_refs(defs)

        self.resolve_xrefs_to(defs)

        self.resolve_special_instructions()

        self.resolve_special_registers()

        if os.path.exists(IBOOT_H_PATH):
            self.log("Adding iBoot Header")
            with open(IBOOT_H_PATH) as iboot_h:
                (type_result, errors) = self.parser.parse_types_from_source(iboot_h.read(), "iboot.h", self.platform)
                if type_result:
                    for type in type_result.types:
                        self.define_type(Type.generate_auto_type_id("iboot.h", type.name), type.name, type.type)

    def resolve_special_registers(self):
        if os.path.exists(REGISTERS_PATH):
            self.log(f"Loading registers from #{REGISTERS_PATH}")
            with open(REGISTERS_PATH) as registers:
                self.registers = yaml.load(registers, yaml.Loader)['aarch64']
                self.registers['msr'] = dict({key.lower(): value for key, value in self.registers['msr'].items()})
                self.registers['apple_system_registers'] = dict(
                    {key.lower(): value for key, value in self.registers['apple_system_registers'].items()})
                self.log(f"Loaded #{len(self.registers['msr'])} MSR names")
                self.log(f"Loaded #{len(self.registers['apple_system_registers'])} Apple Register names")

        if 'msr' not in self.registers:
            return None

        for reg_type in ['msr ', 'mrs ']:
            self.log("Resolving MSR instructions")
            ptr = self.start
            while ptr is not None and ptr < self.end:
                ptr = self.find_next_text(ptr, reg_type)
                if isinstance(ptr, int):
                    inst_bytes = self.read(ptr, self.arch.max_instr_length)
                    inst_info = self.arch.get_instruction_info(inst_bytes, ptr)
                    reg, _i = next(self.disassembly_text(ptr))
                    reg = reg.split(' ', maxsplit=1)[1].split(',')[0].lower().strip()
                    if reg in self.registers['msr'].keys():
                        resolved_reg = self.registers['msr'][reg]
                        self.set_comment_at(ptr, f"{resolved_reg['name']}: {resolved_reg['description']}")
                        self.log(f"Found MSR: {reg} @ {ptr:#08x}")
                    elif reg in self.registers['apple_system_registers'].keys():
                        resolved_reg = self.registers['apple_system_registers'][reg]
                        self.set_comment_at(ptr, f"{resolved_reg['name']}: {resolved_reg['description']}")
                        self.log(f"Found Apple Register: {reg} @ {ptr:#08x}")
                    else:
                        self.log(f"Couldn't find MSR: {reg} @ {ptr:#08x}")
                    ptr += inst_info.length

    def resolve_special_instructions(self):
        self.log("Resolving `hint` instructions")
        ptr = self.start
        while ptr is not None and ptr < self.end:
            ptr = self.find_next_text(ptr, 'hint    #0x45')
            if isinstance(ptr, int):
                self.set_comment_at(ptr, 'hint 0x45 would enable the debugger on simulated hardware')
                inst_bytes = self.read(ptr, self.arch.max_instr_length)
                inst_info = self.arch.get_instruction_info(inst_bytes, ptr)
                ptr += inst_info.length

    def find_reset(self, data):
        self.base = None
        for addr in range(0, 0x200, 4):
            inst = self.raw.get_disassembly(addr, Architecture['aarch64'])
            if "ldr" in inst:
                self.reader.seek(int(inst.split(" ")[-1], 16))
                self.base = self.reader.read64()
                return self.base

        if self.base is None:
            self.log("Failed to find entry point", error=True)
            return False

    def define_func_from_stringref(self, needle, func_name):
        if isinstance(needle, str):
            needle = bytes(needle, 'utf8')

        ptr = self.start
        while ptr < self.end:
            # using bv.find_next_data instead of bv.find_next_text here because it seems to be _way_ faster
            # ptr = self.find_next_text(ptr, needle)
            # ptr = self.find_next_data(ptr, bytes(needle.encode("utf-8")))
            ptr = self.find_next_data(ptr, needle)

            if not ptr:
                break
            refs = list(self.get_code_refs(ptr))
            if refs:
                func_start = refs[0].function.lowest_address
                self.define_function_at_address(func_start, func_name)
                # self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, func_start, func_name))
                # print("[+] Added function {} at {}".format(func_name, hex(func_start)))
                return func_start
            else:
                ptr = ptr + 1
        return None

    def define_func_from_n_stringrefs(self, needle, func_name, refcount):
        ptr = self.start
        while ptr < self.end:
            refs = []
            ptr = self.find_next_data(ptr, needle)
            if not ptr:
                break
            for ref in list(self.get_code_refs(ptr)):
                refs.append(ref.function.lowest_address)
            for func_start in refs:
                if refs.count(func_start) == refcount:
                    self.define_function_at_address(func_start, func_name)
                    return func_start
            ptr = ptr + 1
        return None

    def define_func_from_bytesignature(self, signature, func_name):
        ptr = self.start
        while ptr < self.end:
            # Have to convert signature byearray to a string since find_next_data can't handle bytes on stable
            # fixed on dev in: https://github.com/Vector35/binaryninja-api/commit/c18b89e4cabfc28081a7893ccd4cf8956c9a797f
            signature = b"".join(chr(x) for x in signature)
            ptr = self.find_next_data(ptr, signature)
            if not ptr:
                break
            # Only finds first occurance of signature - might want to warn if muliple hits...
            func_start = self.get_functions_containing(ptr)[0].lowest_address
            self.define_function_at_address(func_start, func_name)
            return func_start
        return None

    def define_func_from_constant(self, const, func_name):
        ptr = self.start
        while ptr < self.end:
            ptr = self.find_next_constant(ptr, const)
            if not ptr:
                break
            func_start = self.get_functions_containing(ptr)[0].lowest_address
            self.define_function_at_address(func_start, func_name)
            return func_start
        return None

    def define_func_from_xref_to(self, ref, func_name):
        ptr = self.start
        while ptr < self.end:
            syms = self.get_symbols_by_name(ref)
            if len(syms) != 1:
                return None
            if syms[0].type != SymbolType.FunctionSymbol:
                return None
            ptr = syms[0].address
            if not ptr:
                break
            func_start = self.get_code_refs(ptr)[0].function.start
            self.define_function_at_address(func_start, func_name)
            return func_start
        return None

    def define_function_at_address(self, address, name):
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, address, name))
        print("[+] Added function {} at {}".format(name, hex(address)))

    # def define_func_from_bytesig(self, signature, func_name):
    #     ptr = self.start
    #     addrs = []
    #     while ptr < self.end:
    #         ptr = self.find_next_data
