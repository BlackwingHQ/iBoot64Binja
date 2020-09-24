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

# from binaryninja import log
# from binaryninja import _binaryninjacore as core
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, AnalysisCompletionEvent
from binaryninja.enums import SymbolType, SegmentFlag
from binaryninja.types import Symbol
from binaryninja import Settings
# from binaryninja.binaryview import BinaryViewType
# from capstone import *
# from capstone.arm64 import *
# import json
import struct
import traceback

use_default_loader_settings = True


# def disassemble(arch, data):
#     i = 0
#     out = []
#     while i < len(data):
#         instr, width = arch.get_instruction_text(data[i:], 0)
#         # Do stuff with instr
#         out.append(instr)
#         if width == 0:
#             continue
#         i += width
#     return out

class iBoot64View(BinaryView):
    name = "iBoot64Binja"
    long_name = "iBoot64 View"
    load_address = 0x0

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        self.raw = self.data
        self.add_analysis_completion_event(self.on_complete)
        try:
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

            self.add_auto_segment(self.load_address, len(self.parent_view), 0, len(self.parent_view),
                                  SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_entry_point(self.load_address)
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.load_address, '_start'))
            self.update_analysis()
            # self.find_interesting()

            return True
        except:
            print(traceback.format_exc())
            return False

    @classmethod
    def is_valid_for_data(self, data):
        try:
            iBootVersionOffset = 0x280
            iboot_version = data.get_ascii_string_at(iBootVersionOffset).value
            if iboot_version.startswith("iBoot"):
                # Save version to global for future ref?
                return True
            return False
        except AttributeError:
            return False

    @classmethod
    def get_load_settings_for_data(self, data):
        load_settings = Settings("mapped_load_settings")
        if use_default_loader_settings:
            load_settings = self.registered_view_type.get_default_load_settings_for_data(data)
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

    def on_complete(self, blah):
        print("[+] Analysis complete. Finding interesting functions...")
        self.find_interesting()

    def find_interesting(self):
        # self.find_panic()
        refs = {
            "string_reftype":
            [
                {
                    "fname": "_panic",
                    "identifier": "double panic in ",
                },
                {
                    "fname": "_aes_crypto_cmd",
                    "identifier": "aes_crypto_cmd",
                },
                {
                    "fname": "_main_task",
                    "identifier": "debug-uarts",
                },
                {
                    "fname": "_UpdateDeviceTree",
                    "identifier": "development-cert",
                },
                {
                    "fname": "_pmgr_binning_mode_get_value",
                    "identifier": "Invalid low",
                },
                {
                    "fname": "_do_printf",
                    "identifier": "<ptr>",
                },
                    
            ]
        }
        for ref in refs["string_reftype"]:
            if self.define_func_from_stringref(ref["identifier"], ref["fname"]) == None:
                print("[!] Can't find function {}".format(ref["fname"]))
        # self.define_func_from_string("double panic in ", "_panic")
        
    def find_reset(self, data):
        i = 0
        end = data.find_next_data(0, b'iBoot for')
        if end is None:
            end = data.find_next_data(0, b'SecureROM for')
            if end is None:
                return None
        while i < end:
            # Hacky way to hand disassemble. Better than requiring capstone...
            instr, width = self.arch.get_instruction_text(data[i:], 0)
            try:
                if instr[0].text == 'ldr':
                    # Add current address to ldr argument for offset
                    offset = instr[4].value + i
                    return struct.unpack("Q", data[offset:offset + 8])[0]
                i += width
            except TypeError:
                i += 1
                continue
        return None

    def find_panic(self):
        ptr = self.start
        while ptr < self.end:
            ptr = self.find_next_data(ptr, b'double panic in ')

            refs = self.get_code_refs(ptr)
            if refs:
                for i in refs:
                    func_start = i.function.lowest_address
                    # self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, func_start, '_panic'))
                    self.define_user_symbol(Symbol(SymbolType.FunctionSymbol, func_start, '_panic'))
                    # TODO: Improve - Currently breaks on first ref
                    return func_start
            else:
                ptr = ptr + 1
        # Not sure the Binja idiomatic thing to return
        # return -1
        return None

    def define_func_from_stringref(self, needle, func_name):
        ptr = self.start
        while ptr < self.end:
            ptr = self.find_next_data(ptr, bytes(needle.encode("utf-8")))
            if not ptr:
                break
            refs = self.get_code_refs(ptr)
            if refs:
                func_start = refs[0].function.lowest_address
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, func_start, func_name))
                print("[+] Added function {} at {}".format(func_name, hex(func_start)))
                return func_start
            else:
                ptr = ptr + 1
        return None


iBoot64View.register()

