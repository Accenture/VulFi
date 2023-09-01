from ast import expr_context
from cmath import exp
import collections
from email.policy import default
from uuid import RESERVED_FUTURE
import idaapi
import idc
import ida_ua
import os
import json
import idautils
import ida_kernwin
import ida_name
import ida_hexrays
import ida_funcs
import traceback


icon = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00*\x00\x00\x00&\x08\x06\x00\x00\x00\xb2\x01\t \x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs\x00\x00\x0e\xc3\x00\x00\x0e\xc3\x01\xc7o\xa8d\x00\x00\x02TIDATXG\xcd\x98\xcd.\x03Q\x14\xc7\xef\x10\x14-\xd5\xf8Jj!x\x00+,\xc5\x03\x88\x07\xb0\xb0\xb2\xea\x82\'\xc0\x13\x90\xb0\x15\x8f\x80x\x00+k\x89\xd8\x93\xb0\x94\xb0\x13A\xc6\xf9\xb7skz\xe7\xcc\xf4\xdc\xf9\xec/\xf9\xa5\x9d\x99\xce\xbdg\xce\xdc9\xf7N\x15\xb1@\x1e\x93\xf3\xd8\xe81\xaa\xe4\x91\xf7\xd9\xe4\x9etI\x04\xdc\x0b \xb0=\xf2\x89\xbc\xc0\x0e\r\xb2\x89@\xe1;\xb9C\x16\x05\xfaF\x80:\x9ee\xb2\x83KR\x1f\x84\xc8\xf2:\x99\x17\xe8K\xdfY\xed\x01\x19\xc0\x9fU\xbf\xb8\x80\xc0U\xa5\x08\xda\xbe%\xcd~qg\xdbc\xd3\x04\xe3\xc1<A\x9b\xf6\xf8E\x80h\x13\x01q\xfd\xb1\xd9\xd4\xe0\n\xb8\x93\xfcF6 \x00}D\x05\x081FC\xb3\xa9A#\xdc\xc9~1\x96l\x1f8I\x80Zq\xdb\xfe\xa7.J\x04\xbcEF\x81\x00\xf1\x1bI\x80\x10\xe3U\x0c\x1a\xe6\x1a\t\x13\x0f\x1c7apOr7\xad+\x8d4\xab~\xf10"`tf\x96;\x898\xc7\x1at\xc65\x96\x95\x18\x1a\xb1\xa7q\xae\xbeee\xa2\xf2\x97WV\x91\xcd\xae\xe5\xa8\x1b\x81\xb1\xd6glK\x1dp\x1c\xb7\x9fd\x8ea\x01\x92\x98\xc0\xd4\xeaxn\x0e\x97;\xf6G\xb9:Tj\x9e\xc3\x1c\x13\x15w)\x81\xa9\x15\x9d\xdeL\xd5\xdd\xdd\xf2x\xc7~\xceF\xa5\xea\x9e\xd5f\xc2\x02Mu\xa5\x86+\x0etrM\x81\xbe\xcd-\xb9\x1b\xa5\x91\xc01\xed\xf6\xe8\x98\xfbZ_tO\'\xa6\xb9\xe3\xa8\xb1"h\xb8\x89\xf8 OZ_\x83\x9c\xd7f\xd5\xda\xd0\xb0\xb7\xf5\xcf\xca`I\x1d\x8dO\xaa\x92C\xb9\xe4\xc1\xea]\x844P\xb0O>\xb7\xbe\xb6x\xfc\xfeRw_\x9f\xea\x81>\x1b\xe5\xaa\x1aq\xfe\x9bCp\x8d\xcaD\xfb7/\xbf?\xde\x916W\x9e\x99\x80\xf1\xc4\xdd\xc28ZO\x95\xb6\xc4\x99ZMcM\x95\xb6\xd8.XLQ\xdc\xb3|c\xe8 IV\x93.\xbc\xad\x88;\xb5&Zx\xc4%\xce\x82%\xd7lj0\xce\xb8`\xc2Lu\xaa\xb4%\xea\xad\xd5\xb4\x90lj\xd8\xa9\x95\x11Sea\xd9\xd4\x1c\x92\\p~3/\xee\x12\x90\xa9\xa8r\x95Kq\x97\x82\xf1\xc7\x05\ts+\xee\x12\xc2\xb2Z\xe8\x03\x14\x86\xb9`I\xe5=(+\xfcY\xed\xc9ljtV\x0b-\xeeR\xe2\xfc\x81V\x08\x19dR\xa9?"\x80\x16\n\xa6\x0c\x13@\x00\x00\x00\x00IEND\xaeB`\x82'
icon_id = idaapi.load_custom_icon(data=icon, format="png")

class utils:
    def get_negative_disass(op):
        # Get negative value based on the size of the operand
        if op.dtype == 0x0: # Byte
            return -(((op.value & 0xff) ^ 0xff) + 1)
        elif op.dtype == 0x1: # Word
            return -(((op.value & 0xffff) ^ 0xffff) + 1)
        elif op.dtype == 0x2: # Dword
            return -(((op.value & 0xffffffff) ^ 0xffffffff) + 1)
        elif op.dtype == 0x7: # Qword
            return -((op.value ^ 0xffffffffffffffff) + 1)

    def get_func_name(ea):
        # Get pretty function name
        func_name = utils.get_pretty_func_name(idc.get_func_name(ea))
        if not func_name:
            func_name = utils.get_pretty_func_name(idc.get_name(ea))
        return func_name

    def get_pretty_func_name(name):
        # Demangle function name
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        # Return as is if failed to demangle
        if not demangled_name:
            return name
        # Cut arguments
        return demangled_name[:demangled_name.find("(")]

    def prep_func_name(name):
        if name[0] != "." and name[0] != "_":
            # Name does not start with dot or underscore
            return [name,f".{name}",f"_{name}"]
        else:
            return [name[1:],f".{name[1:]}",f"_{name[1:]}"]

class null_after_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self,decompiled_function,call_xref,func_name,matched):
        self.found_call = False
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST) # CV_FAST does not keep parents nodes in CTREE
        self.decompiled_function = decompiled_function
        self.call_xref = call_xref
        self.func_name = func_name
        self.insn_counter = 0
        self.matched = matched

    def visit_insn(self, i):
        if self.found_call:
            self.insn_counter += 1
        return 0

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            xref_func_name = utils.get_func_name(e.x.obj_ea)
            if not xref_func_name:
                xref_func_name = idc.get_name(e.x.obj_ea)
            if xref_func_name.lower() == self.func_name.lower() and e.ea == self.call_xref:
                self.found_call = True
        if self.found_call and self.insn_counter < 2:
            if e.op == ida_hexrays.cot_asg:
                # The expression is assignment, check the right side of the assign
                if e.y.op == ida_hexrays.cot_num:
                    # The right side is number
                    if e.y.numval() == 0:
                        # Set to null
                        self.matched["set_to_null"] = True
        return 0

class VulFiScanner:
    def __init__(self,custom_rules=None):
        # Init class-wide variables
        self.functions_list = []
        if not custom_rules:
            with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"vulfi_rules.json"),"r") as rules_file:
                self.rules = json.load(rules_file)
        else:
            self.rules = custom_rules
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"vulfi_prototypes.json"),"r") as proto_file:
            self.prototypes = json.load(proto_file)
        # get pointer size
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            self.ptr_size = 8
        elif info.is_32bit():
            self.ptr_size = 4
        else:
            self.ptr_size = 2
        # Get endianness
        self.endian = "big" if idaapi.cvar.inf.is_be() else "little"
        # Check whether Hexrays can be used
        if not ida_hexrays.init_hexrays_plugin():
            self.hexrays = False
            self.strings_list = idautils.Strings()
        else:
            self.hexrays = True
            #self.strings_list = idautils.Strings()

    def start_scan(self,ignore_addr_list):
        results = []
        ida_kernwin.show_wait_box("VulFi scan running ... ")
        self.prepare_functions_list()
        for rule in self.rules:
            try:
                xrefs_dict = self.find_xrefs_by_name(rule["function_names"],rule["wrappers"])
            except:
                ida_kernwin.warning("This does not seem like a correct rule file. Aborting scan.")
                return
            for scanned_function in xrefs_dict:
            # For each function in the rules
                skip_count = 0
                counter = 0 # For UI only
                total_xrefs = len(xrefs_dict[scanned_function]) # For UI only
                for scanned_function_xref_tuple in xrefs_dict[scanned_function]:
                    counter += 1
                    if ida_kernwin.user_cancelled():
                        print("[VulFi] Scan canceled!")
                        ida_kernwin.hide_wait_box()
                        return None
                    if skip_count > 0:
                        skip_count -= 1
                        continue
                    param = []
                    param_count = 0
                    function_call = None
                    scanned_function_xref = scanned_function_xref_tuple[0] # Address
                    scanned_function_name = scanned_function_xref_tuple[1] # Name
                    scanned_function_display_name = scanned_function_xref_tuple[2] # Display Name
                    # Update progress bar
                    ida_kernwin.replace_wait_box(f"Scanning {scanned_function_display_name} ({counter}/{total_xrefs})")
                    # If this rule is already verified for this address, move on
                    if f"{rule['name']}_{hex(scanned_function_xref)}" in ignore_addr_list:
                        continue
                    # For each xref to the function in the rules
                    # If ida_hexrays can be used eval the conditions in the rules file
                    params_raw = self.get_xref_parameters(scanned_function_xref,scanned_function_name)
                    if params_raw is None:
                        if self.hexrays:
                            # Likely decompiler failure, we have to skip
                            continue
                        else:
                            # Params were not found, lets mark all XREFS
                            params_raw = []
                    for p in params_raw:
                        param.append(VulFiScanner.Param(self,p,scanned_function_xref,scanned_function_name))
                    param_count = len(param)

                    function_call = VulFiScanner.FunctionCall(self,scanned_function_xref,scanned_function_name)
                    # Name of the function where the xref is located
                    found_in_name = utils.get_func_name(scanned_function_xref)
                    priority = ""
                    # Every xref will be marked as Info in case that params fetch fails
                    try:
                        if not param:
                            priority = "Info"
                        elif eval(rule["mark_if"]["High"],dict(self=self, param=param,param_count=param_count,function_call=function_call)):
                            priority = "High"
                        elif eval(rule["mark_if"]["Medium"],dict(self=self, param=param,param_count=param_count,function_call=function_call)):
                            priority = "Medium"
                        elif eval(rule["mark_if"]["Low"],dict(self=self, param=param,param_count=param_count,function_call=function_call)):
                            priority = "Low"

                    except IndexError:
                        # Decompiler output has fewer parameters than the function prototype
                        # Mark the issue with Info priority
                        priority = "Info"
                        #results.append(list(VulFi.result_window_row(rule["name"],scanned_function_display_name,found_in_name,hex(scanned_function_xref),"Not Checked","Low","")))
                    except Exception:
                        print(traceback.format_exc())
                        ida_kernwin.warning(f"The rule \"{rule}\" is not valid!")
                        continue
                    # If the rule matched and is not wrapped:
                    #if priority and found_in_name and not "wrapped" in scanned_function_display_name:
                    if priority and not "wrapped" in scanned_function_display_name:
                        results.append(list(VulFi.result_window_row(rule["name"],scanned_function_display_name,found_in_name,hex(scanned_function_xref),"Not Checked",priority,"")))
                    elif "wrapped" in scanned_function_display_name and priority:
                        skip_count = 0 # rule for the wrapped function matched so no need to skip calls to the wrapper
                    elif "wrapped" in scanned_function_display_name and priority == "":
                        # Rule for wrapped function did not match, skip the wrapper
                        skip_count = int(scanned_function_display_name[scanned_function_display_name.find("wrapped:") + 8:-1])
        ida_kernwin.hide_wait_box()
        return results

    def prepare_functions_list(self):
        self.functions_list = []
        # Gather all functions in all segments
        for segment in idautils.Segments():
            self.functions_list.extend(list(idautils.Functions(idc.get_segm_start(segment),idc.get_segm_end(segment))))

        # Gather imports
        def imports_callback(ea, name, ordinal):
            self.functions_list.append(ea)
            return True

        # For each import
        number_of_imports = idaapi.get_import_module_qty()
        for i in range(0, number_of_imports):
            idaapi.enum_import_names(i, imports_callback)

    # Returns a list of all xrefs to the function with specified name
    def find_xrefs_by_name(self,func_names,wrappers):
        xrefs_list = {}
        insn = ida_ua.insn_t()
        function_names = []
        for name in func_names:
            function_names.extend(utils.prep_func_name(name))

        # Convert function names to expected format (demangle them if possible)
        function_names = list(map(utils.get_pretty_func_name, function_names))

        # For all addresses of functions and imports check if it is function we are looking for
        for function_address in self.functions_list:
            current_function_name = utils.get_func_name(function_address)
            if not current_function_name:
                current_function_name = ida_name.get_ea_name(function_address)
            # If the type is not defined and the name of the function is known set the type
            prototype = self.prototypes.get(current_function_name.lower(), None)
            if prototype is not None:
                idc.SetType(function_address, prototype)
                idaapi.auto_wait()


            # Seach function "as is" and "ingnore case"
            if current_function_name not in function_names:
                current_function_name = current_function_name.lower()
                if current_function_name not in function_names:
                    continue

            # This is the function we are looking for
            if current_function_name not in xrefs_list.keys():
                xrefs_list[current_function_name] = []
            for xref in idautils.XrefsTo(function_address):
                # This rules out any functions within those that we are already looking at (wrapped)
                # It also makes sure that functions that are not xrefed within another function are not displayed
                xref_func_name = utils.get_func_name(xref.frm)
                if not xref_func_name or xref_func_name.lower() in function_names:
                    continue
                # Make sure that the instrution is indeed a call
                if ida_ua.decode_insn(insn,xref.frm) != idc.BADADDR:
                    if (insn.get_canon_feature() & 0x2 == 0x2 or # The instruction is a call
                    (insn.get_canon_feature() & 0xfff == 0x100 and insn.Op1.type in [idc.o_near,idc.o_far])): # The instruction uses first operand which is of type near/far immediate address
                        xref_tuple = (xref.frm,current_function_name,current_function_name)
                        if wrappers:
                            # If we should look for wrappers, do not includ the wrapped xref
                            retrieved_wrappers = self.get_wrapper_xrefs(xref.frm,current_function_name)
                            if not retrieved_wrappers:
                                # No wrappers
                                if not xref_tuple in xrefs_list[current_function_name]:
                                    xrefs_list[current_function_name].append(xref_tuple)
                            else:
                                # Wrappers were found
                                wrapped_tupple = (xref_tuple[0],xref_tuple[1],f"{xref_tuple[2]} (wrapped:{len(retrieved_wrappers)})")
                                xrefs_list[current_function_name].append(wrapped_tupple) # this makes sure that the wrapped function is right before its wrappers
                                xrefs_list[current_function_name].extend(retrieved_wrappers)
                        else:
                            if not xref_tuple in xrefs_list[current_function_name]:
                                xrefs_list[current_function_name].append(xref_tuple)
        return xrefs_list

    # Check if the xref can be a wrapper
    def get_wrapper_xrefs(self,xref,current_function_name):
        if self.hexrays:
            # Hexrays avaialble, we can use decompiler
            return self.get_wrapper_xrefs_hexrays(xref,current_function_name)
        else:
            # Hexrays not available, decompiler cannot be used
            return self.get_wrapper_xrefs_disass(xref)

    def get_wrapper_xrefs_hexrays(self,function_xref,current_function_name):
        wrapper_xrefs = []
        try:
            decompiled_function = ida_hexrays.decompile(function_xref)
        except:
            return wrapper_xrefs
        if decompiled_function:
            # Decompilation is fine
            code = decompiled_function.pseudocode
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea == function_xref and tree_item.op == ida_hexrays.cot_call:
                    # Get called function name
                    xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if not xref_func_name:
                        xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if xref_func_name == current_function_name.lower():
                        # This is the correct call
                        lvars = list(decompiled_function.get_lvars()) # Get lvars
                        arg_objects = list(tree_item.to_specific_type.a)
                        found = True
                        while arg_objects:
                            current_obj = arg_objects.pop(0)
                            if current_obj is None:
                                continue
                            if current_obj.op == ida_hexrays.cot_var:
                                # if variable is not an arg_var we do not have a wrapper
                                if not lvars[current_obj.v.idx].is_arg_var:
                                    found = False
                            else:
                                arg_objects.extend([current_obj.to_specific_type.x,current_obj.to_specific_type.y])
                        # The function is likely a wrapper, get XREFs to it
                        if found:
                            for wrapper_xref in idautils.XrefsTo(decompiled_function.entry_ea):
                                wrapper_xref_func_name = utils.get_func_name(decompiled_function.entry_ea)
                                wrapper_xrefs.append((wrapper_xref.frm,wrapper_xref_func_name,f"{wrapper_xref_func_name} ({current_function_name} wrapper)"))
        return wrapper_xrefs


    # There probably is no architecture-agnostic way on how to do this without decompiler
    def get_wrapper_xrefs_disass(self,xref):
        return []

    # Wrapper for getting function params
    def get_xref_parameters(self,function_xref,scanned_function):
        if self.hexrays:
            # Hexrays avaialble, we can use decompiler
            return self.get_xref_parameters_hexrays(function_xref,scanned_function)
        else:
            # Hexrays not available, decompiler cannot be used
            return self.get_xref_parameters_disass(function_xref)

    # Returns list of ordered paramters from disassembly
    def get_xref_parameters_disass(self,function_xref):
        params_list = []
        # Requires the type to be already assigned to functions
        try:
            for param_ea in idaapi.get_arg_addrs(function_xref):
                if param_ea != idc.BADADDR:
                    param_insn = ida_ua.insn_t()
                    # decode the instruction linked to the parameter
                    if ida_ua.decode_insn(param_insn,param_ea) != idc.BADADDR:
                        if param_insn.get_canon_feature() & 0x00100 == 0x100:
                            # First operand - push
                            params_list.append(param_insn.Op1)
                        elif param_insn.get_canon_feature() & 0x00200 == 0x200:
                            # Second operands - mov/lea
                            params_list.append(param_insn.Op2)
                        elif param_insn.get_canon_feature() & 0x00400 == 0x400:
                            # Third operand
                            params_list.append(param_insn.Op3)
        except:
            return None
        return params_list

    # Returns an ordered list of workable object that represent each parameter of the function from decompiled code
    def get_xref_parameters_hexrays(self,function_xref,scanned_function):
        # Decompile function and find the call
        try:
            decompiled_function = ida_hexrays.decompile(function_xref)
        except:
            return None
        if decompiled_function is None:
            # Decompilation failed
            return None
        index = 0
        code = decompiled_function.pseudocode
        for tree_item in decompiled_function.treeitems:
            if tree_item.ea == function_xref and tree_item.op == ida_hexrays.cot_call:
                xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                if not xref_func_name:
                    xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                if xref_func_name == scanned_function.lower():
                    return list(tree_item.to_specific_type.a)
            index += 1
        # Call not found :(
        return None

    class Param:
        def __init__(self,scanner,param,call_xref,scanned_function):
            self.scanner_instance = scanner
            self.param = param
            self.call_xref = call_xref
            self.scanned_function = scanned_function

        def is_constant(self):
            if self.string_value() == "" and self.number_value() == None:
                asgs = self.__get_var_assignments()
                if asgs: # asgs will be empty with no hexrays
                    for asg in asgs:
                        if self.__is_before_call(asg.ea):
                            if self.string_value(asg.y) == "" and self.number_value(asg.y) == None:
                                # One of the assigns is non-const
                                return False
                    return True
                return False
            else:
                return True

        # Returns True if the param is used in any function call specified in the "function_list" parameter
        def used_in_call_before(self,function_list):
            if self.scanner_instance.hexrays:
                return self.used_in_call_before_hexrays(function_list)
            else:
                return self.used_in_call_before_disass(function_list)

        def used_in_call_before_hexrays(self,function_list):
            # get all calls with the parameter
            calls = self.__get_var_arg_calls()
            # prep function list
            tmp_fun_list = []
            for fun in function_list:
                tmp_fun_list.extend(utils.prep_func_name(fun))
            for call in calls:
                if utils.get_func_name(call.x.obj_ea) in tmp_fun_list and self.__is_before_call(call.ea):
                    return True
            return False

        def used_in_call_before_disass(self,function_list):
            return False

        def used_in_call_after(self,function_list):
            if self.scanner_instance.hexrays:
                return self.used_in_call_after_hexrays(function_list)
            else:
                return self.used_in_call_after_disass(function_list)

        def used_in_call_after_hexrays(self,function_list):
            # get all calls with the parameter
            calls = self.__get_var_arg_calls()
            # prep function list
            tmp_fun_list = []
            for fun in function_list:
                tmp_fun_list.extend(utils.prep_func_name(fun))
            for call in calls:
                if utils.get_func_name(call.x.obj_ea) in tmp_fun_list and not self.__is_before_call(call.ea):
                    return True
            return False

        def used_in_call_after_disass(self,function_list):
            return False

        # Simple check whether the given EA is before the call
        def __is_before_call(self,ea):
            func = idaapi.get_func(ea)
            flow = idaapi.FlowChart(func)
            call_block = None
            asg_block = None
            checked_blocks = []
            # Get block of the assignemnt and block of the call
            for block in flow:
                if ea >= block.start_ea and ea <= block.end_ea:
                    asg_block = block
                if self.call_xref >= block.start_ea and self.call_xref <= block.end_ea:
                    call_block = block
                    checked_blocks.append(block.start_ea)
            # If they are in the same block and asg ea is smaller then call_xref ea return True
            if call_block == asg_block:
                if ea < self.call_xref:
                    return True
            else:
                # Blocks are different
                call_preds = list(call_block.preds())
                while call_preds:
                    current_pred = call_preds.pop(0)
                    # Prevent endless loops
                    if current_pred.start_ea in checked_blocks:
                        continue
                    checked_blocks.append(current_pred.start_ea)
                    # Check if we matched the given assign block
                    if current_pred.start_ea == asg_block.start_ea:
                        return True
                    call_preds.extend(list(current_pred.preds()))
            return False

        def __get_var_arg_calls(self):
            calls = []
            # Parameter is cast, get x
            if self.param.op == ida_hexrays.cot_cast:
                param = self.param.x
            else:
                param = self.param
            decompiled_function = ida_hexrays.decompile(self.call_xref)
            code = decompiled_function.pseudocode
            for citem in decompiled_function.treeitems:
                if citem.op == ida_hexrays.cot_call and citem.ea != self.call_xref: # skip calls we are tracing
                    # Potentially interesting call
                    for a in citem.to_specific_type.a:
                        expressions = [a,a.x,a.y,a.z]
                        while expressions:
                            current_expr = expressions.pop(0)
                            if current_expr:
                                if param == current_expr:
                                    # Call operation, add to array
                                    calls.append(citem.to_specific_type)
                                    break # we can break the loop as the variable was found within the arguments
                                expressions.extend([current_expr.x, current_expr.y, current_expr.z])
            return calls

        # Returns list of assign expressions for better accuracy
        def __get_var_assignments(self):
            asg = []
            # Parameter is cast, get x
            if self.param.op == ida_hexrays.cot_cast:
                param = self.param.x
            else:
                param = self.param
            decompiled_function = ida_hexrays.decompile(self.call_xref)
            code = decompiled_function.pseudocode
            for citem in decompiled_function.treeitems:
                if param == citem.to_specific_type:
                    parent = decompiled_function.body.find_parent_of(citem)
                    if parent.op >= ida_hexrays.cot_asg and parent.op <= ida_hexrays.cot_asgumod:
                        # Assign operation, add to array
                        asg.append(parent.to_specific_type)
            return asg

        def string_value(self,expr=None):
            if not expr:
                expr = self.param
            if self.scanner_instance.hexrays: # hexrays
                string_val = idc.get_strlit_contents(expr.obj_ea)
                if string_val:
                    return string_val.decode()
                # If it is a cast (could happen)
                elif expr.op == ida_hexrays.cot_cast:
                    # If casted op is object
                    if expr.x.op == ida_hexrays.cot_obj:
                        # If that object points to a string
                        string_val = idc.get_strlit_contents(expr.x.obj_ea)
                        if string_val:
                            return string_val.decode()
                elif expr.op == ida_hexrays.cot_ref:
                    string_val = idc.get_strlit_contents(expr.x.obj_ea)
                    if string_val:
                        return string_val.decode()
                    if expr.x.op == ida_hexrays.cot_idx:
                        string_val = idc.get_strlit_contents(expr.x.x.obj_ea)
                        if string_val:
                            return string_val.decode()
                    # Check whether we are looking at CFString
                    if expr.x.obj_ea != idc.BADADDR:
                        c_str_pointer_value = idc.get_bytes(expr.x.obj_ea +  2* self.scanner_instance.ptr_size, self.scanner_instance.ptr_size)
                        tmp_ea = int.from_bytes(c_str_pointer_value,byteorder=self.scanner_instance.endian)
                        c_str_len = int.from_bytes(idc.get_bytes(expr.x.obj_ea +  3* self.scanner_instance.ptr_size, self.scanner_instance.ptr_size),byteorder=self.scanner_instance.endian)
                        c_string_value = idc.get_strlit_contents(tmp_ea)
                        # Having a string at this position and its length following the pointer suggests CFString struct
                        if c_string_value and len(c_string_value) == c_str_len:
                            # If this evaluates to string we have a constant
                            return c_string_value.decode()
                else:
                    # not a direct string
                    byte_value = idc.get_bytes(expr.obj_ea,self.scanner_instance.ptr_size)
                    if byte_value:
                        tmp_ea = int.from_bytes(byte_value,byteorder=self.scanner_instance.endian)
                        string_val = idc.get_strlit_contents(tmp_ea)
                        if string_val:
                            # If this evaluates to string we have a constant
                            return string_val.decode()
            else: # No hexrays
                if expr.type == 0x2:
                    # Reference
                    if idc.get_strlit_contents(expr.addr):
                        return idc.get_strlit_contents(expr.addr).decode()
                    else:
                        # Reference to reference
                        addr = int.from_bytes(idc.get_bytes(expr.addr, self.scanner_instance.ptr_size),byteorder=self.scanner_instance.endian)
                        if idc.get_strlit_contents(addr):
                            return idc.get_strlit_contents(addr).decode()

                if expr.type == 0x5:
                    if idc.get_strlit_contents(expr.value):
                        return idc.get_strlit_contents(expr.value).decode()
                # Reverse appoach of going from strings to calls
                for c_string in self.scanner_instance.strings_list:
                    for str_xref in idautils.XrefsTo(c_string.ea):
                        func = idaapi.get_func(str_xref.frm)
                        if func:
                            if func.start_ea == idaapi.get_func(self.call_xref).start_ea:
                                # The xref and the call are in the same function
                                # look if those are used within 5 instructions
                                if (str_xref.frm < self.call_xref):
                                    # XREF to STR is before the call to XREF
                                    instr_list = list(idautils.Heads(str_xref.frm,self.call_xref))
                                    if len(instr_list) <= 10:
                                        # No more then 10 instructions between the str XREF and the call
                                        for head in instr_list:
                                            current_insn = ida_ua.insn_t()
                                            if ida_ua.decode_insn(current_insn,head) != idc.BADADDR:
                                                if head != self.call_xref and current_insn.get_canon_feature() & 0x2 == 0x2:
                                                    # If it is not a target call but it is a call its false
                                                    return ""
                                        # If we survived the loop it is True
                                        return str(c_string)
            return ""

        def number_value(self,expr=None):
            if not expr:
                expr = self.param
            if self.scanner_instance.hexrays: # hexrays
                # If it is number directly
                if expr.op == ida_hexrays.cot_num:
                    return expr.n._value
                # if it is a float
                elif expr.op == ida_hexrays.cot_fnum:
                    return expr.fpc.fnum.float
                # If it is a cast
                elif expr.op == ida_hexrays.cot_cast:
                    if expr.x.op == ida_hexrays.cot_num:
                        return expr.x.n._value
                    elif expr.x.op == ida_hexrays.cot_fnum:
                        return expr.x.fpc.fnum.float
            else: # No hexrays
                # self.param is op_t
                # 0x5 is immediate
                if expr.type == 0x5:
                    return expr.value
            return None

        def is_const_number(self,expr=None):
            if not expr:
                expr = self.param
            if self.scanner_instance.hexrays:
                if expr.op == ida_hexrays.cot_num or expr.op == ida_hexrays.cot_fnum:
                    return True
                elif expr.op == ida_hexrays.cot_cast and expr.x.op == ida_hexrays.cot_num:
                    return True
            else:
                if expr.type == 0x5:
                    return True
            return False

        # Wrapper for the basic UAF filter
        def set_to_null_after_call(self):
            if self.scanner_instance.hexrays:
                # Hexrays avaialble, we can use decompiler
                return self.set_to_null_after_call_hexrays()
            else:
                # Hexrays not available, decompiler cannot be used
                return self.set_to_null_after_call_disass()

        # Simple function that just checks whether the call is followed by an isntruction that sets the parameter to null
        # Note that this is very primitive to keep sort of architecture agnostic approach
        def set_to_null_after_call_disass(self):
            call_insn = ida_ua.insn_t()
            following_insn = ida_ua.insn_t()
            # First get the call instruction
            if ida_ua.decode_insn(call_insn,self.call_xref) != idc.BADADDR:
                # Now use the call instruction to get EA of next insn
                if ida_ua.decode_insn(following_insn,call_insn.ea + call_insn.size) != idc.BADADDR:
                    # following_insn can be used to evaluate whether Op2 is a constant or not
                    if following_insn.Op2.type == 0x5 and following_insn.Op2.value == 0x0:
                        # This should cover most of the cases where a mov instuction is used
                        return True
            return False

        # Using hexrays to figure out whether the function was followed by a null-set
        def set_to_null_after_call_hexrays(self):
            # get size of the call instruction, go past it and get expression that is linked to that address?
            matched = {"set_to_null":False}
            try:
                decompiled_function = ida_hexrays.decompile(self.call_xref)
            except:
                return matched["set_to_null"]
            if decompiled_function is None:
                # Decompilation failed
                return None
            custom_visitor = null_after_visitor(decompiled_function,self.call_xref,self.scanned_function,matched)
            custom_visitor.apply_to(decompiled_function.body, None)

            return matched["set_to_null"]



    class FunctionCall:
        def __init__(self,scanner,call_xref,scanned_function):
            self.scanner_instance = scanner
            self.call_xref = call_xref
            self.scanned_function = scanned_function

        
        def reachable_from(self,function_name):
            functions = [idaapi.get_func(self.call_xref)]
            checked_xrefs = []
            while functions:
                current_function = functions.pop(0)
                if current_function:
                    if utils.get_func_name(current_function.start_ea) in utils.prep_func_name(function_name):
                        return True
                    for xref in idautils.XrefsTo(current_function.start_ea):
                        if xref.frm not in checked_xrefs:
                            functions.append(idaapi.get_func(xref.frm))
                            checked_xrefs.append(xref.frm)
            return False

        # Check whether the return value of a function is part of some comparison (verification)
        def return_value_checked(self,check_val = None):
            if self.scanner_instance.hexrays:
                # Hexrays avaialble, we can use decompiler
                return self.return_value_checked_hexrays(check_val)
            else:
                # Hexrays not available, decompiler cannot be used
                return self.return_value_checked_disass(check_val)

        # Check if the return value of a function is verified after the call
        def return_value_checked_disass(self,check_val):
            # To stay architecture agnostic, this simply checks whether there is conditional jump within 5 instructions after the call
            for basic_block in idaapi.FlowChart(idaapi.get_func(self.call_xref)):
                if self.call_xref >= basic_block.start_ea and self.call_xref < basic_block.end_ea and len(list(basic_block.succs())) > 1:
                    # xref call belongs to this block
                    insn_counter = 0
                    current_insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(current_insn,self.call_xref) != idc.BADADDR:
                        while insn_counter < 5:
                            following_insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(following_insn,current_insn.ea + current_insn.size) != idc.BADADDR:
                                current_insn = following_insn
                                # Most of the compare instructions
                                if current_insn.get_canon_feature() & 0xffff == 0x300:
                                    if check_val is not None:
                                        for op in current_insn.ops:
                                            if op.type == 0x5:
                                                negative_value = utils.get_negative_disass(op)
                                                if op.value == check_val or negative_value == check_val:
                                                    return True
                                                else:
                                                    return False
                                    else:
                                        # Likely comparison instruction hit
                                        return True
                                insn_counter += 1
                            else:
                                break
                            # Jumped out of the block within 5 instructions
                            if current_insn.ea >= basic_block.end_ea:
                                return True
            return False

        def return_value_checked_hexrays(self,check_val):
            try:
                decompiled_function = ida_hexrays.decompile(self.call_xref)
            except:
                return None
            if decompiled_function is None:
                # Decompilation failed
                return None
            code = decompiled_function.pseudocode
            index = 0
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea == self.call_xref and tree_item.op == ida_hexrays.cot_call:
                    xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if not xref_func_name:
                        xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if xref_func_name == self.scanned_function.lower():
                        parent = decompiled_function.body.find_parent_of(tree_item)
                        if parent.op == ida_hexrays.cot_cast: # return value is casted
                            parent = decompiled_function.body.find_parent_of(parent)
                        if (parent.op >= 22 and parent.op <= 31):
                            if check_val is not None:
                                parent = parent.to_specific_type
                                if parent.y and (parent.y.n or parent.y.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                    if parent.y.n: # int
                                        value = parent.y.n._value
                                        negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                    else: # float
                                        value = parent.y.fpc.fnum.float
                                        negative_value = value
                                    if negative_value == check_val or value == check_val:
                                        return True
                                    else:
                                        return False
                            else:
                                return True
                        elif parent.op == ida_hexrays.cit_if or parent.op == ida_hexrays.cot_lnot or parent.op == ida_hexrays.cot_lor or parent.op == ida_hexrays.cot_land:
                            if check_val is not None:
                                if not parent.to_specific_type.cif.expr.y:
                                    # There is no Y, likely checked against 0: if(func_call())
                                    if check_val == 0:
                                        return True
                                    else:
                                        return False
                            else:
                                return True
                        elif parent.op == ida_hexrays.cot_asg:
                            # return value is assigned to the variable/global
                            # Look through the rest of the function and find any if comparison with this variable and const number
                            if parent.to_specific_type.x.v or parent.to_specific_type.x.op == ida_hexrays.cot_obj:
                                for sub_tree_item in list(decompiled_function.treeitems)[index:]:
                                    if sub_tree_item.to_specific_type.op >= 22 and sub_tree_item.to_specific_type.op <= 31:
                                        # Comparison operator
                                        if (sub_tree_item.to_specific_type.x.v and sub_tree_item.to_specific_type.x.v.idx == parent.to_specific_type.x.v.idx) or (sub_tree_item.to_specific_type.x.obj_ea and sub_tree_item.to_specific_type.x.obj_ea == parent.to_specific_type.x.obj_ea):
                                            if check_val is not None:
                                                numeric_val = sub_tree_item.to_specific_type.y
                                                if numeric_val and (numeric_val.n or numeric_val.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                                    if numeric_val.n: # int
                                                        value = numeric_val.n._value
                                                        negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                                    else: # float
                                                        value = numeric_val.fpc.fnum.float
                                                        negative_value = value
                                                    if negative_value == check_val or value == check_val:
                                                        return True
                                                    else:
                                                        return False
                                            else:
                                                return True
                                        else:
                                            # Look for embedded assigns in cit_if (look until cit_if or cit_block is found)
                                            embedded_parent = decompiled_function.body.find_parent_of(sub_tree_item)
                                            while True:
                                                if embedded_parent.op == ida_hexrays.cit_if:
                                                    return True
                                                elif embedded_parent.op == ida_hexrays.cit_block:
                                                    return False
                                                else:
                                                    embedded_parent = decompiled_function.body.find_parent_of(embedded_parent)
                                    elif sub_tree_item.op == ida_hexrays.cit_if or sub_tree_item.op == ida_hexrays.cot_lnot or sub_tree_item.op == ida_hexrays.cot_lor or sub_tree_item.op == ida_hexrays.cot_land:
                                        if check_val is not None:
                                            if not parent.is_expr():
                                                if not parent.to_specific_type.cif.expr.y:
                                                    # There is no Y, likely checked against 0: if(func_call())
                                                    if check_val == 0:
                                                        return True
                                                    else:
                                                        return False
                                        else:
                                            return True


                index += 1
            return False

class vulfi_form_t(ida_kernwin.Form):

    def __init__(self,function_name):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rule_name_str}
BUTTON YES* Run
BUTTON CANCEL Cancel
Custom VulFi rule

{FormChangeCb}
Add custom rule to trace function: {function_name}
Custom rule name:
<#Name of the rule#:{rule_name_str}>
Custom Rule:
<#Rule as desribed in README#:{rule_str}>

""", {
            'function_name': F.StringLabel(function_name),
            'rule_name_str': F.StringInput(),
            'rule_str': F.StringInput(),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        return 1

class VulFi_Single_Function(idaapi.action_handler_t):
    result_window_title = "VulFi Results"
    result_window_columns_names = ["IssueName","FunctionName","FoundIn", "Address","Status", "Priority","Comment"]
    result_window_columns_sizes = [15,20,20,8,8,5,30]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("VulFiResultRow",result_window_columns_names)

    def __init__(self,function_ea):
        idaapi.action_handler_t.__init__(self)
        self.function_ea = function_ea

    # Called when the button is clicked
    def activate(self, ctx):
        custom_rule = custom_rule_name = ""
        if not idc.get_type(self.function_ea) and (idaapi.get_func(self.function_ea) and not idc.get_type(idaapi.get_func(self.function_ea).start_ea)):
            # If the type of the function is not set notify the user
            answer = ida_kernwin.ask_buttons("Yes","No","Cancel",1,f"You should first set type for the function. Continue without type anyway?")
            if answer != 1:
                return

        # Show the form
        function_name = idc.get_func_name(self.function_ea)
        if not function_name:
            function_name = idc.get_name(self.function_ea)
        f = vulfi_form_t(function_name)
        # Compile (in order to populate the controls)
        f.Compile()
        # Execute the form
        ok = f.Execute()
        # If the form was confirmed
        if ok == 1:
            custom_rule_name = f.rule_name_str.value
            custom_rule = f.rule_str.value
        else:
            # Cancel
            return
        # Dispose the form
        f.Free()

        if not custom_rule or not custom_rule_name:
            ida_kernwin.warning("Both rule name and the rule have to be filled!")
            return
        # Craft a temporary rule here:
        tmp_rule = [{"name":f"{custom_rule_name}","function_names":[function_name.lower(),f".{function_name.lower()}"],"wrappers":False,"mark_if":{"High":custom_rule,"Medium":"False","Low":"False"}}]
        vulfi_scanner = VulFiScanner(tmp_rule)
        rows = []
        marked_addrs = []
        vulfi_data = {}
        # Load stored data
        node = idaapi.netnode()
        node.create("vulfi_data")
        if node.getblob(1,"S"):
            vulfi_data = json.loads(node.getblob(1,"S"))
        else:
            vulfi_data = {}
        for item in vulfi_data:
            rows.append([vulfi_data[item]["name"],vulfi_data[item]["function"],vulfi_data[item]["in"],vulfi_data[item]["addr"],vulfi_data[item]["status"],vulfi_data[item]["priority"],vulfi_data[item]["comment"]])
            marked_addrs.append(vulfi_data[item]["addr"])

        # Run the scan for selected function
        print("[VulFi] Started the scan ...")
        scan_result = vulfi_scanner.start_scan(marked_addrs)
        if scan_result is None:
            return
        rows.extend(scan_result)
        print("[VulFi] Scan done!")
        # Save the results
        for item in rows:
            vulfi_data[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
        node.setblob(json.dumps(vulfi_data).encode("ascii"),1,"S")
        # Construct and show the form
        results_window = VulFiEmbeddedChooser(self.result_window_title,self.result_window_columns,rows,icon_id)
        results_window.AddCommand("Mark as False Positive", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Suspicious", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Vulnerable", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Set Vulfi Comment", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Remove Item(s)", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Export Results", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.Show()
        hooks.set_chooser(results_window)

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class vulfi_main_form_t(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rDefault}
BUTTON YES* Run
BUTTON CANCEL Cancel
Custom VulFi rule

{FormChangeCb}
<##What rule set to use?##Default rules:{rDefault}>
<Custom rules:{rCustom}>
<Import previous results (JSON):{rImport}>{cType}>
<#Select a file to open#Browse to open:{iFileOpen}>

""", {
            'iFileOpen': F.FileInput(open=True),
            'cType': F.RadGroupControl(("rDefault", "rCustom","rImport")),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        if fid == -1 or fid == self.cType.id:
            if self.GetControlValue(self.cType) == 0:
                self.EnableField(self.iFileOpen, False)
            else:
                self.EnableField(self.iFileOpen, True)
        return 1

class VulFi(idaapi.action_handler_t):
    result_window_title = "VulFi Results"
    result_window_columns_names = ["IssueName","FunctionName","FoundIn", "Address","Status", "Priority","Comment"]
    result_window_columns_sizes = [15,20,20,8,8,5,30]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("VulFiResultRow",result_window_columns_names)
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Called when the button is clicked
    def activate(self, ctx):
        answer = 0
        skip_scan = False
        rows = []
        vulfi_data = {}
        marked_addrs = []
        # Load stored data
        node = idaapi.netnode()
        node.create("vulfi_data")
        if node.getblob(1,"S"):
            vulfi_data = json.loads(node.getblob(1,"S"))
        else:
            vulfi_data = {}
        if vulfi_data:
            answer = ida_kernwin.ask_buttons("Load Existing","Scan Again","Cancel",1,f"Previous scan results found.")
        else:
            answer = 2
        if vulfi_data and answer == 1:
            for item in vulfi_data:
                rows.append([vulfi_data[item]["name"],vulfi_data[item]["function"],vulfi_data[item]["in"],vulfi_data[item]["addr"],vulfi_data[item]["status"],vulfi_data[item]["priority"],vulfi_data[item]["comment"]])
                marked_addrs.append(f'{vulfi_data[item]["name"]}_{vulfi_data[item]["addr"]}')
            print("[VulFi] Loading previous data.")
        elif answer == -1:
            # Cancel
            return
        else:
            # Show the form
            f = vulfi_main_form_t()
            # Compile (in order to populate the controls)
            f.Compile()
            # Execute the form
            ok = f.Execute()
            # If the form was confirmed
            if ok == 1:
                if f.cType.value == 0:
                    # Default scan
                    vulfi_scanner = VulFiScanner()
                elif f.cType.value == 1:
                    try:
                        with open(os.path.join(f.iFileOpen.value),"r") as rules_file:
                            vulfi_scanner = VulFiScanner(json.load(rules_file))
                    except:
                        ida_kernwin.warning("Failed to load custom rules!")
                        return
                else:
                    try:
                        with open(os.path.join(f.iFileOpen.value),"r") as import_file:
                            import_data = json.load(import_file)
                        for item in import_data["issues"]:
                            rows.append([item["IssueName"],item["FunctionName"],item["FoundIn"],item["Address"],item["Status"],item["Priority"],item["Comment"]])
                        skip_scan = True
                    except:
                        ida_kernwin.warning("Failed to load custom rules!")
                        return
            else:
                return

            for item in vulfi_data:
                rows.append([vulfi_data[item]["name"],vulfi_data[item]["function"],vulfi_data[item]["in"],vulfi_data[item]["addr"],vulfi_data[item]["status"],vulfi_data[item]["priority"],vulfi_data[item]["comment"]])
                marked_addrs.append(f'{vulfi_data[item]["name"]}_{vulfi_data[item]["addr"]}')
            # Run the scan
            if not skip_scan:
                print("[VulFi] Started the scan ...")
                scan_result = vulfi_scanner.start_scan(marked_addrs)
                if scan_result is None:
                    return
                rows.extend(scan_result)
                print("[VulFi] Scan done!")
            # Save the results
            for item in rows:
                vulfi_data[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
            node.setblob(json.dumps(vulfi_data).encode("ascii"),1,"S")

        # Construct and show the form
        results_window = VulFiEmbeddedChooser(self.result_window_title,self.result_window_columns,rows,icon_id)
        results_window.AddCommand("Mark as False Positive", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Suspicious", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Vulnerable", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Set Vulfi Comment", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Remove Item(s)", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Export Results", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.Show()
        hooks.set_chooser(results_window)


    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class vulfi_export_form_t(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rJSON}
BUTTON YES* Save
BUTTON CANCEL Cancel
VulFi Results Export

{FormChangeCb}
<##Choose format for export##JSON:{rJSON}>
<CSV:{rCSV}>{cType}>
<#Select the output file#Select the output file:{iFileOpen}>

""", {
            'iFileOpen': F.FileInput(save=True),
            'cType': F.RadGroupControl(("rJSON", "rCSV")),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self,fid):
        return 1


class VulFiEmbeddedChooser(ida_kernwin.Choose):
    def __init__(self,title,columns,items,icon,embedded=False):
        ida_kernwin.Choose.__init__(self,title,columns,embedded=embedded,width=100,flags=ida_kernwin.Choose.CH_MULTI + ida_kernwin.Choose.CH_CAN_REFRESH)
        self.items = items
        self.icon = icon
        self.delete = False
        self.comment = False
        self.export = False

    def GetItems(self):
        return self.items

    def SetItems(self,items):
        if items is None:
            self.items = []
        else:
            self.items = items
        self.Refresh()

    def OnRefresh(self,n):
        for item in self.items:
            item[2] = utils.get_func_name(int(item[3],16))
        if self.delete:
            for i in reversed(n):
                self.items.pop(i)
            self.delete = False
            self.save()
        if self.comment:
            if len(n) == 1:
                comment = ida_kernwin.ask_str(self.items[n[0]][6],1,f"Enter the comment: ")
            else:
                comment = ida_kernwin.ask_str("",1,f"Enter the comment: ")
            for i in n:
                self.items[i][6] = comment
            self.comment = False
            self.save()
        if self.export:
            self.export = False
            self.vulfi_export()
            
        return n

    def save(self):
        # On close dumps the results
        vulfi_dict = {}
        for item in self.items:
            vulfi_dict[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
        node = idaapi.netnode()
        node.create("vulfi_data")
        # Set the blob
        node.setblob(json.dumps(vulfi_dict).encode("ascii"),1,"S")

    def OnCommand(self,number,cmd_id):
        # Cmd_ids: 0 - FP, 1 - Susp, 2 - Vuln
        if cmd_id < 3:
            if cmd_id == 0:
                status = "False Positive"
            if cmd_id == 1:
                status = "Suspicious"
            if cmd_id == 2:
                status = "Vulnerable"
            # Item at index #3 is status
            self.items[number][4] = status
        if cmd_id == 3:
            # Comment
            self.comment = True
        if cmd_id == 4:
            # Delete selected items
            self.delete = True
        if cmd_id == 5:
            # Export
            self.export = True
            
        self.Refresh()
        # Save the data after every change
        self.save()

    def vulfi_export(self):
        # Show the form
        f = vulfi_export_form_t()
        # Compile (in order to populate the controls)
        f.Compile()
        # Execute the form
        ok = f.Execute()
        # If the form was confirmed
        if ok == 1:
            # Get file name
            file_name = f.iFileOpen.value
            if file_name:
                if f.cType.value == 0:
                    # JSON
                    # Pretify 
                    tmp_json = {"issues":[]}
                    for item in self.items:
                        tmp_json["issues"].append({
                            "IssueName": item[0],
                            "FunctionName": item[1],
                            "FoundIn": item[2],
                            "Address": item[3],
                            "Status": item[4],
                            "Priority": item[5],
                            "Comment": item[6]
                        })
                    with open(file_name,"w") as out_file:
                        json.dump(tmp_json, out_file)
                    ida_kernwin.info(f"Results exported in JSON format to {file_name}")
                else:
                    #CSV
                    csv_string = "IssueName,FunctionName,FoundIn,Address,Status,Priority,Comment\n"
                    for item in self.items:
                        csv_string += f"{item[0]},{item[1]},{item[2]},{item[3]},{item[4]},{item[5]},{item[6]}\n"
                    with open(file_name,"w") as out_file:
                        out_file.write(csv_string)
                    ida_kernwin.info(f"Results exported in comma-separated CSV file to {file_name}")
        

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self,number):
        # By default change to first selected line
        row = VulFi.result_window_row(*self.items[number[0]])
        destination = row.Address
        ida_kernwin.jumpto(int(destination,16))

    def OnGetLine(self,number):
        try:
            return self.items[number]
        except:
            self.Refresh()
            return None


class vulfi_fetch_t(idaapi.plugin_t):
    comment = "Vulnerability Finder"
    help = "This script helps to reduce the amount of work required when inspecting potentially dangerous calls to functions such as 'memcpy', 'strcpy', etc."
    wanted_name = "VulFi"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP


    def init(self):
        vulfi_desc = idaapi.action_desc_t(
            'vulfi:fetch',   # The action name. This acts like an ID and must be unique
            'VulFi',  # The action text.
            VulFi(),   # The action handler.
            '',      # Optional: the action shortcut
            'Make VulFi fetch the potentially interesting places in binary.',  # Optional: the action tooltip (available in menus/toolbar)
            icon_id)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(vulfi_desc)
        idaapi.attach_action_to_menu("Search", "vulfi:fetch", idaapi.SETMENU_APP)

    def run(self):
        pass

    def term(self):
        pass



class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        self.chooser = None
        idaapi.UI_Hooks.__init__(self)


    def finish_populating_widget_popup(self, form, popup):
        action_text = f"Add '{utils.get_func_name(idc.here())}' function to VulFi"
        function_ea = idc.here()
        try:
            # Get selected symbol
            selected_symbol, _ = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
            # Check if it is a function name
            for function in idautils.Functions():
                if utils.get_func_name(function) in utils.prep_func_name(selected_symbol):
                    action_text = f"Add '{utils.get_func_name(function)}' function to VulFi"
                    function_ea = function
        except:
            pass
        action_desc = idaapi.action_desc_t(
        'vulfi:get_one',   # The action name. This acts like an ID and must be unique
        action_text,  # The action text.
        VulFi_Single_Function(function_ea),   # The action handler.
        '',      # Optional: the action shortcut
        'Make VulFi look for all interesting refences of this function.',  # Optional: the action tooltip (available in menus/toolbar)
        icon_id)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.unregister_action("vulfi:get_one")
        idaapi.register_action(action_desc)
        if ida_kernwin.get_widget_type(form) == idaapi.BWN_DISASM or ida_kernwin.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, "vulfi:get_one", "")

    def current_widget_changed(self, widget, prev_widget):
        title = ida_kernwin.get_widget_title(widget)
        if title and "VulFi" in title and self.chooser:
            self.chooser.Refresh()

    def set_chooser(self,chooser):
        self.chooser = chooser

# Run the hooks
hooks = Hooks()
hooks.hook()

def PLUGIN_ENTRY():
    return vulfi_fetch_t()
