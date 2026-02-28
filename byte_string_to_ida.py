import ida_kernwin
import ida_bytes
import ida_idaapi

def byte_string_to_ida():
    raw_input = ida_kernwin.ask_str("", 0, "Enter byte string (e.g., \\x55\\x8B\\x0F):")
    if not raw_input:
        return

    bytes_list = [b for b in raw_input.split("\\x") if b]
    
    mask = ida_kernwin.ask_str("", 0, "Enter mask (e.g., xxx??x) or leave empty:")
    
    if not mask:
        mask = 'x' * len(bytes_list)

    if len(mask) != len(bytes_list):
        print(f"Error: Mismatch (Bytes: {len(bytes_list)}, Mask: {len(mask)})")
        return

    formatted_pattern = []
    for b, m in zip(bytes_list, mask):
        clean_b = b.strip()
        if len(clean_b) == 1:
            clean_b = "0" + clean_b
        formatted_pattern.append("?" if m == "?" else clean_b)

    final_pattern = " ".join(formatted_pattern).upper()
    print(f"Searching all occurrences for: {final_pattern}")

    compiled_query = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(compiled_query, 0, final_pattern, 16)
    
    curr_ea = 0
    found_count = 0
    
    while True:
        search_res = ida_bytes.bin_search3(curr_ea, ida_idaapi.BADADDR, compiled_query, 0)
        found_ea = search_res[0] if isinstance(search_res, tuple) else search_res
        
        if found_ea == ida_idaapi.BADADDR:
            break
            
        if found_count == 0:
            ida_kernwin.jumpto(found_ea)
            
        print(f"[{found_count + 1}] Found at: {hex(found_ea)}")
        found_count += 1
        curr_ea = found_ea + 1

    if found_count == 0:
        print("Pattern not found.")
    else:
        print(f"Search finished. Total matches: {found_count}")

class PatternHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        byte_string_to_ida()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ByteStringToIdaPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    comment = ""
    help = ""
    wanted_name = "Byte String to IDA"
    wanted_hotkey = ""

    def init(self):
        action_name = "user:byte_string_to_ida"
        action_desc = ida_kernwin.action_desc_t(
            action_name,
            "Byte String to IDA",
            PatternHandler(),
            "Ctrl+Alt+D", 
            "",
            -1)
        
        ida_kernwin.register_action(action_desc)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        byte_string_to_ida()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return ByteStringToIdaPlugin()