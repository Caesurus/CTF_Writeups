
-- Just declare it for clarity
g_bf_char = 0
g_bf_context

g_passwd_seg_offset = 0
g_passwd_seg_cnt = 0
g_passwd_ptr = 0

-- Helper functions
func update_str_with_char_at_index (str, character, index)
  tmp_str = ''
  for i=1, #str do
    if index == i then
      tmp_str = tmp_str .. character
    else
      tmp_str = tmp_str .. string.sub(str, i, i)
    end
  end
  return tmp_str
end

func get_func_info(addr)
  cmps = {}
  read_char_from_memory = {}
  ret_addr = 0
  succss = 0
  arr = u.dis(rcx, 2000)
  for idx,inst in pairs(arr) do
      --formatted_str = "0x%x : %s %s" %{inst.addr, inst.name, inst.op_str}
      -- print formatted_str
      if 'cmp' == inst.name then
        if not string.find(inst.op_str, 'ptr') then
           table.insert(cmps, {addr = inst.addr, text = formatted_str})
         end
      elif 'mov' == inst.name and 'eax, 1' == inst.op_str then
        success = inst.addr
      elif 'ret' == inst.name then
        ret_addr = inst.addr
        break
      elif 'movzx' == inst.name and string.find(inst.op_str, 'byte ptr %[rax%]') then
        table.insert(read_char_from_memory, {addr = inst.addr, text = formatted_str})
      end
  end

  info = {start_addr = addr, ret_addr = ret_addr, func_len = ret_addr-addr}
  return info
end

func print_passwd_so_far()
  print "Password: "
  passwd = ''
  for i=0,100,1 do
    val = read g_passwd_ptr+i 1
    if 31 < string.byte(val) and 125 > string.byte(val) then
      passwd = passwd .. val
      io.write(val)
    end
  end
  io.write('\n')
  print "%s\r" %{passwd}
end

-- Take a risk limiting the characters used in Permutations
acceptable_chars = {}
--acceptable_chars_str = ' .,abcdefghijklmnopqrstuvwxyz0123456789'
acceptable_chars_str = ' -,.aAbcdefghHiklnorstuwy'

for i = 1, #acceptable_chars_str do
    acceptable_chars[i] = acceptable_chars_str:sub(i, i)
end

func kmers(n, prev)
  prev = prev or {''}
  if n <= 0 then return prev end
  local k,r = 1,{}
  for i=1,#prev do
    for j=1,#acceptable_chars do
      r[k] = prev[i] .. acceptable_chars[j]
      k = k+1
    end
  end
  return kmers(n-1, r)
end


-- Generally useful information outside the dynamically decoded functions
on code 0x402ee4 do
  g_passwd_seg_cnt = rax
  print "+> Segment #: %d" %{g_passwd_seg_cnt}
end
on code 0x402ef9 do
  g_passwd_seg_offset = rdx
  print "+> Segment position: %d" %{rdx+1}
end
on code 0x402e25 do
  val = us:UnpackAddr(read(rbp-0x20))
  print "Checking input len exp:%d vs given:%d " %{rax, val}
end
on code 0x403b23 do
  g_passwd_ptr = rdi
end

--[[
on code 0x403038 do
  print "Call to memcpy"
  print "   0x%x(rdx), 0x%x(rsi), 0x%x(rdi)" %{rdx, rsi, rdi}
end
]]--

-- Print password at the end of a round
on code 0x403044 do
  if rdx == rax then
    print_passwd_so_far

    rip = rip + 9
  end
end

g_next_file_name = ''
on code 0x4031eb do
  print "RENAME function called"
  --Lets skip over this function call since we don't want to update the binary
  rip = rip + ins.bytes:len()
  print "0x%x(rdx),  0%x(rsi),  0x%x(rdi)" %{rdx, rsi, rdi}
  g_next_file_name = read rdi 15
  print g_next_file_name
end

on code 0x403078 do
  print "FOPEN, rdi hold pointer to filename"
  print "0x%x(rdx),  0%x(rsi),  0x%x(rdi)" %{rdx, rsi, rdi}
  tmp_filename = './' .. g_next_file_name
  print "Filename to open and read = %s" %{tmp_filename}
  write rdi tmp_filename
  print "Done Updating"
end

on code 0x403208 do
  rip = rip + ins.bytes:len()
end





--fgets
on code 0x403b23 do
  print "Getting User Input"
  -- Handle this so we don't have to type anything.
  -- Fill in the buffer with '-'*69
  input = '---------------------------------------------------------------------'
  write rdi input
  rax = rdi
  rip = 0x403b28
end


-- Generic BruteForce using instruction count
g_bf_options = {}
g_bf_idx = 1
func cb_inst_start_addr()
  --print "0x%x: CallBack Start Addr" %{ins.addr}
  --print "Testing string: \'%s\', writing to 0x%x" %{g_bf_str, g_pre_func_ptr}
  write g_pre_func_ptr g_bf_str
  str_from_mem = read g_pre_func_ptr g_pre_func_len
  --print "Here is what's in memory: %s" %{str_from_mem}
  g_bf_context = u.context_save()
  g_bf_inscount_start = us:Inscount()
  if 0 == g_bf_inscount_start then
    print "Error, no instruction count. Are you running with -inscount ?"
  end
end

func cb_inst_ret_addr()
  --print "0x%x) CallBack Checking Return Code" %{ins.addr}
  if 1 == rax then
    tmp_str = read g_pre_func_ptr g_pre_func_len
    print "Yay Found IT!: \'%s\'" %{tmp_str}
  else
    --print "%c instruction count = %d" %{g_bf_char, us:Inscount() - g_bf_inscount_start}
    if g_bf_timing_table[us:Inscount() - g_bf_inscount_start] then
      cnt = g_bf_timing_table[us:Inscount() - g_bf_inscount_start].count
    else
      cnt = 0
    end
    cnt = cnt + 1

    g_bf_timing_table[us:Inscount() - g_bf_inscount_start] = {character = g_bf_char, count = cnt}
    g_bf_char = g_bf_char-1
    g_bf_str = update_str_with_char_at_index(g_bf_str, string.char(g_bf_char), g_bf_idx)

    -- Character should be printable, so shouldn't be less than dec 31
    if 31 >= g_bf_char then
      --print "done for this character #%d" %{g_bf_idx}
      --print "Timing Table"
      --print g_bf_timing_table
      most_likely_char = g_bf_timing_table[#g_bf_timing_table].character
      --print "Most Likely correct char = \'%c\'" %{most_likely_char}
      g_bf_str = update_str_with_char_at_index(g_bf_str, string.char(most_likely_char), g_bf_idx)
      --print "updated Password segment = \'%s\'" %{g_bf_str}
      g_bf_idx = g_bf_idx + 1
      g_bf_char = 126
    end

    if g_pre_func_len >= g_bf_idx then
      u.context_restore(g_bf_context)
      rip = info.start_addr
    end

  end
end

func setup_generic_bruteforce(info)
  print "setup_generic_bruteforce: 0x%x" %{info.start_addr}
  hookers = {}
  if info.start_addr then
    -- reinitialize to max
    -- Lua starts array index at 1 :(
    g_bf_idx = 1

    g_bf_str = ''
    g_bf_char = 126
    g_bf_inscount_start = 0
    g_bf_timing_table = {}

    -- Initialize the inputs to max characters
    for i=1, g_pre_func_len do
      g_bf_str = g_bf_str .. string.char(g_bf_char)
    end

    print "Start of Generic BruteForce. "

    -- save context so we can restore it
    hh = u.hook_add(cpu.HOOK_CODE, cb_inst_start_addr, info.start_addr, info.start_addr)
    table.insert(hookers, hh)

    hh = u.hook_add(cpu.HOOK_CODE, cb_inst_ret_addr, info.ret_addr, info.ret_addr)
    table.insert(hookers, hh)

  end
  return hookers
end
-- =============================================================================





on code 0x4010f9 do
  print "compare 0x%x : 0x%x" %{rax, rdx}
end

func setup_handle_for_function(addr)

  info = get_func_info(addr)
  print info

  print g_pre_func_len
  if 1 >= g_pre_func_len then
    print "Doing Generic BruteForce"
    hookers = setup_generic_bruteforce(info)
  else
    --special_cases
    if 0x2fd == info.func_len then
      hookers = bruteforce_2fd(info)
    elif 0xb2 == info.func_len then
      hookers = bruteforce_b2(info)
    else
      hookers = setup_generic_bruteforce(info)
    end
  end
  return hookers
end


g_pre_func_len = 0
g_pre_func_ptr = 0
g_bf_hookers_table = {}
-- Handlers for decoded functions entry/exit
on code 0x402f06 do
  --print '\r'
  --print '-------------------------------------------------'
  print "+> Calling decoded function at address 0x%x" %{rcx}
  print "   ptr to encoded -> 0x%x(rdx), LENGTH: %d(rsi)" %{rdx, rsi}
  print "   ptr to user input -> 0x%x(rdi)" %{rdi}

  g_pre_func_len = rsi
  g_pre_func_ptr = rdi
  g_bf_hookers_table = setup_handle_for_function(rcx)
  print g_bf_hookers_table
  print '\r'
end
on code 0x402f08 do
  -- Force Success for Debugging
  --rax = 1
  print "<+ Returned %x (1 == Good, 0 == Bad)" %{rax}
  in_str = read g_pre_func_ptr g_pre_func_len
  print "Updated: \'%s\'" %{in_str}
  print ""

  g_pre_func_len = 0
  g_pre_func_ptr = 0
  for idx,hook in pairs(g_bf_hookers_table) do
    print "Deleting Hook:" hook
    u.hook_del(hook)
  end
  g_bf_hookers_table = {}
  print '-------------------------------------------------'
  print '\r'
end




-- Exiting will print what we have so far:
on sys 'exit_group' do
  print_passwd_so_far
end



g_flag_update_needed = false
func cb_reset_bf_chr()
  print "0x%x: CallBack Reset BF Character" %{ins.addr}
  bruteforce_char = 126
end

func cb_update_user_buffer()
  if true == g_flag_update_needed then
    print "0x%x: CallBack updating user data" %{ins.addr}
    write rax string.char(bruteforce_char)
    g_flag_update_needed = false
  end
end

func cb_save_bf_context()
  print "0x%x: CallBack saving context" %{ins.addr}
  bruteforce_contxt = u.context_save()
end



func cb_check_special_bruteforce()
  print "0x%x: CallBack Checking Xor bruteforce rax: %x rdx: %x" %{ins.addr, rax, rdx}
  g_flag_update_needed = true
  if rdx != rax then
    u.context_restore(bruteforce_contxt)
    rip = save_context_addr
    bruteforce_char = bruteforce_char-1

    -- Have a give up clause
    if 31 > bruteforce_char then
      rax = 0
      rip = give_up_addr
      print "GIVING UP"
    end
  else
    print "0x%x: yay, correct char was %c %d %x" %{ins.addr, bruteforce_char, bruteforce_char,bruteforce_char}
    bruteforce_char = 126
  end
end


func bruteforce_special(info, offsets)
  print "Start of Specific BruteForce"
  if info.start_addr then

    hookers = {}

    check_addr = info.start_addr + offsets.check_offset
    give_up_addr = info.start_addr + offsets.give_up_offset
    save_context_addr = info.start_addr + offsets.save_context_offset
    update_buffer_addr = info.start_addr + offsets.update_buffer_offset
    reset_bf_char_addr = info.start_addr + offsets.reset_bf_char_offset

    print "  check_addr 0x%x" %{check_addr}
    print "  give_up_addr 0x%x" %{give_up_addr}
    print "  save_context_addr 0x%x" %{save_context_addr}
    print "  update_buffer_addr 0x%x" %{update_buffer_addr}
    print "  reset_bf_char_addr 0x%x" %{reset_bf_char_addr}

    hh = u.hook_add(cpu.HOOK_CODE, cb_reset_bf_chr, reset_bf_char_addr,reset_bf_char_addr)
    table.insert(hookers, hh)

    hh = u.hook_add(cpu.HOOK_CODE, cb_update_user_buffer, update_buffer_addr, update_buffer_addr)
    table.insert(hookers, hh)

    hh = u.hook_add(cpu.HOOK_CODE, cb_save_bf_context, save_context_addr, save_context_addr)
    table.insert(hookers, hh)

    hh = u.hook_add(cpu.HOOK_CODE, cb_check_special_bruteforce, check_addr, check_addr)
    table.insert(hookers, hh)

    return hookers
  end
end

func bruteforce_2fd(info)
  -- Tis but scratch
  offsets = {
        reset_bf_char_offset = 697,
        save_context_offset = 700,
        update_buffer_offset = 710,
        check_offset = 729,
        give_up_offset = 729+4,
      }
  print offsets

  return bruteforce_special(info, offsets)
end
-- =============================================================================

func cb_perm_start_addr()
  --print "0x%x: CallBack Permutations Start Addr " %{ins.addr}
  curr_str = g_permutations_table[g_permutations_idx]
  write g_pre_func_ptr curr_str
  --print "Trying %s" %{curr_str}
  --str_from_mem = read g_pre_func_ptr g_pre_func_len
  -- print "Here is what's in memory: %s" %{str_from_mem}
  g_bf_context = u.context_save()
end

func cb_perm_ret_addr()
  --print "0x%x) CallBack Permutations Checking Return Code" %{ins.addr}
  if 1 == rax then
    tmp_str = read g_pre_func_ptr g_pre_func_len
    print "Yay Found IT!: \'%s\'" %{tmp_str}
  else
    --print "#%d)checksum: 0x%x" %{g_permutations_idx, rdx}
    if g_permutations_idx <= #g_permutations_table then
      u.context_restore(g_bf_context)
      rip = info.start_addr
      g_permutations_idx = g_permutations_idx + 1
    end

  end
end

func bruteforce_permutations(info)
  print "Setup bruteforce_permutations: 0x%x" %{info.start_addr}
  hookers = {}
  g_bf_str = ''
  if info.start_addr then

    -- Initialize the Permutations table
    g_permutations_table = kmers(g_pre_func_len)
    g_permutations_idx = 1

    for i=1, g_pre_func_len do
      g_bf_str = g_bf_str .. string.char(g_bf_char)
    end

    print "Start of Permutations BruteForce. "

    -- save context so we can restore it
    hh = u.hook_add(cpu.HOOK_CODE, cb_perm_start_addr, info.start_addr, info.start_addr)
    table.insert(hookers, hh)

    hh = u.hook_add(cpu.HOOK_CODE, cb_perm_ret_addr, info.ret_addr, info.ret_addr)
    table.insert(hookers, hh)

  end --if start_addr
  return hookers
end

func bruteforce_b2(info)
  offsets = {
        reset_bf_char_offset = 0,
        save_context_offset = 1,
        update_buffer_offset = 48,
        check_offset = 161, --0x402c62 check rax == 1
        give_up_offset = 165,
      }
  print offsets

  return bruteforce_permutations(info)
end


-- Opens a file in append mode
file = io.open("magic.keys", "a")

-- sets the default output file as test.lua
io.output(file)
