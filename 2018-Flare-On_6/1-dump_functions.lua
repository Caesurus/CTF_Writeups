-- hooking code instruction that calls the decoded function
on code 0x402f06 do
  addr_start = rcx
  addr_end = 0

  -- read disassembly into a table in order to analyze
  func_code = u.dis(addr_start, 1000)

  -- now loop through it to find the return instruction
  for idx, instruction in pairs(func_code) do
    if 'ret' == instruction.name then
      addr_end = instruction.addr
      break
    end
  end

  print "Decoded function, start %#x - %#x" %{addr_start, addr_end}
  print "Function Length: %#x" %{addr_end-addr_start}
  -- print the function
  dis addr_start addr_end-addr_start
  print string.rep("-", 70)
end

-- This is the instruction after the decoded function returns.
on code 0x402f08 do
  print 'Function returned %#x' %{rax}
  -- lets overwrite that with a success (1)
  rax = 1
end

on code 0x403b23 do
  -- This is where fgets() is called,
  --   rdi has the pointer to the buffer
  --   rax is the retun from fgets() which should be the ptr to the buffer

  -- Fill in the buffer with '-'*0x80
  ptr_buffer = string.rep("-", 70)
  -- Write this string to the buffer, this will update the memory
  write rdi ptr_buffer

  -- set the return to the initial ptr to the buffer
  rax = rdi
  -- Increment rip to skip this instruction and avoid call to fgets()
  rip = rip + ins.bytes:len()

  -- Proceed without being bothered to enter password
end
