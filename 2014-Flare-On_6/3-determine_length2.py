#!/usr/bin/env python
import shlex, subprocess

cmd = "/home/code/usercorn/usercorn run -inscount -ex 1-patch_ptrace.usrcrn ./e7bc5d2c0cf4480348f5504196561297 {} {}"

for i in range(1,30):
  tmp_cmd = cmd.format('A'*10, '1'*i)
  print tmp_cmd
  args = shlex.split(tmp_cmd)
  p = subprocess.Popen(args,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (s_out, s_err) = p.communicate()
  for line in s_err.splitlines():
    if 'inscount' in line:
      print 'Chars in second arg: %d' %i
      print line
      print '-'*80



