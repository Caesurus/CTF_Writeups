#!/usr/bin/env python
import shlex, subprocess

cmd = "/home/code/usercorn/usercorn run -inscount -ex 1-patch_ptrace.usrcrn ./e7bc5d2c0cf4480348f5504196561297 {} {}"

for i in range(1,15):
  tmp_cmd = cmd.format('1'*i, 'A')
  print tmp_cmd
  args = shlex.split(tmp_cmd)
  p = subprocess.Popen(args,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (s_out, s_err) = p.communicate()
  for line in s_err.splitlines():
    if 'inscount' in line:
      print 'Chars in first arg: %d' %i
      print line
      print '-'*80



