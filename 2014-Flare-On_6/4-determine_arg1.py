#!/usr/bin/env python
import string
import shlex, subprocess

cmd = "/home/code/usercorn/usercorn run -inscount -ex 1-patch_ptrace.usrcrn ./e7bc5d2c0cf4480348f5504196561297 {} {}"

characters_to_test = string.digits + string.ascii_letters

flag = ''
for i in reversed(range(1, 11)):
  for c in characters_to_test:
    tmp_flag = flag + (c*1) + ('A'*(i-1))
    tmp_cmd = cmd.format(tmp_flag, 'A'*20)
    print tmp_cmd
    args = shlex.split(tmp_cmd)
    p = subprocess.Popen(args,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (s_out, s_err) = p.communicate()
    for line in s_err.splitlines():
      if 'inscount' in line:
        print 'Testing %s' %tmp_flag,
        print line.split(':')[1]
        print '-'*80



