#!/usr/bin/env python
import string
import shlex, subprocess

cmd = "/home/code/usercorn/usercorn run -inscount -ex 5-patch_ptrace_sleep.usrcrn ./e7bc5d2c0cf4480348f5504196561297 4815162342 {}"

characters_to_test = string.digits + '.' + string.ascii_letters + '@' + '-'

flag = 'l1nhax.hurt.u5.a1l@flare-on'
for i in reversed(range(len(flag), 30)):

  results = {}
  last_cnt = 0
  for c in characters_to_test:
    tmp_flag = flag + (c*1) + ('A'*(i-1))
    tmp_cmd = cmd.format(tmp_flag)
    args = shlex.split(tmp_cmd)
    p = subprocess.Popen(args,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (s_out, s_err) = p.communicate()
    for line in s_err.splitlines():
      if 'inscount' in line:
        count = int(line.split(':')[1])
        print 'Testing %s, %d' %(tmp_flag,count)
        results[c] = count
        #print '-'*80
    if last_cnt == 0:
      last_cnt = count
    elif count > last_cnt:
      break    
          
  likely_char = max(results, key=results.get)
  flag += likely_char
  print "So Far: %s" %(flag)





