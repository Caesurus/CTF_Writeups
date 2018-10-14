#!/usr/bin/python2
script = """
from z3 import *
s = Solver()
"""
script_post = """
if s.check():
  m = s.model()
"""
#c1  = BitVec('c1', 8)
from hashlib import sha512
import sys

def generate_script(x, chalbox):
    script = ""
    length, gates, check = chalbox
    for i in range(check[0]+1):
        #print "b%d  = BitVec('b%d', 1)" % (i,i)
        script += "b%d  = BitVec('b%d', 1)\n" % (i,i)
    script += "# check[0] = %d\n" %(check[0])
    script += "s.add(b%d == 0)\n" %(check[0])
    b_idx = length
    for name, args in gates:
        if name == 'true':
            script += "s.add(b%d == 1)\n" %(b_idx)
        else:
            #u1 = b[args[0][0]] ^ args[0][1]
            #u2 = b[args[1][0]] ^ args[1][1]
            if name == 'or':
                #b.append(u1 | u2)
                script += "s.add(b%d == (b%d ^ %d)|(b%d ^ %d))\n" %(b_idx, args[0][0], args[0][1], args[1][0], args[1][1])
            elif name == 'xor':
                #b.append(u1 ^ u2)
                script += "s.add(b%d == (b%d ^ %d)^(b%d ^ %d))\n" %(b_idx, args[0][0], args[0][1], args[1][0], args[1][1])
        b_idx += 1
    script += script_post
    script += "  final_list = []\n"
    for i in range(check[0]+1):
        #script += '  print \"b%d = %%s\" %%(m[b%d])\n' % (i,i)
        script += '  val = int("%%s" %%(m[b%d]))\n' % (i)
        script += '  final_list.append(val)\n'
    script += "import sys\n"
    script += "flag_bin_str = ''\n"
    script += "for i in reversed(range(%d)):\n" %(length)
    script += "  sys.stdout.write(\"%d\" %(final_list[i]))\n"
    script += "  flag_bin_str += \"%d\" %(final_list[i])\n"
    script += "print(\"\\n\")\n"
    script += "print(int(flag_bin_str, 2))\n"
    return script


def verify(x, chalbox):
    length, gates, check = chalbox
    b = [(x >> i) & 1 for i in range(length)]
    for name, args in gates:
        if name == 'true':
            b.append(1)
        else:
            u1 = b[args[0][0]] ^ args[0][1]
            u2 = b[args[1][0]] ^ args[1][1]
            if name == 'or':
                b.append(u1 | u2)
            elif name == 'xor':
                b.append(u1 ^ u2)
    print length
    print b[length]
    return b[check[0]] ^ check[1]

def dec(x, w):
    z = int(sha512(str(int(x))).hexdigest(), 16)
    return '{:x}'.format(w ^ z).decode('hex')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: ' + sys.argv[0] + ' <map.txt>'
        print 'Example: Try Running ' + sys.argv[0] + ' map1.txt'
        exit(1)
    with open(sys.argv[1], 'r') as f:
        cipher, chalbox = eval(f.read())

    key = 0
    #print 'Attempting to decrypt ' + sys.argv[2] + '...'
    script_text = generate_script(key,chalbox)
    script += script_text
    print script
