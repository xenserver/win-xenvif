#!python -u

import os, sys
import subprocess
from pprint import pprint

def callfnout(cmd):
    print(cmd)

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = sub.communicate()[0]
    ret = sub.returncode

    if ret != 0:
        raise(Exception("Error %d in : %s" % (ret, cmd)))

    return output.decode('utf-8')

def regenerate_kdfiles(filename, arch, pkg, source):
	cwd = os.getcwd()
	file = open(filename, 'w')
	os.chdir(pkg + '/' + arch)
	drivers = callfnout(['ls','*.sys']).split()
	pprint(drivers)
	for driver in drivers:
		file.write("map\n")
		file.write('\SystemRoot\System32\drivers\\' + driver + '\n')
		file.write(source + '\\' + pkg + '\\' + arch + '\\' + driver + '\n')
		file.write('\n')
	os.chdir(cwd)
	file.close()

if __name__ == '__main__':
	pkg = 'xenvif'
	source = os.getcwd()
	regenerate_kdfiles('kdfiles32.txt', 'x86', pkg, source)
	regenerate_kdfiles('kdfiles64.txt', 'x64', pkg, source)
