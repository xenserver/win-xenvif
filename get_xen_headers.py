#!python -u

import os, sys
import shutil
import subprocess
import re

def shell(command):
    print(command)
    sys.stdout.flush()

    pipe = os.popen(' '.join(command), 'r', 1)

    for line in pipe:
        print(line.rstrip())

    return pipe.close()

def get_repo(url):
    shell(['rm', '-rf', 'working'])
    shell(['git', 'clone', '--no-checkout', url, 'working'])

def get_branch(tag):
    cwd = os.getcwd()
    os.chdir('working')
    shell(['git', 'checkout', '-b', tag])
    os.chdir(cwd)

def copy_file(src_dir, dst_dir, name):
    try:
        os.makedirs('include\\xen\\%s' % dst_dir)
    except OSError:
        None

    src = open('working\\xen\\include\\%s\\%s' % (src_dir, name), 'r')
    dst = open('include\\xen\\%s\\%s' % (dst_dir, name), 'w')

    print(name)

    for line in src:
        line = re.sub(' unsigned long', ' ULONG_PTR', line)
        line = re.sub('\(unsigned long', '(ULONG_PTR', line)
        line = re.sub(' long', ' LONG_PTR', line)
        line = re.sub('\(long', '(LONG_PTR', line)
        dst.write(line)

    dst.close()
    src.close()

if __name__ == '__main__':
    get_repo('git://xenbits.xen.org/xen.git')
    get_branch(sys.argv[1])

    copy_file('public', '.', 'xen.h')

    copy_file('public', '.', 'xen-compat.h')
    copy_file('public', '.', 'trace.h')
    copy_file('public', '.', 'grant_table.h')

    copy_file('public\\arch-x86', 'arch-x86', 'xen.h')
    copy_file('public\\arch-x86', 'arch-x86', 'xen-x86_32.h')
    copy_file('public\\arch-x86', 'arch-x86', 'xen-x86_64.h')

    copy_file('public\\io', '.', 'netif.h')
