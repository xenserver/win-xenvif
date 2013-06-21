#!python -u

import os, sys
import datetime
import re
import glob
import tarfile
import subprocess

def shell(command):
    print(command)
    sys.stdout.flush()

    pipe = os.popen(command, 'r', 1)

    for line in pipe:
        print(line.rstrip())

    return pipe.close()

class msbuild_failure(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

def msbuild(name, target, sdv_arg):
    cwd = os.getcwd()

    os.environ['CONFIGURATION'] = 'Windows 8 Release'
    os.environ['PLATFORM'] = 'x64'
    os.environ['TARGET'] = target
    os.environ['BUILD_FILE'] = name + '.vcxproj'
    os.environ['BUILD_ARGS'] = sdv_arg

    os.chdir('proj')
    os.chdir(name)
    status = shell('..\\msbuild.bat')
    os.chdir(cwd)

#    if (status != None):
#        raise msbuild_failure(sdv_arg)

def archive(filename, files, tgz=False):
    access='w'
    if tgz:
        access='w:gz'
    tar = tarfile.open(filename, access)
    for name in files :
        try:
            print('adding '+name)
            tar.add(name)
        except:
            pass
    tar.close()

if __name__ == '__main__':
    msbuild('xenvif', 'sdv', '/p:Inputs="/clean"')
    msbuild('xenvif', 'sdv', '/p:Inputs="/check:default.sdv"')
    msbuild('xenvif', 'dvl', '')
