
import os
import sys
import tarfile
import subprocess

def get_configuration(release, debug):
    configuration = release

    if debug:
        configuration += ' Debug'
    else:
        configuration += ' Release'

    return configuration

def archive(filename, files, tgz=False):
    access='w'
    if tgz:
        access='w:gz'
    tar = tarfile.open(filename, access)
    for name in files :
        try:
            tar.add(name)
        except:
            pass
    tar.close()

def getfiles(dir):
    return [ os.path.join(dp, f) for dp, dn, filenames in os.walk(dir) for f in filenames ]

def shell(command, dir):
    print(dir)
    print(command)
    sys.stdout.flush()
    
    sub = subprocess.Popen(' '.join(command), cwd=dir,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    for line in sub.stdout:
        print(line.decode(sys.getdefaultencoding()).rstrip())

    sub.wait()

    return sub.returncode

def get_target_path(release, arch, debug, vs):
    configuration = get_configuration(release, debug)
    name = ''.join(configuration.split(' '))
    target = { 'x86': os.sep.join([name, 'Win32']), 'x64': os.sep.join([name, 'x64']) }
    target_path = os.sep.join([vs, target[arch]])

    return target_path

def default_environment(name, value):
    if name not in os.environ.keys():
        os.environ[name] = value

def next_build_number():
    try:
        file = open('.build_number', 'r')
        build_number = file.read()
        file.close()
    except IOError:
        build_number = '0'

    file = open('.build_number', 'w')
    file.write(str(int(build_number) + 1))
    file.close()

    return build_number

