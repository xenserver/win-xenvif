#!python -u

import os, sys
import datetime
import re
import glob
import tarfile
import subprocess
import shutil

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


def make_header():
    now = datetime.datetime.now()

    file = open('include\\version.h', 'w')
    file.write('#define MAJOR_VERSION\t' + os.environ['MAJOR_VERSION'] + '\n')
    file.write('#define MAJOR_VERSION_STR\t"' + os.environ['MAJOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MINOR_VERSION\t' + os.environ['MINOR_VERSION'] + '\n')
    file.write('#define MINOR_VERSION_STR\t"' + os.environ['MINOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MICRO_VERSION\t' + os.environ['MICRO_VERSION'] + '\n')
    file.write('#define MICRO_VERSION_STR\t"' + os.environ['MICRO_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define BUILD_NUMBER\t' + os.environ['BUILD_NUMBER'] + '\n')
    file.write('#define BUILD_NUMBER_STR\t"' + os.environ['BUILD_NUMBER'] + '"\n')
    file.write('\n')

    file.write('#define YEAR\t' + str(now.year) + '\n')
    file.write('#define YEAR_STR\t"' + str(now.year) + '"\n')

    file.write('#define MONTH\t' + str(now.month) + '\n')
    file.write('#define MONTH_STR\t"' + str(now.month) + '"\n')

    file.write('#define DAY\t' + str(now.day) + '\n')
    file.write('#define DAY_STR\t"' + str(now.day) + '"\n')

    file.close()


def copy_inf(name):
    src = open('src\\%s.inf' % name, 'r')
    dst = open('proj\\%s.inf' % name, 'w')

    for line in src:
        line = re.sub('@MAJOR_VERSION@', os.environ['MAJOR_VERSION'], line)
        line = re.sub('@MINOR_VERSION@', os.environ['MINOR_VERSION'], line)
        line = re.sub('@MICRO_VERSION@', os.environ['MICRO_VERSION'], line)
        line = re.sub('@BUILD_NUMBER@', os.environ['BUILD_NUMBER'], line)
        dst.write(line)

    dst.close()
    src.close()


def get_expired_symbols(name, age = 30):
    path = os.path.join(os.environ['SYMBOL_SERVER'], '000Admin\\history.txt')

    try:
        file = open(path, 'r')
    except IOError:
        return []

    threshold = datetime.datetime.utcnow() - datetime.timedelta(days = age)

    expired = []

    for line in file:
        item = line.split(',')

        if (re.match('add', item[1])):
            id = item[0]
            date = item[3].split('/')
            time = item[4].split(':')
            tag = item[5].strip('"')

            age = datetime.datetime(year = int(date[2]),
                                    month = int(date[0]),
                                    day = int(date[1]),
                                    hour = int(time[0]),
                                    minute = int(time[1]),
                                    second = int(time[2]))
            if (tag == name and age < threshold):
                expired.append(id)

        elif (re.match('del', item[1])):
            id = item[2].rstrip()
            try:
                expired.remove(id)
            except ValueError:
                pass

    file.close()

    return expired


def get_configuration(release, debug):
    configuration = release

    if debug:
        configuration += ' Debug'
    else:
        configuration += ' Release'

    return configuration

def get_target_path(release, arch, debug):
    configuration = get_configuration(release, debug)
    name = ''.join(configuration.split(' '))
    target = { 'x86': os.sep.join([name, 'Win32']), 'x64': os.sep.join([name, 'x64']) }
    target_path = os.sep.join(['proj', target[arch]])

    return target_path


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

def msbuild(platform, configuration, target, file, args, dir):
    os.environ['PLATFORM'] = platform
    os.environ['CONFIGURATION'] = configuration
    os.environ['TARGET'] = target
    os.environ['FILE'] = file
    os.environ['EXTRA'] = args

    cwd = os.getcwd()
    bin = os.path.join(cwd, 'msbuild.bat')

    print(bin)
    print(dir)

    os.chdir(dir)
    status = shell(bin)
    os.chdir(cwd)

    if (status != None):
        raise msbuild_failure(configuration)

def build_sln(name, release, arch, debug):
    configuration = get_configuration(release, debug)

    if arch == 'x86':
        platform = 'Win32'
    elif arch == 'x64':
        platform = 'x64'

    cwd = os.getcwd()

    msbuild(platform, configuration, 'Build', name + '.sln', '', 'proj')

def remove_timestamps(path):
    try:
        os.unlink(path + '.orig')
    except OSError:
        pass

    os.rename(path, path + '.orig')

    src = open(path + '.orig', 'r')
    dst = open(path, 'w')

    for line in src:
        if line.find('TimeStamp') == -1:
            dst.write(line)

    dst.close()
    src.close()

def run_sdv(name, dir):
    configuration = get_configuration('Windows 8', False)
    platform = 'x64'

    msbuild(platform, configuration, 'Build', name + '.vcxproj',
            '', os.path.join('proj', name))
    msbuild(platform, configuration, 'sdv', name + '.vcxproj',
            '/p:Inputs="/clean"', os.path.join('proj', name))
    msbuild(platform, configuration, 'sdv', name + '.vcxproj',
            '/p:Inputs="/check:default.sdv"', os.path.join('proj', name))

    path = ['proj', name, 'sdv', 'SDV.DVL.xml']
    remove_timestamps(os.path.join(*path))

    msbuild(platform, configuration, 'dvl', name + '.vcxproj',
            '', os.path.join('proj', name))

    path = ['proj', name, name + '.DVL.XML']
    shutil.copy(os.path.join(*path), dir)

def symstore_del(name, age):
    symstore_path = [os.environ['KIT'], 'Debuggers']
    if os.environ['PROCESSOR_ARCHITECTURE'] == 'x86':
        symstore_path.append('x86')
    else:
        symstore_path.append('x64')
    symstore_path.append('symstore.exe')

    symstore = os.path.join(*symstore_path)

    for id in get_expired_symbols(name, age):
        command=['"' + symstore + '"']
        command.append('del')
        command.append('/i')
        command.append(str(id))
        command.append('/s')
        command.append(os.environ['SYMBOL_SERVER'])

        shell(' '.join(command))

def symstore_add(name, release, arch, debug):
    cwd = os.getcwd()
    target_path = get_target_path(release, arch, debug)

    symstore_path = [os.environ['KIT'], 'Debuggers']
    if os.environ['PROCESSOR_ARCHITECTURE'] == 'x86':
        symstore_path.append('x86')
    else:
        symstore_path.append('x64')
    symstore_path.append('symstore.exe')

    symstore = os.path.join(*symstore_path)

    version = '.'.join([os.environ['MAJOR_VERSION'],
                        os.environ['MINOR_VERSION'],
                        os.environ['MICRO_VERSION'],
                        os.environ['BUILD_NUMBER']])

    os.chdir(target_path)
    command=['"' + symstore + '"']
    command.append('add')
    command.append('/s')
    command.append(os.environ['SYMBOL_SERVER'])
    command.append('/r')
    command.append('/f')
    command.append('*.pdb')
    command.append('/t')
    command.append(name)
    command.append('/v')
    command.append(version)

    shell(' '.join(command))

    os.chdir(cwd)


def callfnout(cmd):
    print(cmd)

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = sub.communicate()[0]
    ret = sub.returncode

    if ret != 0:
        raise(Exception("Error %d in : %s" % (ret, cmd)))

    return output.decode('utf-8')


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


if __name__ == '__main__':
    debug = { 'checked': True, 'free': False }
    driver = 'xenvif'

    os.environ['MAJOR_VERSION'] = '7'
    os.environ['MINOR_VERSION'] = '2'
    os.environ['MICRO_VERSION'] = '0'

    if 'BUILD_NUMBER' not in os.environ.keys():
        os.environ['BUILD_NUMBER'] = next_build_number()

    print("BUILD_NUMBER=%s" % os.environ['BUILD_NUMBER'])

    if 'GIT_REVISION' in os.environ.keys():
        revision = open('revision', 'w')
        print(os.environ['GIT_REVISION'], file=revision)
        revision.close()

    make_header()

    copy_inf(driver)

    symstore_del(driver, 30)

    release = 'Windows Vista'

    build_sln(driver, release, 'x86', debug[sys.argv[1]])
    build_sln(driver, release, 'x64', debug[sys.argv[1]])

    symstore_add(driver, release, 'x86', debug[sys.argv[1]])
    symstore_add(driver, release, 'x64', debug[sys.argv[1]])

    if len(sys.argv) <= 2 or sys.argv[2] != 'nosdv':
        run_sdv(driver, driver)

    listfile = callfnout(['git','ls-tree', '-r', '--name-only', 'HEAD'])   
    archive(driver + '\\source.tgz', listfile.splitlines(), tgz=True)
    archive(driver + '.tar', [driver,'revision'])

