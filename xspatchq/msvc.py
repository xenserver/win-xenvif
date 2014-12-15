
import subprocess
import shutil
import os
import xspatchq.buildtool as xsbuildtool

def get_version():
    vsenv ={} 
    vars = subprocess.check_output([os.environ['VS']+'\\VC\\vcvarsall.bat', 
                                        '&&', 'set'], 
                                    shell=True)
    for var in vars.splitlines():
        k, _, v = map(str.strip, var.strip().decode('utf-8').partition('='))
        if k.startswith('?'):
            continue
        vsenv[k] = v

    if vsenv['VisualStudioVersion'] == '11.0' :
        return 'vs2012'
    elif vsenv['VisualStudioVersion'] == '12.0' :
        return 'vs2013'

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



def sdv_clean(name, vs):
    path = [vs, name, 'sdv']
    print(path)

    shutil.rmtree(os.path.join(*path), True)

    path = [vs, name, 'sdv.temp']
    print(path)

    shutil.rmtree(os.path.join(*path), True)

    path = [vs, name, 'staticdv.job']
    print(path)

    try:
        os.unlink(os.path.join(*path))
    except OSError:
        pass

    path = [vs, name, 'refine.sdv']
    print(path)

    try:
        os.unlink(os.path.join(*path))
    except OSError:
        pass

    path = [vs, name, 'sdv-map.h']
    print(path)

    try:
        os.unlink(os.path.join(*path))
    except OSError:
        pass


def run_sdv(name, dir, vs):
    configuration = xsbuildtool.get_configuration('Windows 8', False)
    platform = 'x64'

    msbuild(platform, configuration, 'Build', name + '.vcxproj',
            '', os.path.join(vs, name))

    sdv_clean(name, vs)

    msbuild(platform, configuration, 'sdv', name + '.vcxproj',
            '/p:Inputs="/scan"', os.path.join(vs, name))

    path = [vs, name, 'sdv-map.h']
    file = open(os.path.join(*path), 'r')

    for line in file:
        print(line)

    file.close()

    msbuild(platform, configuration, 'sdv', name + '.vcxproj',
            '/p:Inputs="/check:default.sdv"', os.path.join(vs, name))

    path = [vs, name, 'sdv', 'SDV.DVL.xml']
    remove_timestamps(os.path.join(*path))

    msbuild(platform, configuration, 'dvl', name + '.vcxproj',
            '', os.path.join(vs, name))

    path = [vs, name, name + '.DVL.XML']
    shutil.copy(os.path.join(*path), dir)

    path = [vs, name, 'refine.sdv']
    if os.path.isfile(os.path.join(*path)):
        msbuild(platform, configuration, 'sdv', name + '.vcxproj',
                '/p:Inputs=/refine', os.path.join(vs, name))

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

    bin = os.path.join(os.getcwd(), 'msbuild.bat')

    status = xsbuildtool.shell([bin], dir)

    if (status != 0):
        raise msbuild_failure(configuration)


def build_sln(name, release, arch, debug, vs):
    configuration = xsbuildtool.get_configuration(release, debug)

    if arch == 'x86':
        platform = 'Win32'
    elif arch == 'x64':
        platform = 'x64'

    cwd = os.getcwd()

    msbuild(platform, configuration, 'Build', name + '.sln', '', vs)
