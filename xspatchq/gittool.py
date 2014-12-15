
import os
import shutil
import xspatchq.buildtool as xsbuildtool
import stat

def remove_readonly(func, path, execinfo):
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)

def apply(patchname):
    res = xsbuildtool.shell(['git', 'am', patchname], None)
    if res != 0 :
        raise Exception("git am "+patchname+" returned ", res)

def clone_to(repo, tag, destination):
    if os.path.exists(destination):
        shutil.rmtree(destination, onerror=remove_readonly)
    res = xsbuildtool.shell(['git','clone',repo, destination], None)
    if res != 0:
        raise Exception("git clone "+repo+" "+destination+" returned :", res)
    res = xsbuildtool.shell(['git','checkout',tag], destination)
    if res != 0:
        raise Exception("git checkout "+tag+" returned :", res)
