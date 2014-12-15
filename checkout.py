import xspatchq.gittool as xsgittool
import patchqueue
import os
import sys
import posixpath

def clone_apply_patchqueue():
    print ("Destination "+patchqueue.package)
    xsgittool.clone_to(patchqueue.baserepo, patchqueue.basetag, patchqueue.package)
    pregitdir = os.getcwd()
    os.chdir(patchqueue.package);
    for patch in patchqueue.patchlist:
        xsgittool.apply(posixpath.join('..',patch))
    os.chdir(pregitdir)

if __name__ == '__main__':
    clone_apply_patchqueue()
