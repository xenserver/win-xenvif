#!/usr/bin/env python

import os, sys, shutil

if __name__ == '__main__':
    file = os.popen('git status -u --porcelain')

    for line in file:
        item = line.split(' ')
        if item[0] == '??':
            path = ' '.join(item[1:]).rstrip()
            print(path)
            try:
                if os.path.isfile(path):
                    os.remove(path)
                if os.path.isdir(path):
                    shutil.rmtree(path)
            except OSError:
                None
                
    file.close()
