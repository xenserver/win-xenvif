#!/usr/bin/env python

import os, sys

file = os.popen('hg status')

for line in file:
    item = line.split(' ')
    if item[0] == '?':
        path = ' '.join(item[1:]).rstrip()
        print(path)
        os.remove(path)

file.close()
