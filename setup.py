#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created on 14.12.2020

import subprocess
import pathlib
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
from distutils.core import Command

pkg_name = "cpyvpn"

src_dir = pathlib.Path(__file__).absolute().parent


def make_version():

    VERSION = ""
    try:
        VERSION = subprocess.check_output(["git", "describe", "--tags"], stderr=subprocess.STDOUT).decode().strip()
    except subprocess.CalledProcessError:
        pass
    if VERSION:
        vermod = src_dir / pkg_name / "__version__.py"
        with open(vermod, "wt") as f:
            f.write("VERSION='{}'".format(VERSION))
    else:
        from cpyvpn import __version__
        VERSION = __version__.VERSION

    return VERSION

ma_mod = "cpga"
# Standalone CheckPoint Gateway Authentication helper
class build_cpga(Command):

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import sys, os
        import zipfile
        import stat

        main_py = '''
# -*- coding: utf-8 -*-
import sys
from {}.ma import main
sys.exit(main())
    '''.format(pkg_name)
        old_mods = set(sys.modules.keys())
        from cpyvpn import ma
        new_mods = set(sys.modules.keys())

        zip_root = pathlib.Path(pkg_name)

        target = src_dir / pathlib.Path("dist") / pathlib.Path(ma_mod + ".pyz")
        os.makedirs(target.parent, exist_ok=True)
        with open(target, 'wb') as fd:
            fd.write(b'#!/usr/bin/env python\n')

            with zipfile.ZipFile(fd, 'w', compression=zipfile.ZIP_DEFLATED) as z:
                for m in new_mods - old_mods:
                    mm = sys.modules[m]
                    if not hasattr(mm, "__file__"):
                        continue
                    mod = pathlib.Path(mm.__file__)

                    if str(src_dir) in str(mod):
                        z.write(mod, zip_root.joinpath(mod.name).as_posix())
                z.writestr('__main__.py', main_py.encode('utf-8'))
        os.chmod(target, os.stat(target).st_mode | stat.S_IEXEC)


def main():

    setup(name=pkg_name,
               version=make_version(),
               packages=[pkg_name],
               entry_points={
                   'console_scripts': ['cp_client=' + pkg_name + '.client:main', 'cp_server=' + pkg_name + '.server:main', ma_mod+'=' + pkg_name + '.ma:main'],
               },
               cmdclass={
                   "build_cpga":build_cpga
               }
               )


if __name__ == "__main__":
    main()
