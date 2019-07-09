# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def options(opt):
    opt.load(['compiler_c', 'compiler_cxx'])

def configure(conf):
    conf.load(['compiler_c', 'compiler_cxx'])
    conf.check_cxx(lib='pthread', uselib_store='PTHREAD', define_name='HAVE_PTHREAD', mandatory=False)
    conf.check_cfg(path='pcap-config', package='libpcap', args=['--libs', '--cflags'], uselib_store='PCAP', mandatory=True)

def build(bld):
    bld.program(
        features = 'cxx',
        target='autoFace',
        source=bld.path.ant_glob(['src/*.cpp', 'src/log/*.cpp']),
        includes = "./src ./src/log",
        use='PCAP PTHREAD',
    )
