#!/bin/env python3
#
# rpm-verity.py
#
# This is a tool to generate a side-load rpm with fs-verity signatures
# for an existing binary rpm
#
import os
import sys
import rpm
from argparse import ArgumentParser
from stat import *

parser = ArgumentParser()

parser.add_argument(
    "-r", "--rpm",
    help="input rpm",
    required=True,
    type=str,
    default=False,
)
parser.add_argument(
    "-p", "--path",
    help="path for work directory, default is /tmp/rpm-verity",
    required=False,
    type=str,
    default="/tmp/rpm-verity",
)
parser.add_argument(
    "-c", "--cert",
    help="certificate file for signing",
    required=True,
    type=str,
)
parser.add_argument(
    "-k", "--key",
    help="key file for signing",
    required=True,
    type=str,
)
parser.add_argument(
    "-f", "--fsverity",
    help="fsverity binary",
    required=False,
    type=str,
    default="fsverity"
)
parser.add_argument(
    "-B", "--rpmbuild",
    help="rpmbuild binary",
    required=False,
    type=str,
    default="rpmbuild"
)
parser.add_argument(
    "-V", "--verity-prefix",
    help="base directory for signature files, default /var/verity",
    required=False,
    type=str,
    default="/var/verity"
)
parser.add_argument(
    "-v", "--verbose",
    help="Verbose output",
    required=False,
    default=False,
    action="store_true"
)
parser.add_argument(
    "-vs", "--verbose-spec",
    help="dump generated .spec to stdout during build",
    required=False,
    default=False,
    action="store_true"
)

spectemplate="""
Name:		{}
Release:	{}
Version:	{}
Requires:	{}
Summary:	Verity signatures for {}
License:	None

%description
Verity signatures

%files
%defattr(444, root, root, 755)
"""

def build_specfile(packagename, version, release, datafilelist, sigfilelist):
    origpackage = "{}-{}-{}".format(packagename, version, release)
    specfile = spectemplate.format(packagename+"-verity", release, version,
                                   packagename+" = "+version+"-"+release,
                                   origpackage)

    for sf in sigfilelist:
        specfile += sf
        specfile += '\n'
    specfile += "%post\n"
    for df, sf in zip(datafilelist, sigfilelist):
        specfile += "fsverity enable --signature={} {}".format(sf, df)
        specfile += '\n'

    if (args.verbose_spec):
        print(specfile)
    specfn = args.path+"/verity.spec"
    specfd = open(specfn, "w")
    specfd.write(specfile)
    specfd.close()
    return specfn

def generate_signatures(filenames, filemodes, fileflags, datapath, veritypath):
    sigfilelist = []
    datafilelist = []
    quiet = "> /dev/null"

    os.makedirs(veritypath+args.verity_prefix)
    for fn, fm, ff in zip(filenames, filemodes, fileflags):
        # Only parse regular files (no directories, symlinks, etc),
        # skip files marked as config and doc files in the RPM
        if (S_ISREG(fm) and not (ff & rpm.RPMFILE_CONFIG) and not
            (ff & rpm.RPMFILE_DOC)):
            datafile = fn.decode("utf-8")
            datafilelist += [datafile]
            (filepath, filename) = os.path.split(datafile)
            sigpath = args.verity_prefix+filepath
            if not os.path.exists(veritypath+sigpath):
                os.makedirs(veritypath+sigpath)
            sigfile = args.verity_prefix+datafile+".sig"
            sigfilelist += [sigfile]
            if args.verbose:
                print("%06o %s" % (fm, fn.decode("utf-8")))
                print("{} sign {} {} --key={} --cert={}"
                      .format(args.fsverity, datapath+datafile,
                              veritypath+sigfile, args.key, args.cert))
                quiet = ""
            os.system("{} sign {} {} --key={} --cert={} {}"
                      .format(args.fsverity, datapath+datafile,
                              veritypath+sigfile, args.key, args.cert, quiet))

    return sigfilelist, datafilelist

args = parser.parse_args()
    
if args.rpm:
    print(args.rpm)

ts = rpm.TransactionSet()

fdno = os.open(args.rpm, os.O_RDONLY)
hdr = ts.hdrFromFdno(fdno)
os.close(fdno)

packagename = hdr['name'].decode("utf-8")
version = hdr['version'].decode("utf-8")
release = hdr['release'].decode("utf-8")
print("Processing RPM: {}-{}-{}".format(packagename, version, release))

filenames=hdr['filenames']
filemodes=hdr['filemodes']
fileflags=hdr['fileflags']
md5sums=hdr['filemd5s']
datapath = args.path+"/data"
veritypath = args.path+"/verity"

# Because CentOS 7 ships an ancient version of cpio
os.makedirs(datapath)
if args.verbose:
    print("cd {} ; rpm2cpio {} | cpio -id".format(datapath, args.rpm))
os.system("cd {} ; rpm2cpio {} | cpio -id".format(datapath, args.rpm))

sigfilelist, datafilelist = generate_signatures(filenames, filemodes, fileflags,
                                                datapath, veritypath)

specfn = build_specfile(packagename, version, release, datafilelist,
                        sigfilelist)
os.system("rm -rf {}".format(datapath))

# Build the RPM
buildcmd = "{} --buildroot={} -bb {}".format(args.rpmbuild, veritypath, specfn)
if args.verbose:
    print(buildcmd)
os.system(buildcmd)

os.remove(specfn)
os.rmdir(args.path)
