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

    if (args.verbose):
        print(specfile)
    specfn = args.path+"/verity.spec"
    specfd = open(specfn, "w")
    specfd.write(specfile)
    specfd.close()
    return specfn

def generate_signatures(filenames, filemodes, datapath, veritypath):
    sigfilelist = []
    datafilelist = []
    os.system("mkdir -p {}".format(veritypath+args.verity_prefix))

    # Maybe allow for a filter to only touch files with executable bits set
    for fn, fm in zip(filenames, filemodes):
        if S_ISREG(fm):
            datafile = fn.decode("utf-8")
            datafilelist += [datafile]
            (filepath, filename) = os.path.split(datafile)
            sigpath = args.verity_prefix+filepath
            if not os.path.exists(sigpath):
                os.system("mkdir -p {}".format(veritypath+sigpath))
            sigfile = args.verity_prefix+datafile+".sig"
            sigfilelist += [sigfile]
            if args.verbose:
                print("%06o %s" % (fm, fn.decode("utf-8")))
                print("{} sign {} {} --key={} --cert={}"
                      .format(args.fsverity, datapath+datafile,
                              veritypath+sigfile, args.key, args.cert))
            os.system("{} sign {} {} --key={} --cert={}"
                      .format(args.fsverity, datapath+datafile,
                              veritypath+sigfile, args.key, args.cert))

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
package = "Package: {}-{}-{}".format(packagename, version, release)
print(package)

filenames=hdr['filenames']
filemodes=hdr['filemodes']
md5sums=hdr['filemd5s']
datapath = args.path+"/data"
veritypath = args.path+"/verity"

# Because CentOS 7 ships an ancient version of cpio
os.system("mkdir -p {}".format(datapath))
if args.verbose:
    print("cd {} ; rpm2cpio {} | cpio -id".format(datapath, args.rpm))
os.system("cd {} ; rpm2cpio {} | cpio -id".format(datapath, args.rpm))

sigfilelist, datafilelist = generate_signatures(filenames, filemodes,
                                                datapath, veritypath)

# Remove all non directories installed from the original rpm
#for fn, fm in zip(filenames, filemodes):
#    if not S_ISDIR(fm):
#        os.system("rm {}".format(datapath+fn.decode("utf-8")))

specfn = build_specfile(packagename, version, release, datafilelist,
                        sigfilelist)
os.system("rm -rf {}".format(datapath))

# Build the RPM
buildcmd = "{} --buildroot={} -bb {}".format(args.rpmbuild, veritypath, specfn)
if args.verbose:
    print(buildcmd)
os.system(buildcmd)

os.system("rm {}".format(specfn))
os.system("rmdir {}".format(args.path))
