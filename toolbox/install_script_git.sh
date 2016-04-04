#!/bin/bash
set -x
venv="nephoria_venv"
neph_branch="oldboto"
adminapi_branch="master"
yum install --disablerepo=euca-build-deps -y python-devel gcc git python-setuptools python-virtualenv
rpm -qa | grep virtualenv # verify it was installed successfully above
yum repolist # check repos
if [ ! -d adminapi ]; then
    git clone https://github.com/nephomaniac/adminapi.git
fi
if [ ! -d nephoria ]; then
    git clone https://github.com/nephomaniac/nephoria.git
fi
if [ "x$venv" != "x" ]; then
    if [ ! -d $venv ]; then
        /usr/bin/virtualenv $venv
    fi
    source $venv/bin/activate
fi
cd adminapi
git fetch
git checkout $adminapi_branch
git pull origin $adminapi_branch
python setup.py install
cd -
cd nephoria
git fetch
git checkout $neph_branch
git pull origin $neph_branch
python setup.py install
cd -