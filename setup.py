#!/usr/bin/python
# -*- encoding: utf-8 -*-
# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import setuptools

setuptools.setup(
    name='aiclib',
    version='0.87',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2.6', ],
    install_requires=[
        'urllib3',
    ],
    packages=['aiclib'],
    keywords='aiclib nvp',
    author='Ozone Networking (Team Johnnie)',
    author_email='justin.hammond@rackspace.com',
    license='Apache Software License',
    description='A declarative system to consume the NVP api.',
    long_description=open('README.rst').read(),
    url='https://github.com/rackerlabs/aiclib',
    zip_safe=False,
)
