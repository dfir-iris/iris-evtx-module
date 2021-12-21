#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


import setuptools


setuptools.setup(
     name='iris_evtx',
     version='0.1',
     packages=['iris_evtx'],
     author="Airbus CyberSecurity",
     author_email="ir@cyberactionlab.net",
     description="An interface module for Evtx2Splunk and Iris",
     long_description="An interface module for Evtx2Splunk and Iris",
     long_description_content_type="text/markdown",
     url="https://github.com/",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: LGPLv3",
         "Operating System :: OS Independent",
     ]
 )