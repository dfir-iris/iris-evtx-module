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

module_name = "Evtx2Splunk"
module_description = "Provides handling of Windows EVTX files and ingest them into Splunk"
interface_version = 1.1
module_version = 1.1
pipeline_support = True
pipeline_info = {
    "pipeline_internal_name": "evtx_pipeline",
    "pipeline_human_name": "EVTX Pipeline",
    "pipeline_args": [
        ['index_evtx', 'required'],
        ['hostname_evtx', 'optional']
    ],
    "pipeline_update_support": True,
    "pipeline_import_support": True
}
module_configuration = [
    {
        "param_name": "splunk_http_proxy",
        "param_human_name": "Splunk HTTP Proxy",
        "param_description": "HTTP Proxy parameter",
        "default": None,
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "splunk_https_proxy",
        "param_human_name": "Splunk HTTPS Proxy",
        "param_description": "HTTPS Proxy parameter",
        "default": None,
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "evtxdump_config_file",
        "param_human_name": "EVTXDump Configuration file",
        "param_description": "Full path of the EVTXDump configuration file in order to find the necessary binaries",
        "default": None,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "evtx_splunk_url",
        "param_human_name": "URL Splunk",
        "param_description": "Domain or IP where splunk is running",
        "default": None,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "evtx_splunk_user",
        "param_human_name": "Splunk user",
        "param_description": "Splunk user",
        "default": None,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "evtx_splunk_pass",
        "param_human_name": "Splunk password",
        "param_description": "Splunk user password",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "evtx_splunk_mport",
        "param_human_name": "Splunk Management Port",
        "param_description": "Splunk Management Port Number",
        "default": 8089,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "evtx_splunk_use_ssl",
        "param_human_name": "Splunk Use SSL",
        "param_description": "Contact Splunk over SSL",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "evtx_splunk_verify_ssl",
        "param_human_name": "Splunk Verify SSL",
        "param_description": "Splunk Verify SSL",
        "default": False,
        "mandatory": True,
        "type": "bool"
    }
]