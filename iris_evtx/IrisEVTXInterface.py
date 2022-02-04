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

import traceback
from pathlib import Path
from celery import chain, current_app

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_evtx.EVTXImportDispatcher import ImportDispatcher
import iris_evtx.IrisEVTXModConfig as interface_conf

import logging

log = logging.getLogger('iris')


class IrisEVTXInterface(IrisModuleInterface):
    """
    Provide the interface between Iris and Evtx2Splunk
    """
    name = "IrisEVTXInterface"
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_pipeline

    def pipeline_handler(self, pipeline_type, pipeline_data):
        """
        Receive data from the main pipeline and dispatch to EVTX2Splunk handler
        :param pipeline_type:
        :param pipeline_data:
        :return:
        """

        if pipeline_type == IrisPipelineTypes.pipeline_type_import:
            #  Call the import chain as task chain
            return self.task_files_import(task_args=pipeline_data)

        elif pipeline_type == IrisPipelineTypes.pipeline_type_update:
            # Call the update chain as task chain
            return self.task_files_import(task_args=pipeline_data)

        else:
            return InterfaceStatus.I2Error('Unrecognized pipeline type')

    def get_tasks_for_registration(self):
        """
        :return: List of tasks to register with Celery
        """
        status = self.wrap_task(self.task_files_import)
        if status.is_success():
            return status(data=[IrisEVTXInterface])
        else:
            return InterfaceStatus.I2Error('No tasks to register')

    def pipeline_files_upload(self, base_path, file_handle, case_customer, case_name, is_update):
        """
        Handle the files for a specific
        :return:
        """

        if base_path and Path(base_path).is_dir:
            file_handle.save(Path(base_path, file_handle.filename))
            return InterfaceStatus.I2Success("Successfully saved file {} to {}".format(file_handle.filename, base_path))

        else:
            return InterfaceStatus.I2Error("Directory {} not found. Can't save file".format(base_path))

    def task_files_import(self, task_args):

        try:
            configuration = self.get_configuration_dict()
            if self._evidence_storage:

                if configuration.is_success():

                    importer = ImportDispatcher(task_self=self,
                                                task_args=task_args,
                                                evidence_storage=self._evidence_storage,
                                                configuration=configuration.get_data()
                                                )

                    return importer.import_files()

                else:
                    log.error(configuration.get_message())
                    logs = [configuration.get_message()]
            else:
                log.error('Evidence storage not available')
                logs = ['Evidence storage not available']

            return InterfaceStatus.iit_report_task_failure(
                user=task_args['user'],
                initial=0,
                case_name=task_args['case_name'],
                logs=logs
            )

        except Exception as e:
            traceback.print_exc()
            return InterfaceStatus.iit_report_task_failure(
                user=task_args['user'],
                initial=0,
                case_name=task_args['case_name'],
                logs=[traceback.print_exc()]
            )
