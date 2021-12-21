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

# IMPORTS ------------------------------------------------
import hashlib
import logging
import os
import shutil
import tempfile
from pathlib import Path
import time
from multiprocessing import cpu_count
from datetime import datetime
from pyunpack import Archive

from evtx2splunk.Evtx2Splunk import Evtx2Splunk

import iris_interface.IrisInterfaceStatus as InterfaceStatus

log = logging.getLogger('iris')


# CONTENT ------------------------------------------------
def decompress_7z(filename, output_dir):
    """
    Decompress a 7z file in specified output directory
    :param filename: Filename to decompress
    :param output_dir: Target output dir
    :return: True if uncompress
    """
    try:
        a = Archive(filename=filename)
        a.extractall(directory=output_dir, auto_create_dir=True)

    except Exception as e:
        log.warning(e)
        return False

    return True


class ImportDispatcher(object):
    """
    Allows to dispatch files to each related importers
    """

    def __init__(self, task_self, task_args=None, evidence_storage=None, configuration=None):
        self.task = task_self
        self.evidence_storage = evidence_storage
        self.configuration = configuration
        self.message_queue = []
        handler = InterfaceStatus.QueuingHandler(message_queue=self.message_queue,
                                                 level=logging.INFO,
                                                 celery_task=task_self)
        log.addHandler(handler)

        self.index = task_args['pipeline_args']['index_evtx']
        self.user = task_args['user']
        self.user_id = task_args['user_id']
        self.case_name = task_args['case_name']
        self.path = Path(task_args['path'])
        self.case_id = task_args['case_id']
        self.is_update = task_args['is_update']
        self._hostname = task_args['pipeline_args']['hostname_evtx']

    def _ret_task_success(self):
        """
        Return a task compatible success object to be passed to the next task
        :return:
        """
        return InterfaceStatus.iit_report_task_success(
            user=self.user,
            initial=self.task.request.id,
            case_name=self.case_name,
            logs=list(self.message_queue),
            data={}
        )

    def _ret_task_failure(self):
        """
        Return a task compatible failure object to be passed to the next task
        :return:
        """
        return InterfaceStatus.iit_report_task_failure(
            user=self.user,
            initial=self.task.request.id,
            case_name=self.case_name,
            logs=list(self.message_queue),
            data={}
        )

    def import_files(self):
        """
        Check every uploaded files and dispatch to handlers
        :return:
        """

        log.info("Received new evtx import signal for {}".format(self.case_name))

        temp_zippath = tempfile.TemporaryDirectory()
        shutil.move(str(self.path), temp_zippath.name)
        module_name = self.path.name
        self.path = Path(temp_zippath.name, module_name)

        import_list = self._create_import_list(path=self.path)

        ret = self._ret_task_success()
        if import_list:

            for data_type in import_list:

                ret_t = self.inner_import_files(import_list[data_type], data_type)

                # Merge the result with the current caller
                ret.merge_task_results(ret_t, is_update=self.is_update)

        else:

            log.error("Import list was empty. Please check previous errors.")
            log.error("Either internal error, either the files could not be uploaded successfully.")
            log.error("Nothing to import")
            ret = self._ret_task_failure()

        return ret

    def _merge_task_results(self, base_ret, new_ret, type):
        """
        Merge the result of multiple tasks
        :param base_ret: Task return to merge
        :return:
        """
        # Set the overall task success at false if any of the task failed
        base_ret['success'] = new_ret['success'] and base_ret['success']

        # Concatenate the tasks logs to display everything at the end
        base_ret['logs'] += new_ret['logs']

        base_ret['data']['is_update'] = self.is_update

        return base_ret

    def _create_import_list(self, path=None):
        """
        Create the list for every files
        :param path: Path containing the files to check
        :return: A json with types and files
        """
        import_list = {
        }

        log.info("Checking input files")
        log.info("Path is {}".format(path))

        if path.is_dir():
            for entry in path.iterdir():

                if not entry.is_dir():
                    # Compute file hash
                    # Compute SHA256 of file
                    sha256_hash = hashlib.sha256()

                    with open(entry, "rb") as f:
                        # Read and update hash string value in blocks of 4K
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                        fhash = sha256_hash.hexdigest()

                        file_registered = self.evidence_storage.is_evidence_registered(sha256=fhash,
                                                                                       case_id=self.case_id)

                        if not file_registered:

                            is_valid = True
                            # EVTX are Windows event files. EVTX_DATA is found in ORC results
                            if entry.suffix == ".evtx" or entry.suffix == ".evtx_data":

                                if "evtx" not in import_list:
                                    import_list["evtx"] = [entry]
                                else:
                                    import_list["evtx"].append(entry)

                            elif entry.suffix == ".zip" or entry.suffix == ".7z":

                                if "archive" not in import_list:
                                    import_list["archive"] = [entry]
                                else:
                                    import_list["archive"].append(entry)

                            else:
                                is_valid = False

                            if not is_valid:
                                try:
                                    entry.unlink()
                                    log.debug(entry)
                                except Exception:
                                    pass
                                log.info("File has been deleted from the server")

                        else:
                            entry.unlink()
                            log.warning("{} was already imported".format(entry))

            # log.info("Detected {} valid files".format(len(import_list)))
            return import_list

        else:
            log.error("Internal error. Provided path is not a path")
            return None

    def inner_import_files(self, import_list: list, files_type):
        """
        Method to be called as an entry point to create imports KBHs
        :param files_type:
        :param import_list:
        :return: True if imported, false if not + list of errors
        """

        log.info("New imports for {} on behalf of {}".format(self.case_name, self.user))
        log.info("{} files of type {} to import into {}".format(len(import_list), files_type, self.index))

        log.info("Starting processing of files")

        in_path = import_list[0].parent
        # Temporary files are placed in the same directory, not in tmp as there is a
        # a risk over overloading tmp dir depending on the partitioning
        out_path = in_path.parent / "out"

        if files_type == "archive":
            for archive in import_list:
                zippath = Path(out_path) / archive.name.replace(archive.suffix, '')
                zippath.mkdir(parents=True)
                decompress_7z(archive, zippath)

            in_path_evtx = out_path
        elif files_type == "evtx":
            in_path_evtx = in_path
        else:
            log.error("Unexpected file type, aborting...")
            return self._ret_task_failure()

        start_time = time.time()

        e2s = Evtx2Splunk()
        # We could just pass on self.configuration, but we prefer to format the dict in such way that
        # field names in evtx2splunk will not depend on IrisEVTXModule
        proxies = {
            "http": self.configuration.get('splunk_http_proxy'),
            "https": self.configuration.get('splunk_https_proxy')
        }
        e2s_config = {
            "evtxdump_config_file": self.configuration.get("evtxdump_config_file"),
            "splunk_url": self.configuration.get("evtx_splunk_url"),
            "splunk_user": self.configuration.get("evtx_splunk_user"),
            "splunk_pass": self.configuration.get("evtx_splunk_pass"),
            "splunk_hec_name": self.configuration.get("evtx_splunk_hecname"),
            "splunk_mport": self.configuration.get("evtx_splunk_mport"),
            "splunk_ssl": self.configuration.get("evtx_splunk_use_ssl"),
            "splunk_ssl_verify": self.configuration.get("evtx_splunk_verify_ssl"),
        }
        if e2s.configure(config=e2s_config,
                         index=self.index,
                         nb_ingestors=cpu_count(),
                         testing=False,
                         no_resolve=True,
                         proxies=proxies
                         ):
            ret_t = e2s.ingest(input_files=in_path_evtx, keep_cache=False, use_cache=False)
        else:
            ret_t = False

        end_time = time.time()

        log.info("Finished in {time}".format(time=end_time - start_time))

        if ret_t is False:
            return self._ret_task_failure()

        # Clean the temporary folder
        if files_type == "archive":
            shutil.rmtree(out_path, ignore_errors=True)

        for file in import_list:
            # Compute SHA256 of file
            sha256_hash = hashlib.sha256()

            # Get file size
            fsize = os.path.getsize(file)

            with open(file, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                fhash = sha256_hash.hexdigest()

                file_registered = self.evidence_storage.is_evidence_registered(sha256=fhash, case_id=self.case_id)

                if not file_registered:
                    self.evidence_storage.add_evidence(
                        filename=file.name,
                        sha256=fhash,
                        date_added=datetime.now(),
                        case_id=self.case_id,
                        user_id=self.user_id,
                        size=fsize,
                        description="[Auto] EVTX file named {}".format(file.name)
                    )

        return self._ret_task_success()
