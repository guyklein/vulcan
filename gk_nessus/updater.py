import io
import json
import logging

import sqlalchemy
import zipfile

from gk_nessus import downloader, consts

LOG = logging.getLogger(__name__)


class NessusUpdater:
    def __init__(self, ns_sqlcon):
        super(NessusUpdater, self).__init__()
        self._ns_sqlcon = ns_sqlcon

    def run(self):
        # TODO: Should run indefinitely
        stream = self._get_nessus_file()
        self._update_db(stream)

    def _update_db(self, stream):
        zipped_file = zipfile.ZipFile(stream)
        if bad_file := zipped_file.testzip():
            LOG.error(f'corrupt file in zip: {bad_file}')
            exit(consts.ERROR.CORRUPT_ZIP)
        file_names = zipped_file.namelist()
        if not len(file_names):
            LOG.error('empty zip file')
            exit(consts.ERROR.EMPTY_ZIP)
        file_to_extract = file_names[0]
        json_content = json.loads(zipped_file.read(file_to_extract))
        self._process_json(json_content)

    @staticmethod
    def _get_nessus_file(online=True, save=False):
        """
        Get the nessus zipped file
        :param online: whether to actually retrieve the file from the size or use the offline mock
        :param save: whether to save the retrieved file locally (only used with 'online' option
        :return: the byte stream of the nessus DB file
        """
        ns_download = downloader.NessusDownloader()
        if online:
            if save:
                file_path, file_data = ns_download.download()
            else:
                file_name, file_data = ns_download.open()
            # either download (with local saving) or just "open" (in memory) - we should check the file_data
            if file_data is None:
                LOG.error(f'Failed to download file from {ns_download.url}')
                exit(consts.ERROR.DOWNLOAD_ERROR)
            stream = io.BytesIO(file_data)
        else:
            # "offline" - use a mock file for testing
            stream = io.open("../app/mock/nessus.json.zip", "rb")

        return stream

    def _process_json(self, json_content):
        """
        process the given json and update the DB
        :param json_content:
        :return:
        """
        if self._ns_sqlcon.connection is None:
            LOG.error(f'failed to open connection to DB')
            return
        entries = [entry for entry in json_content]
        LOG.info('started updating DB')
        num_of_entries = len(entries)
        for x in range(num_of_entries):
            entry = entries[x]
            try:
                self._ns_sqlcon.update_plugins_table(entry['_source'])
            except AttributeError:
                LOG.exception(f'malformed entry: {entry}')
            if x % 2000 != 0:
                continue
            LOG.info(f'Updated {x} records')

        LOG.info(f'Updated {num_of_entries} records')
        try:
            LOG.info('Commit started')
            self._ns_sqlcon.session.commit()
            LOG.info('Commit finished')
        except sqlalchemy.exc.IntegrityError:
            LOG.exception('failed committing updates to DB')
            self._ns_sqlcon.session.rollback()

        LOG.info('Finished updating DB')
