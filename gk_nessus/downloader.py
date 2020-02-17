import datetime
import logging
import tempfile
import time
import re
import urllib.error
import urllib.request

LOG = logging.getLogger(__name__)


class NessusDownloader(object):

    def __init__(self,
                 url='https://vulners.com/api/v3/archive/collection/?type=nessus',
                 max_retries=5,
                 api_key='DGJQ30KZPRZGAY8DHW6DAFF9LOQ1THRQ6ADJYZ7I470Q5XF0L2LN0GO7NYT8INZD'
                 ):
        """
        Initialize a new downloader instance
        :param url: the url to download from
        :type url: string

        # :param dest_dir: the directory in which the downloaded file will be stored
        #                  supply None to create a temporary directory
        # :type dest_dir: string

        :param max_retries: the maximal number of attempts to download the file from the url
        :type max_retries: number
        """
        self._url = url
        self._max_retries = max_retries
        self._api_key = api_key

        assert (max_retries > 0)
        assert (url is not None)

    @property
    def url(self):
        return self._url

    def open(self):
        """
        Single attempt to download the file
        :return: the downloaded file name and file data
        """
        return self._download()

    def _download(self):
        """
        Single attempt to download the file
        :return: file name of the downloaded file and the file data or None on failure
        """
        headers = {
            'User-Agent': (
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2)'
                'AppleWebKit/537.36 (KHTML, like Gecko)'
                'Chrome/79.0.3945.130 Safari/537.36'
            ),
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        url = f'{self._url}&apiKey={self._api_key}'
        request = urllib.request.Request(url, headers=headers)
        try:
            LOG.info(f'opening {url}')
            with urllib.request.urlopen(request) as response:
                code = response.getcode()
                if code < 200 or code >= 300:
                    LOG.warning(f'failed to open {url}! response code is {code}')
                    return None
                info = response.info()
                if info.get('Content-Type') != 'application/x-zip-compressed':
                    LOG.warning('content type (json received?)')
                    return None
                disposition = info.get('Content-Disposition')
                m = re.search('filename=(.*)', disposition)
                start_time = datetime.datetime.now()
                LOG.info(f'started getting data from {url}')
                file_data = response.read()
                end_time = datetime.datetime.now()
                time_span = str(end_time - start_time)
                LOG.info(f'finished getting data - operations took {time_span}')
                return m.group(0), file_data
        except urllib.error.URLError:
            LOG.exception(f'Failed to fetch {self._url}')
            return None, None

    def download(self, dest_dir=None):
        """
        Attempts to downloads the file from the predefined url
        :return: path to the downloaded file or None on failure
        """
        _dest_dir = dest_dir
        if _dest_dir is None:
            # create a temp dir and set it to self._dest_dir
            _dest_dir = tempfile.mkdtemp()

        for attempt in range(self._max_retries):
            file_name, file_data = self._download()
            if path := _dest_dir + '/' + file_name:
                return path, file_data
            LOG.debug(
                f'Attempt #{attempt} to download the file failed,'
                f' trying again in {attempt * 2} seconds'
            )
            time.sleep(attempt * 2)

        LOG.debug(f'{self._max_retries} tries exceeded, giving up')
        return None, None
