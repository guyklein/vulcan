import datetime
import logging
import sqlalchemy as db
import time

import gk_nessus.base
import gk_nessus.cve
import gk_nessus.plugin

LOG = logging.getLogger('db')


class NessusSqlConnector(object):
    def __init__(
            self,
            connection_string=gk_nessus.base.connection_string
    ):
        self._connection = None

        # try:
        self._connection_string = connection_string
        self._engine = db.create_engine(self._connection_string)
        gk_nessus.base.Session.configure(bind=self._engine)
        self._session = gk_nessus.base.Session()
        sleep_time=15
        for x in range(5):
            try:
                self._connection = self._engine.connect()
            except db.exc.OperationalError:
                if x == 5:
                    LOG.error('failed to connect to DB. Giving up...')
                    return
                else:
                    LOG.error(f'Attempt #{x+1} to connect to DB failed, trying again in {sleep_time} seconds')
                    time.sleep(sleep_time)
        gk_nessus.base.Base.metadata.create_all(self._engine)

        LOG.info(f'Successfully connected to {self._connection_string}')

    @property
    def connection(self):
        return self._connection

    @property
    def session(self):
        return self._session

    def extract_data(self, entry):
        """
        Utility function to read relevant values from object
        :param entry: dictionary transformed JSON object
        :return: array of extracted parameters
        """
        try:
            source = entry
            score_value = source['enchantments']['score']['value']
            cve_list = []
            for cve in source['cvelist']:
                cve_list.append(gk_nessus.cve.CVE(
                    str_id=source['id'],
                    cve=cve
                ))
            plugin = gk_nessus.plugin.Plugin(
                id=int(source['pluginID']),
                modified=datetime.datetime.fromisoformat(source['modified']),
                published=datetime.datetime.fromisoformat(source['published']),
                score_value=float(score_value),
                title=source['title'],
                cve_list=cve_list
            )
            LOG.debug(f'got plugin: {plugin.id}')
            return plugin, cve_list
        except (AttributeError, KeyError):
            LOG.exception(f'failed to read entry data from json :{entry}')
            return None, []

    def update_plugins_table(self, entry):
        """
        Updates the DB with the given entry (plugin from JSON)
        :param entry: dictionary transformed JSON object
        """
        plugin, cve_list = self.extract_data(entry)
        if plugin is None:
            return
        # if the DB already contains such an entry and the modified date is the same - no need to update.
        # First - search for the entry in the DB
        existing_plugin = self.get_plugin_data(plugin.id).first()
        try:
            # a plugin the the same id already exists in the DB
            if existing_plugin is not None:
                if existing_plugin.modified < plugin.modified:
                    # the existing plugin id is out-of-date - delete it (with matching CVEs)
                    self._session.delete(existing_plugin)
                else:
                    # existing plugin is up to date, nothing to do.
                    return
            # Add the CVEs of that plugin
            for cve in cve_list:
                existing_cve = self._session.query(
                    gk_nessus.cve.CVE).filter(gk_nessus.cve.CVE.id == cve.id).first()
                if existing_cve is None:
                    self._session.add(cve)

            # add the new plugin
            self._session.add(plugin)
        except (db.exc.IntegrityError, db.exc.InvalidRequestError):
            # FIXME: verify which exceptions can be thrown here
            LOG.exception(f'failed to update entry ${entry} in the DB')

    def get_all_plugins(self, config):
        """
        Query the DB for all listed plugins
        :param config: optionally ordering by PluginID, published, score
        :return: all listed plugins, ordered by given params.
        """
        sort_order_list = []
        if 'PluginID' in config:
            if config['PluginID'][0] == 'desc':
                sort_order_list.append(gk_nessus.plugin.Plugin.id.desc())
            else:
                sort_order_list.append(gk_nessus.plugin.Plugin.id.asc())
        if 'published' in config:
            if config['published'][0] == 'desc':
                sort_order_list.append(gk_nessus.plugin.Plugin.published.desc())
            else:
                sort_order_list.append(gk_nessus.plugin.Plugin.published.asc())
        if 'score' in config:
            if config['score'][0] == 'desc':
                sort_order_list.append(gk_nessus.plugin.Plugin.score_value.desc())
            else:
                sort_order_list.append(gk_nessus.plugin.Plugin.score_value.asc())

        return self._session.query(gk_nessus.plugin.Plugin).order_by(*sort_order_list)

    def get_plugin_data(self, plugin_id):
        """
        Query DB for specific plugin_id
        :param plugin_id: plugin id to by which to get the data
        :return: all data of a specific plugin
        """
        return self._session.query(gk_nessus.plugin.Plugin).filter(
            gk_nessus.plugin.Plugin.id == plugin_id)

    def get_plugins_by_cve_ids(self, cve_ids):
        """
        Get plugins affected by given CVE based on cve_id
        :param cve_ids: list of cve_ids by which to get the data
        :return: all affected plugins
        """
        return self._session.query(gk_nessus.plugin.Plugin).join(
            gk_nessus.cve.CVE, gk_nessus.plugin.Plugin.cve_list).filter(gk_nessus.cve.CVE.cve.in_(cve_ids))

    def clear_db(self):

        LOG.info('Clearing database')
        gk_nessus.base.Base.metadata.drop_all(bind=self._engine)
        self._session.commit()

