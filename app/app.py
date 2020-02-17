from bottle import get, request, response, run, abort
import json
import logging

from gk_nessus import sqlconnector, updater

LOG = logging.getLogger(__name__)

ns_sqlcon = sqlconnector.NessusSqlConnector()


def main():
    updater.NessusUpdater(ns_sqlcon).run()
    run(host='localhost', port=5000)


@get('/plugins')
def get_all_plugins():
    """
    Get all the plugins from the DB, order them by the query params and
    return the result as an HTML table
    :return: HTML table with all listed plugins, ordered by query params
    """
    params = request.query.decode()
    # FIXME: send correct config (sort order)
    try:
        results = ns_sqlcon.get_all_plugins(config=params.dict)
        length = results.count()
        LOG.debug(
            f'Request to get all the plugins was submitted. Result len is {length}'
        )
        response.content_type = 'application/json'
        return json.dumps([r.serialize() for r in results.all()])
    except Exception:
        # FIXME: use specific exceptions
        response.status_code = 500


@get('/plugin/<plugin_id>')
def get_plugin_by_plugin_id(plugin_id):
    try:
        num_id = int(plugin_id)
    except ValueError:
        abort(400, 'Invalid ID')
        return
    results = ns_sqlcon.get_plugin_data(num_id)
    length = results.count()
    LOG.debug(
        f'Request to get {plugin_id} was submitted. Result len is {length}'
    )
    response.content_type = 'application/json'
    response.body = json.dumps([r.serialize for r in results.all()])
    return response


@get('/plugin/getByCVE')
def get_plugins_by_cve_ids():
    params = request.query.decode()
    cve_ids = params.dict.get('cve')
    results = ns_sqlcon.get_plugins_by_cve_ids(cve_ids)
    length = results.count()
    LOG.debug(
        f'Request to get {cve_ids} was submitted. Result len is {length}'
    )
    response.content_type = 'application/json'
    response.body = json.dumps([r.serialize for r in results.all()])
    # FIXME: add exceptions handling
    return response


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    main()
