import gk_nessus.downloader
import gk_nessus.sqlconnector


# Testing route /plugins
def test_get_all_plugins():
    # FIXME: here I should simulate regular request
    # first we need to clear the DB.
    # then we need to load the mock json
    # after that we need to load the entries to the DB
    # finally we trigger the "get_all_plugins" function and expect to get the predefined result
    sql_con = gk_nessus.sqlconnector.NessusSqlConnector()
    result = [result.serialize for result in sql_con.get_all_plugins({}).all()]
    assert (result == [
        {
            'PluginID': 1,
            'modified': '1970-01-01T00:00:00',
            'published': '1970-01-01T00:00:00',
            'score': -0.1,
            'title': 'Plugin 1 title',
            'cvelist': [{'id': 44, 'str_id': 'ID #1', 'cve': 'CVE-2000-0001'}]
        },
        {
            'PluginID': 2,
            'modified': '1970-01-02T00:00:00',
            'published': '1970-01-02T00:00:00',
            'score': -0.2,
            'title': 'Plugin 2 title',
            'cvelist': [{'id': 45, 'str_id': 'ID #2', 'cve': 'CVE-2000-0002'}]
        },
        {
            'PluginID': 3,
            'modified': '1970-01-03T00:00:00',
            'published': '1970-01-03T00:00:00',
            'score': -0.3,
            'title': 'Plugin 3 title',
            'cvelist': [
                {'id': 46, 'str_id': 'ID #3', 'cve': 'CVE-2000-0001'},
                {'id': 47, 'str_id': 'ID #3', 'cve': 'CVE-2000-0002'}
            ]
        },
        {
            'PluginID': 4,
            'modified': '1970-01-04T00:00:00',
            'published': '1970-01-04T00:00:00',
            'score': -0.4,
            'title': 'Plugin 4 title',
            'cvelist': []
        }
    ])
