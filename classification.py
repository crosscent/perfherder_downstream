"""
FILE: classify.py
DESCRIPTION: Automatically classify AlertSummary by Upstream and Downstream
"""

import httplib
import json
import urllib

treeherder_url = "treeherder.mozilla.org"
hg_url = "hg.mozilla.org"
request_count = 0

def treeherder_request(endpoint):
    """Return a dictioanry of the JSON returned from an endpoint"""
    conn = httplib.HTTPSConnection(treeherder_url)
    headers = {"User-Agent": "Automatic downstream classification script"}
    conn.request("GET", endpoint, {}, headers)

    global request_count
    request_count += 1
    print "{}. {}".format(request_count, endpoint)

    return json.loads(conn.getresponse().read())

def hg_request(endpoint):
    """Return a dictionary of the JSON returned from an endpoint"""
    conn = httplib.HTTPSConnection(hg_url)
    headers = {"User-Agent": "Automatic downstream classification script. If I'm overloading the server, please find royc on #treeherder"}
    conn.request("GET", endpoint, {}, headers)

    global request_count
    request_count += 1
    print "{}. {}".format(request_count, endpoint)

    return json.loads(conn.getresponse().read())

def get_all_alertsummaries(url="/api/performance/alertsummary/", pages=10):
    """Returns a list of AlertSummary
    
    The production server of Perfherder still uses cursor view, and will be
    switched to pagination, but the same idea should still work, since ``next``
    will be provided.
    """
    if pages == 0:
        return []

    result = treeherder_request(url)
    next_page = result['next'].replace("https://treeherder.mozilla.org", "")
    alertsummary = result['results']
    alertsummary.extend(get_all_alertsummaries(next_page, pages-1))
    return alertsummary

def get_alertsummary_resultset_list(alertsummary):
    """Returns a list of tuples ("repo", "result_set_id")
    """
    return [(alertsummary["repository"], i) for i in range(alertsummary["result_set_id"], alertsummary["prev_result_set_id"], -1)]

def get_resultset_map(repository, resultset_id):
    """Returns a dictioanry mapping the resultset
    
    Args:
        repository: the repository in question
        resultset: the resultset in question
    """
    result = treeherder_request("/api/project/{0}/resultset/{1}/".format(repository,
                                                                         resultset_id))
    is_merge = False
    if "merge" in result["comments"].lower():
        is_merge = True

    i = 0
    while(is_merge != False and i < len(result["revisions"])):
        if "merge" in result["revisions"][i]["comments"].lower():
            is_merge = True
        i += 1
    return {"revisions": result["revisions"], "is_merge": is_merge, "changeset": result["revision"]}

def get_all_revision_map(alertsummaries):
    """Returns a dictionary mapping repository to resultset to revisions
    
    Args:
        alertsummaries: a list of AlertSummaries
    """
    empty_set = {"is_merge": False, "revisions": []}
    repo_mapping = {}
    for alertsummary in alertsummaries:
        repo = alertsummary["repository"]
        if repo not in repo_mapping:
            repo_mapping[repo] = {}
        for repo, result_set_id in get_alertsummary_resultset_list(alertsummary):
            if result_set_id not in repo_mapping[repo]:
                try:
                    repo_mapping[repo][result_set_id] = get_resultset_map(repo, result_set_id)
                except ValueError:
                    repo_mapping[repo][result_set_id] = empty_set
    return repo_mapping
    
def add_related_alerts(alertsummary):
    """Add related alerts to list of alerts"""
    alertsummary["alerts"].extend(alertsummary["related_alerts"])
    return alertsummary

def is_downstream_alertsummary(alertsummary, revision_map):
    """Returns a Boolean of whether the alertsummary is upstream"""
    for repo, resultset_id in get_alertsummary_resultset_list(alertsummary):
        if revision_map[repo][resultset_id]["is_merge"]:
            return True
    return False

def get_downstream_alertsummaries(alertsummaries, revision_map):
    """Return a list of AlertSummaries that have been identified as downstream"""
    return filter(lambda summary: is_downstream_alertsummary(summary, revision_map), alertsummaries)

def get_upstream_alertsummaries(alertsummaries, downstreams):
    """Return a list of AlertSummaries that have been identified as upstream"""
    downstream_ids = [alert['id'] for alert in downstreams]
    return [add_related_alerts(summary) for summary in alertsummaries if (summary['id'] not in downstream_ids and summary["status"] != 2)]

def get_single_upstream_revisions(repo, resultset_id, revision_map):
    """Return a list of revision ids of a single upstream
    """
    changeset = revision_map[repo][resultset_id]["changeset"]
    result = hg_request("/integration/{}/json-pushes/?full=1&version=2&changeset={}".format(repo, changeset))
    revisions = []
    for push in result["pushes"].keys():
        for changeset in result["pushes"][push]["changesets"]:
            revisions.append(changeset["node"])
    return revisions

def get_downstream_revisions(alertsummaries, revision_map):
    revisions = {}
    for alertsummary in alertsummaries:
        if alertsummary["id"] not in revisions.keys():
            revisions[alertsummary["id"]] = []
        for repo, resultset_id in get_alertsummary_resultset_list(alertsummary):
            revisions[alertsummary["id"]].extend(get_single_upstream_revisions(repo, resultset_id, revision_map))
    return revisions

def get_upstream_revisions(alertsummaries, revision_map):
    revisions = {}
    for alertsummary in alertsummaries:
        for repo, resultset_id in get_alertsummary_resultset_list(alertsummary):
            for revision in revision_map[repo][resultset_id]["revisions"]:
                if revision["revision"] not in revisions.keys():
                    revisions[revision["revision"]] = []
                revisions[revision["revision"]].append(alertsummary["id"])
    return revisions

def is_possible_upstream(downstream, upstream):
    """Return a bool of whether the summary given could be upstream of the
    given downstream
    
    Args:
        downstream - A downstream AlertSummary
        upstream - A possible upstream AlertSummary
    """
    downstream_signatures = [alert["series_signature"]["signature_hash"] for alert in downstream['alerts']]
    upstream_signatures = [alert["series_signature"]["signature_hash"] for alert in upstream["alerts"]]

    return len(set(downstream_signatures).intersection(upstream_signatures)) > 0

def identify_possible_upstreams(downstream, summaries):
    """Return a list of AlertSummary that could be upstream
    
    Args:
        downstream - an AlertSummary that has been identified as downstream
        summaries - a list of AlertSummary to filter from
    """
    return filter(lambda summary: is_possible_upstream(downstream, summary), summaries)

def identify_true_upstream(downstream, upstreams, downstream_revisions, upstream_revision_map):
    frequency_map = {}
    for revision in downstream_revisions[downstream["id"]]:
        if revision not in upstream_revision_map.keys():
            continue
        for upstream in upstream_revision_map[revision]:
            if upstream not in frequency_map.keys():
                frequency_map[upstream] = 0
            frequency_map[upstream] += 1
    return frequency_map

if __name__ == "__main__":
    all_alertsummaries = get_all_alertsummaries()
    revision_map = get_all_revision_map(all_alertsummaries)
    downstreams = get_downstream_alertsummaries(all_alertsummaries, revision_map)
    upstreams = get_upstream_alertsummaries(all_alertsummaries, downstreams)
    upstream_revisions = get_upstream_revisions(upstreams, revision_map)
    downstream_revisions = get_downstream_revisions(downstreams, revision_map)
    for downstream in downstreams:
        possible_upstream = identify_possible_upstreams(downstream, upstreams)
        frequency_map = identify_true_upstream(downstream,
                                               possible_upstream,
                                               downstream_revisions,
                                               upstream_revisions)
        print "Downstream: {}".format(downstream["id"])
        print "Possible Upstreams: {}".format([upstream["id"] for upstream in possible_upstream])
        print "Narrowed upstreams: {}".format([upstream["id"] for upstream in possible_upstream if upstream["id"] in frequency_map.keys()])
        print "\n"
