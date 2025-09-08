import requests
import json
from log import log_info, log_error, log_debug
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_total_COAs(OPENCTI_URL, OPENCTI_HEADERS):
    """Fetch total number of COAs from OpenCTI."""
    query = """
    query GetCOAsCount {
        coursesOfAction(filters: {
            mode: and,
            filters: [],
            filterGroups: []
        }) {
            pageInfo { globalCount }
        }
    }
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to fetch COAs count: {response.text}")
        log_debug(f"Request payload: {json.dumps({'query': query}, indent=2)}")
        return None
    data = response.json()
    COATotal = data.get("data", {}).get("coursesOfAction", {}).get("pageInfo", {}).get("globalCount", 0)
    return COATotal

def get_sigma_rules(OPENCTI_URL, OPENCTI_HEADERS):
    sigma_rules = []
    page = ""
    page_size = 100
    while True:
        query = f"""
        query getSigmarules {{
            indicators (first: {page_size} after: "{page}" filters: {{
                mode: and,
                filters: [
    	            {{key: "pattern_type", operator: eq, values: ["sigma"]}}
                ],
                filterGroups: []
            }}) {{
                pageInfo {{ globalCount endCursor hasNextPage }}
                edges {{ node {{ name id}}
                }}
            }}
        }}
        """
        response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
        if response.status_code != 200:
            log_error(f"Failed to fetch Sigma rules: {response.text}")
            return None
        data = response.json()
        sigma_rules.extend(edge["node"] for edge in data.get("data", {}).get("indicators", {}).get("edges", []))
        if not data.get("data", {}).get("indicators", {}).get("pageInfo", {}).get("hasNextPage", False):
            break
        page = data.get("data", {}).get("indicators", {}).get("pageInfo", {}).get("endCursor", "")
    return sigma_rules

def get_actor_details(OPENCTI_URL, OPENCTI_HEADERS, actor_name):
    query = f"""
    query GetIntrusionSets {{
        intrusionSets(filters: {{
        mode: or,
        filters: [
            {{key: "name", operator: eq, values: ["{actor_name}"] }},
            {{key: "aliases", operator: eq, values: ["{actor_name}"] }}
        ],
        filterGroups: []
        }}) {{
            edges {{
                node {{
                    id
                    name
                    aliases
                }}
            }}
        }}
    }}
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to fetch actor details: {response.text}")
        return None
    data = response.json()
    if "data" not in data or "intrusionSets" not in data["data"]:
        log_info("No intrusion sets found.")
        return None
    edges = data["data"]["intrusionSets"].get("edges", [])
    intrusion_sets = []
    for edge in edges:
        node = edge.get("node", {})
        actor_id = node.get("id")
        actor_name = node.get("name")
        actor_aliases = node.get("aliases", [])
        intrusion_sets.append((actor_id, actor_name, actor_aliases))        
    return intrusion_sets

def get_actor_campaigns(OPENCTI_URL, OPENCTI_HEADERS, actor_id):
    """fetch system Campaigns"""
    query = f"""
    query GetActorCampaigns {{
        stixCoreRelationships (
        toId: "{actor_id}",
        relationship_type: "attributed-to",
        fromTypes: ["Campaign"]
        ) {{
            pageInfo {{ globalCount }}
            edges {{
                node {{
                    from {{
                        ... on Campaign {{
                        id
                        name
                        }}
                    }}
                }}
            }}
        }}
        }}
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_info(f"Failed to fetch actor campaigns: {response.text}")
        return None
    data = response.json()
    if "data" not in data or "stixCoreRelationships" not in data["data"]:
        log_info(f"No campaigns found for actor {actor_id}.")
        return None
    node_from = data["data"]["stixCoreRelationships"].get("edges", [])
    campaigns = []
    for edge in node_from:
        node = edge.get("node", {})
        from_node = node.get("from", {})
        campaign_name = from_node.get("name")
        campaign_id = from_node.get("id")
        if campaign_name and campaign_id:
            campaigns.append({
                "id": campaign_id,
                "name": campaign_name
            })
    return campaigns

def get_actor_techniques(OPENCTI_URL, OPENCTI_HEADERS, actor_id):
    """Fetch techniques used by a specific actor."""
    query = f"""
    query GetActorTechniques {{
        stixCoreRelationships (
        fromId: "{actor_id}",
        relationship_type: "uses",
        toTypes: ["Attack-Pattern"]
        ) {{
            pageInfo {{ globalCount }}
            edges {{
                node {{
                    to {{
                        ... on AttackPattern {{
                        name
                        x_mitre_id
                        id
                        killChainPhases {{
                            phase_name
                            id
                        }}
                        }}
                    }}
                }}
            }}
        }}
        }}
        """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_info(f"Failed to fetch techniques for actor {actor_id}: {response.text}")
        return None
    data = response.json()
    if "data" not in data or "stixCoreRelationships" not in data["data"]:
        log_info(f"No techniques found for actor {actor_id}.")
        return None
    node_to = data["data"]["stixCoreRelationships"].get("edges", [])
    techniques = []
    for edge in node_to:
        node = edge.get("node", {})
        to_node = node.get("to", {})
        technique_name = to_node.get("name")
        technique_id = to_node.get("x_mitre_id")
        tech_id = to_node.get("id")
        if technique_name and technique_id:
            techniques.append({
                "id": tech_id,
                "name": technique_name,
                "x_mitre_id": technique_id
            })
    return techniques

def get_coas_for_technique(OPENCTI_URL, OPENCTI_HEADERS, technique_id):
    query = f"""
    query GetMitigatingCourses {{
        stixCoreRelationships(
            toId: "{technique_id}"
            relationship_type: "mitigates"
            fromTypes: ["Course-Of-Action"]
        ) {{
        pageInfo {{
            globalCount
            }}
        edges {{
            node {{
                from {{
                    ... on CourseOfAction {{
                            id
                            name
                            }}
                        }}
                    }}
                }}
            }}
        }}
        """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_info(f"Failed to fetch COAs for technique {technique_id}")
        return None
    data = response.json()
    total = data.get("data", {}).get("stixCoreRelationships", {}).get("pageInfo", {}).get("globalCount", 0)
    if "data" not in data or "stixCoreRelationships" not in data["data"]:
        log_info(f"No coas found for {technique_id}.")
        return None
    node_from = data["data"]["stixCoreRelationships"].get("edges", [])
    coas = []
    for edge in node_from:
        node = edge.get("node", {})
        from_node = node.get("from", {})
        coa_id = from_node.get("id")
        coa_name = from_node.get("name")
        if coa_id and coa_name:
            coas.append((coa_id, coa_name))
    return coas, total

def get_sigma_rules_for_technique(OPENCTI_URL, OPENCTI_HEADERS, technique_id):
    query = f"""
    query GetIndicators {{
        stixCoreRelationships(
            toId: "{technique_id}"
            relationship_type: "indicates"
            fromTypes: ["Indicator"]
        ) {{
        pageInfo {{
            globalCount
            }}
        edges {{
            node {{
                from {{
                    ... on Indicator {{
                            id
                            name
                            pattern_type
                            }}
                        }}
                    }}
                }}
            }}
        }}
        """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to fetch COAs for technique {technique_id}")
        return None
    data = response.json()
    if "data" not in data or "stixCoreRelationships" not in data["data"]:
        log_info(f"No coas found for actor {technique_id}.")
        return [], 0  # Return empty list and 0 instead of None
    edges = data["data"]["stixCoreRelationships"].get("edges", [])
    indicators = []
    for node in edges:
        node = node.get("node", {})
        from_node = node.get("from", {})
        indicator_id = from_node.get("id")
        indicator_name = from_node.get("name")
        pattern_type = from_node.get("pattern_type")
        if pattern_type != "sigma":
            log_info(f"Skipping non-Sigma pattern type: {pattern_type}")
            continue
        if indicator_id and indicator_name:
            indicators.append((indicator_id, indicator_name))
    return indicators, len(indicators) 


def get_sigma_techniques(OPENCTI_URL, OPENCTI_HEADERS, sigma_rules):
    results = []
    for rule in sigma_rules:
        log_info(f"Processing Sigma rule: {rule.get('name', 'Unknown Rule')}")
        sigma_name = rule.get('name', 'Unknown Rule')
        sigma_id = rule.get('id', 'Unknown ID')
        query = f"""
        query GetsigmaAPs {{
            stixCoreRelationships(
                fromId: "{sigma_id}"
                relationship_type: "indicates"
                toTypes: ["Attack-Pattern"]
            ) {{ 
                pageInfo {{ globalCount }}  
                edges {{
                    node {{
                        to {{
                            ... on AttackPattern {{
                                id
                                name
                                x_mitre_id
                                killChainPhases {{
                                    phase_name
                                    id
                                }}
                            }}
                        }}
                    }}
                }}
            }}
            }}
        """
        response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
        if response.status_code != 200:
            log_error(f"Failed to fetch Sigma techniques for rule {sigma_name}: {response.text}")
            continue
        data = response.json()
        total = data.get("data", {}).get("stixCoreRelationships", {}).get("pageInfo", {}).get("globalCount", 0)
        if total == 0:
            log_info(f"No techniques found for Sigma rule: {sigma_name}")
            continue
        edges = data.get("data", {}).get("stixCoreRelationships", {}).get("edges", [])
        for edge in edges:
            node = edge.get("node", {})
            to_node = node.get("to", {})
            technique_name = to_node.get("name", 'Unknown Technique')
            tid = to_node.get("x_mitre_id", 'Unknown TID')
            if tid and technique_name:
                results.append({
                    'rule': sigma_name,
                    'tid': tid,
                    'technique': technique_name
                })
    return results



def get_techniques_ids(OPENCTI_URL, OPENCTI_HEADERS, tnumber):
    """Fetch all technique IDs from OpenCTI."""
    query = f"""
    query GetTechniques {{
        attackPatterns (filters: {{
            mode: and,
            filters: [
                {{
                    key: "x_mitre_id",
                    operator: eq,
                    values: ["{tnumber}"]
                }}
            ],
            filterGroups: []
            }} ) {{
            edges {{
                node {{
                    id
                    name
                    x_mitre_id
                }}
            }}
        }}
    }}
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to fetch technique IDs for {tnumber}: {response.text}")
        return None
    data = response.json()
    edges = data.get("data", {}).get("attackPatterns", {}).get("edges", [])
    technique_id = "".join(edge.get("node", {}).get("id", '') for edge in edges)
    if not technique_id:
        log_error(f"No technique found for {tnumber}")
        return None
    return technique_id

def create_coa_relationship(OPENCTI_URL, OPENCTI_HEADERS, coa_id, tid, technique_name):
    """Create a relationship between a COA and a technique."""
    query = f"""
        mutation LinkCOATechnique {{
            stixCoreRelationshipAdd (input: {{
                fromId: "{coa_id}",
                toId: "{tid}",
                relationship_type: "mitigates",
                }}) {{
                    id
                }}
            }}
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to create COA relationship for {technique_name}: {response.text}")
        return
    data = response.json()
    if "data" not in data or "stixCoreRelationshipAdd" not in data["data"]:
        log_error(f"Failed to create COA relationship for {technique_name}: {data}")
        return
    

def update_rules_in_opencti(OPENCTI_URL, OPENCTI_HEADERS, elastic_rules):
    for rule in elastic_rules:
        rule_name = f"[Rule] {rule.get('name', 'Unknown Rule')}"
        log_info(f"Processing Elastic rule: {rule_name}")
        query = f"""
        mutation CreateCOA {{
            courseOfActionAdd (input: {{
                name: "{rule_name}"
            }}) {{
                id
                name
            }}
        }}
        """
        response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
        if response.status_code != 200:
            log_error(f"Failed to fetch existing COA for rule {rule_name}: {response.text}")
            continue
        data = response.json()
        coa_id = data.get("data", {}).get("courseOfActionAdd", {}).get("id")
        if not coa_id:
            log_error(f"Failed to create COA for rule {rule_name}")
            continue
                
        # Now, link the COA to the techniques
        techniques = rule.get('threat', [])
        for technique in techniques:
            technique = technique.get('technique', [])
            for tech in technique:
                tnumber = tech.get('id')
                techid = get_techniques_ids(OPENCTI_URL, OPENCTI_HEADERS, tnumber)
                if not techid:
                    log_error(f"Failed to fetch technique ID for {tnumber}")
                    continue
                create_coa_relationship(OPENCTI_URL, OPENCTI_HEADERS, coa_id, techid , tech.get('name', 'Unknown Technique'))
                
                for subtech in tech.get('subtechnique', []):
                    stid = subtech.get('id')
                    subtech_name = subtech.get('name', 'Unknown Subtechnique')
                    subtech_id = get_techniques_ids(OPENCTI_URL, OPENCTI_HEADERS, stid)
                    if not subtech_id:
                        log_error(f"Failed to fetch subtechnique ID for {stid}")
                        continue
                    create_coa_relationship(OPENCTI_URL, OPENCTI_HEADERS, coa_id, subtech_id, subtech_name)


def delete_coa(OPENCTI_URL, OPENCTI_HEADERS, coa_id):
    query = f"""
    mutation DeleteCOA {{
            courseOfActionEdit (id: "{coa_id}") {{
                delete
            }}
        }}
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to delete COA {coa_id}: {response.text}")
        return
    data = response.json()
    if "data" not in data or "courseOfActionEdit" not in data["data"]:
        log_error(f"Failed to delete COA {coa_id}: {data}")
        return



def remove_disabled_coas(OPENCTI_URL, OPENCTI_HEADERS, enabled_rules):
    """Remove COAs that are no longer enabled in Elastic."""
    COAs = []
    page = ""
    page_size = 100
    while True:
        query = f"""
        query getSigmarules {{
            coursesOfAction (first: {page_size} after: "{page}" filters: {{
                mode: and,
                filters: [
                    {{
                        key: "name",
                        operator: starts_with,
                        values: ["[Rule]"]
                    }}
                ],
                filterGroups: []
            }}) {{
                pageInfo {{globalCount hasNextPage endCursor}}
                edges {{ node {{ name id}}}}
            }}
            }}
        """
        response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
        if response.status_code != 200:
            log_error(f"Failed to fetch COAs: {response.text}")
            return None
        data = response.json()
        COAs.extend(edge["node"] for edge in data.get("data", {}).get("coursesOfAction", {}).get("edges", []))
        if not data.get("data", {}).get("coursesOfAction", {}).get("pageInfo", {}).get("hasNextPage", False):
            break
        page = data.get("data", {}).get("coursesOfAction", {}).get("pageInfo", {}).get("endCursor", "")
    coa_name_to_id = {coa['name']: coa['id'] for coa in COAs}
    enabled_rule_names = {f"[Rule] {rule['name']}" for rule in enabled_rules}
    for coa_name, coa_id in coa_name_to_id.items():
        if coa_name not in enabled_rule_names:
            log_debug(f"Removing disabled COA: {coa_name}")
            delete_coa(OPENCTI_URL, OPENCTI_HEADERS, coa_id)

def create_sigma_relationship(OPENCTI_URL, OPENCTI_HEADERS, rule_id, tid, title):
    """Create a relationship between a Sigma rule and a technique."""
    query = f"""
        mutation LinkSigmaTechnique {{
            stixCoreRelationshipAdd (input: {{
                fromId: "{rule_id}",
                toId: "{tid}",
                relationship_type: "indicates",
                }}) {{
                    id
                }}
            }}
    """
    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": query}, verify=False)
    if response.status_code != 200:
        log_error(f"Failed to create Sigma relationship for {title}: {response.text}")
        return
    data = response.json()
    if "data" not in data or "stixCoreRelationshipAdd" not in data["data"]:
        log_error(f"Failed to create Sigma relationship for {title}: {data}")
        return
    