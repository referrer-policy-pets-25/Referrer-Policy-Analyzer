import ast
from tld import get_fld
import ipaddress
import pandas as pd
from urllib.parse import urlparse, urlunparse
import validators
import helpers.LeakDetector as LeakDetector 

RP_VALUES = [
    "no-referrer",
    'same-origin',
    'origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'origin-when-cross-origin',
    'no-referrer-when-downgrade',
    'unsafe-url'
]

BAD_RP_VALUES = [
    'unsafe-url',
    'no-referrer-when-downgrade',
    'origin-when-cross-origin'
]

GOOD_RP_VALUES = [
    'no-referrer',
    'same-origin',
    'origin'
]

DEFAULT_RP_VALUES = "strict-origin-when-cross-origin"

def get_ps1_or_host(url):
    """
    Extracts the public suffix + 1 (PS+1) or hostname from a given URL.

    If the URL does not start with "http", it prepends "http://" to the URL.
    It first attempts to extract the PS+1 using the `get_fld` function.
    If that fails, it tries to extract the hostname and checks if it is a valid IP address.
    If the hostname is a valid IP address, it returns the IP address.
    If all attempts fail, it returns an empty string.

    Args:
        url (str): The URL from which to extract the PS+1 or hostname.

    Returns:
        str: The extracted PS+1, hostname, or IP address. Returns an empty string if extraction fails.
    """
    if not url.startswith("http"):
        url = 'http://' + url

    try:
        return get_fld(url, fail_silently=False)
    except Exception:
        hostname = urlparse(url).hostname
        try:
            ipaddress.ip_address(hostname)
            return hostname
        except Exception:
            return ""
        
def get_response_referrer_policy(request):
    try:
        return request['responseHeaders'].get('referrer-policy')
    except KeyError:
        return "---NO REFERRER POLICY HEADERS---"

def get_first_non_redir_req(requests):
    """
    Returns the first non-redirect request from a list of requests.

    Args:
        requests (list): A list of request dictionaries, where each dictionary
                         contains request details including the "status" key.

    Returns:
        dict: The first request dictionary that does not have a status code
              starting with '3'. If all requests are redirects, returns an empty dictionary.
    """
    first_non_redir_req ={}
    for request in requests:
        if not str(request["status"]).startswith("3"):
            first_non_redir_req = request
            break
    return first_non_redir_req

def is_failed_visit(results):
    """ Exclude failed visits based on 3 conditions in 
    "https://github.com/asumansenol/kids-tracking-inspector/issues/39#issuecomment-1415837703"
    """
    if results["finalUrl"] == "about:blank":
        return True

    requests = results["data"]["requests"]
    first_non_redir_req = get_first_non_redir_req(requests)
    first_status = ""
    
    if "status" in first_non_redir_req:
        first_status = first_non_redir_req["status"]

    if str(first_status).startswith("4") or str(first_status).startswith("5"):
        return True

    if "size" in first_non_redir_req and first_non_redir_req["size"]<=512:
        return True

    if not any(request["status"] == 200 for request in requests):
        return True
    
    return False

def search_list(*search):
    """
    check whether the value of *search is exist and make a list of it

    :return list: list of search that is not None or ''
    """
    return [i for i in search if i is not None and i != '']

def selection_for_search(final_url):
    """
    parse url using urlparse, check whether the value exist and make a list of it

    :param url final_url: url to be parsed
    :return list: list of 
    """
    parsed_url = urlparse(final_url)
    full_url = urlunparse(parsed_url._replace(fragment=''))
    netloc_search = parsed_url.netloc
    hostname_search = parsed_url.hostname
    path_search = parsed_url.path.strip('/')
    if path_search == '/':
        path_search = ""
    params_search = parsed_url.params
    query_search = parsed_url.query
    fragment_search = parsed_url.fragment

    # Process fragment
    if fragment_search in {'/', '!', path_search} or len(fragment_search) < 5:
        fragment_search = ""
    if fragment_search in path_search.strip('/').split('/'):
        fragment_search = ""

    
    return search_list(final_url, full_url, netloc_search, hostname_search, 
                       path_search, params_search, query_search, fragment_search)

def match_entity(df_entity, domain):
    """
    Return the entity name for a given eTLD+1 using DuckDuckGo's entity map.

    When the first lookup fails, check for the domain's parent since DuckDuckGo's
    entity map may contain public suffixes.

    :param dataframe df_entity: dataframe from domain_map.json
    :param url domain: domain url to be checked
    :return string: entity name if the domain is found in the entity map,
        the domain itself otherwise
    """

    domain = str(domain)  # in case the function is called with None
    if domain in df_entity:
        return df_entity[domain]['entityName']
    if domain.count(".") >= 2:
        # strip the subdomain and try again
        # e.g. for "imasdk.googleapis.com", we try with "googleapis.com"
        # which is present in DuckDuckGo's entity map despite being a public suffix
        parent_domain = domain.split(".", 1)[-1]
        if parent_domain in df_entity:
            return df_entity[parent_domain]['entityName']
    # if the domain or its parent are not present, return unknown entity
    # suffixed with the original domain so different unknown entities
    # can be distinguished
    return domain

def is_same_entity(req_domain, site_domain):
    """
    is_same_entity function is used to check whether the entity is the same or different

    :param entity req_domain: entity from request domain
    :param entity site_domain: entity from site domain
    :return string: return entity name if the entity is the same, 
        return "different" if the entity is different
    """
    # try:
    if req_domain == site_domain:
        return req_domain
    return "different"

def leaky(row):
 
    final_url = row['final_url']
    req_url = row['req_url']
    post_data = row["post_data"]
    is_same_entity = row["is_same_entity_finReq"]
    referrer = row["referrer"]

    # Validate URLs early; if either is invalid, skip processing
    if not (validators.url(final_url) and validators.url(req_url)):
        return None, None, None
        
    url_leaks = None
    post_leaks = None
    referer_leaks = None

    if is_same_entity == "different":  

        search_terms = selection_for_search(final_url)
        leak_detector = LeakDetector.LeakDetector(
                    search_terms, 
                    encoding_set=LeakDetector.ENCODINGS_NO_ROT,
                    hash_set="",
                    # hash_set=LeakDetector.LIKELY_HASHES,
                    encoding_layers=2,
                    hash_layers=0,
                    debugging=False
                    )
        
        try:
            url_leaks = leak_detector.check_url(
                req_url, 
                encoding_layers=2) 
        except Exception as err:
            print("ERROR: Cannot do url leak detector", req_url, err)
        try:
            referer_leaks = leak_detector.check_referrer_str(
                referrer, 
                encoding_layers=2)
        except Exception as err:
            print("ERROR: Cannot do referrer leak detector", req_url, err)
        if post_data:
            try:
                post_leaks = leak_detector.check_post_data(
                    post_data, 
                    encoding_layers=2)
            except Exception as err:
                print("ERROR: Cannot do post leak detector", req_url, err)
                pass

    return str(url_leaks), str(post_leaks), str(referer_leaks)

def check_urlparse(row, leaks):
    """check if the referer_leaks contain the netloc, path, params, query, and fragment from the final_url

    :param row: row of dataframe

    :return: dictionary of the referer_leaks
    """
    url = row['final_url']
    parsed_url_list = selection_for_search(url)

    parsed_url = urlparse(url)
    full_url = urlunparse(parsed_url._replace(fragment=''))
    netloc_search = parsed_url.netloc
    hostname_search = parsed_url.hostname
    path_search = parsed_url.path.strip('/')
    if path_search == '/':
        path_search = ""
    params_search = parsed_url.params
    query_search = parsed_url.query
    fragment_search = parsed_url.fragment
    if fragment_search in {'/', '!', path_search} or len(fragment_search) < 5:
        fragment_search = ""
    if fragment_search in path_search.strip('/').split('/'):
        fragment_search = ""

    if leaks == "ref" :    
        desired_list = row['referer_leaks'].split("'") 
    elif leaks == "url":
        desired_list = row['url_leaks'].split("'")
    elif leaks == "post":
        desired_list = row['post_leaks'].split("'")

    undesired_set = {'[', ']', ',', 'None', '', '[(', ')]', ',)]', '), (', ', '}
    desired_list = [item for item in desired_list if item not in undesired_set]


    # Initialize dictionary to store matches
    matches = {
        "final_found": "","full": "","netloc": "", "hostname": "", "path": "", 
        "params": "", "query": "", "fragment": ""
    }
    
    # Map items to parsed components
    for item in desired_list:
        if item in parsed_url_list:
            if item == url:
                matches["final_found"] = url
            elif item == full_url:
                matches["full"] = full_url
            elif item == netloc_search:
                matches["netloc"] = netloc_search
            elif item == hostname_search:
                matches["hostname"] = hostname_search
            elif item == path_search:
                matches["path"] = path_search
            elif item == params_search:
                matches["params"] = params_search
            elif item == query_search:
                matches["query"] = query_search
            elif item == fragment_search:
                matches["fragment"] = fragment_search

    return matches['final_found'], matches['full'], matches["netloc"], matches["hostname"], matches["path"], matches["params"], matches["query"], matches["fragment"]


def is_http(url):
        return url.startswith("http://")

def is_https(url):
    return url.startswith("https://")

def clean_dataset(df, intersection):
    df = df[df.failed_visit == False]
    df = df[df.init_url.isin(intersection)]
    df = df[df.final_url != "about:blank"]
    return df

def check_circumvention(row, type):
    """
    Check whether potential leak data circumvent the referrer policy (only works on third-party requests) 

    :param dataframe row: a dataframe row that contain "ref_pol_data" column as
    the referer policy and check if leaks circumvent the policy

    :return tuple: (flag, frag_found) where flag is "Circumvention(full)", "Circumvention(partial)" ,"Safe", "Blank", or "Check"
                   frag_found is True if fragment is found, otherwise False
    """

    if type not in {"ref", "post", "url"}:
        print(f"Error: Invalid type '{type}'. Expected 'ref', 'post', or 'url'.")
        return

    frag_found = bool(row.get(f"{type}_fragments"))

    if row["is_same_entity_finReq"] != "different":
        return "Safe", frag_found

    ref_pol = row['ref_pol']
     # Dynamically retrieve fields based on type
    full = row.get(f"{type}_full")    
    final_found = row.get(f"{type}_final_found")
    domain_found = bool(row.get(f"{type}_hostname") or row.get(f"{type}_netloc"))

    base_url_http = f"http://{row.get(f'{type}_netloc', '')}/"
    base_url_https = f"https://{row.get(f'{type}_netloc', '')}/"
    partial_fields = [f"{type}_path", f"{type}_params", f"{type}_query"]

    ref_pol = row['ref_pol']
    full_found = (
        (final_found and final_found not in {base_url_http, base_url_https}) or 
        (full and full not in {base_url_http, base_url_https})
    )

    def has_partial_indication():
        non_empty_fields = [field for field in partial_fields if row.get(field)]
        return len(non_empty_fields) > 1 or (len(non_empty_fields) == 1 and len(row[non_empty_fields[0]]) > 9)


    def has_full_url_indication():
        return domain_found and has_partial_indication()

    
    def https_to_http_downgrade():
        return is_http(row['req_url']) and is_https(row['final_url'])

    if ref_pol == 'no-referrer':
        if full_found or domain_found or has_full_url_indication():
            flag = "Circumvention(full)"
        elif has_partial_indication():
            flag = "Circumvention(partial)"
        else:
            flag = "Safe"
    
    elif ref_pol == "same-origin":
        if full_found or domain_found or has_full_url_indication():
            flag = "Circumvention(full)"
        elif has_partial_indication():
            flag = "Circumvention(partial)"
        else:
            flag = "Safe"
    
    elif ref_pol == 'strict-origin':
        if https_to_http_downgrade():
            if full_found or domain_found or has_full_url_indication():
                flag = "Circumvention(full)"
            elif has_partial_indication():
                flag = "Circumvention(partial)"
            else:
                flag = "Safe"
        else:
            if full_found or has_full_url_indication():
                flag = "Circumvention(full)"
            elif has_partial_indication():
                flag = "Circumvention(partial)"
            else:
                flag = "Safe"
    
    elif ref_pol == 'strict-origin-when-cross-origin':
        if https_to_http_downgrade():
            if full_found or domain_found or has_full_url_indication():
                flag = "Circumvention(full)"
            elif has_partial_indication():
                flag = "Circumvention(partial)"
            else:
                flag = "Safe"
        else:
            if full_found or has_full_url_indication():
                flag = "Circumvention(full)"
            elif has_partial_indication():
                flag = "Circumvention(partial)"
            else:
                flag = "Safe"

    elif ref_pol == 'origin':
        if full_found or has_full_url_indication():
            flag = "Circumvention(full)"
        elif has_partial_indication():
            flag = "Circumvention(partial)"
        else:
            flag = "Safe"

    elif ref_pol == 'origin-when-cross-origin':
        if full_found or has_full_url_indication():
            flag = "Circumvention(full)"
        elif has_partial_indication():
            flag = "Circumvention(partial)"
        else:
            flag = "Safe"
    
    elif ref_pol == 'no-referrer-when-downgrade':
        if https_to_http_downgrade():
            if full_found or domain_found or has_full_url_indication():
                flag = "Circumvention(full)"
            elif has_partial_indication():
                flag = "Circumvention(partial)"
            else:
                flag = "Safe"
        else:
            flag = "Safe"

    elif ref_pol == 'unsafe-url':
        flag = "Safe"

    elif ref_pol == '':
        flag = "Blank"

    else:
        flag = "Check"


    return flag, frag_found

def strip_origin_from_url(url):
    """Return the URL after the origin part"""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return url[len(origin):]

def validate_referrer(df):
    """
    Updates df by checking if df.referrer adheres to df.ref_pol when df.ref_flag contains "Circumvention".
    Previously Circumvention checker on referrer vector show a False Positive.
    Example of false positive:
    - Final URL: https://wiadomosci.ox.pl/wiadomosci	
    - Referrer: https://wiadomosci.ox.pl/
    - Referrer Policy: strict-origin-when-cross-origin
    - Circumvention Flag: Circumvention(full) -> wiadomosci as path detected falsely on referrrer
    - Expected: Safe 

    Parameters:
        df (pd.DataFrame): The input is a DataFrame
        
    Returns:
        pd.DataFrame: The DataFrame with an update column 'ref_flag'.
    """

    def is_false_positive_ref(url, leaked_part):
        """
        Ignore Circumventions if the leaked part (mainly the URL path)
        occurs only in the origin part of the URL. These are mainly false positives
        such as:
            [FINAL_URL: 'https://www.kerstmarkten.net/kerstmarkten/', REF: 'https://www.kerstmarkten.net/'],
            [FINAL_URL: 'https://www.toyota.co.il/toyota-select', REF: 'https://www.toyota-select.co.il/'],
            [FINAL_URL: :'https://informationngr.com/information/', REF: 'https://informationngr.com/'],
        In each case, the path occurs in the origin part of the referer URL.
        """
        if not leaked_part or pd.isna(leaked_part):
            return False
        parsed = urlparse(url)
        url_sans_origin = strip_origin_from_url(url)
        return (leaked_part in parsed.netloc) and (
                leaked_part not in url_sans_origin)
    
    def update_flag(row):
        if row['ref_flag'] == "Safe":
            return "Safe"
        elif is_false_positive_ref(row['referrer'], row['ref_path']):
            return "Safe"
        else:
            return row.ref_flag

    df['ref_flag'] = df.apply(update_flag, axis=1)
    return df

def create_summary(row, type):
    if type not in {"ref", "post", "url"}:
        print(f"Error: Invalid type '{type}'. Expected 'ref', 'post', or 'url'.")
        return

    final = f"{type}_final_found"
    full = f"{type}_full"
    netloc = f"{type}_netloc"
    hostname = f"{type}_hostname"
    path = f"{type}_path"
    params = f"{type}_params"
    query = f"{type}_query"
    fragments = f"{type}_fragments"

    fields = [final, full, netloc, hostname, path, params, query, fragments]

    non_empty_fields = {field: row[field] for field in fields if row.get(field)}
    if not non_empty_fields:
        return None

    # Format the summary string based on non-empty fields
    summary = ', '.join(f"{key} = {value}" for key, value in non_empty_fields.items())
    return summary


def mark_fp_rows(df, mode="url"):

    def is_fragment_empty(url):
        parsed_url = urlparse(str(url))
        return parsed_url.fragment == ""

    def is_pattern_url(url):
        parsed = urlparse(str(url))
        return bool(parsed.netloc and parsed.fragment and parsed.path in ["/", "//"] and not parsed.query)


    def filter_FP_rows(df, mode="url"):
        if mode not in ["url", "post"]:
            raise ValueError("Mode must be either 'url' or 'post'")
        
        flag_col = f"{mode}_flag"
        full_col = f"{mode}_full"
        frag_found_col = f"{mode}_frag_found"
        final_found_col = f"{mode}_final_found"
        
        valid_rows = df[df[flag_col].str.contains("Circum", regex=False, na=False, case=False) # The FP only found in circumvention Flag 
                        & (df['ref_pol'] != "no-referrer") & (df['ref_pol'] != "same-origin") # When the RP values are equal to no-referrer and same-origin, it's not allowed to send any data to Third party so  
                        & df['final_url'].apply(is_pattern_url) # The FP has specific pattern {scheme}://{netloc}/#fragment 
                        & df[full_col].notna() #The FP found when the _full column is not empty 
                        & df[full_col].apply(is_fragment_empty) #The FP found when the _full column fragment is empty
                        & df[frag_found_col].apply(str).str.contains("False", regex=False, na=False, case=False) #The FP found when the _frag_found column is False
                        & (df[final_found_col] == "")
                        # & df[final_found_col].isna() #The FP found when the _final_found column is empty
                        ]
        return valid_rows



    if mode not in ["url", "post"]:
        raise ValueError("Mode must be either 'url' or 'post'")
    
    valid_rows = filter_FP_rows(df, mode)    # Get the filtered rows
    
    flag_col = f"{mode}_flag" # Define the flag column name
    prev_FP_col = f"{mode}_FP_rev" # Define the FP column name

    df.loc[valid_rows.index, prev_FP_col] = 'rev'     # Assign "FP" to the 'FP' column for these rows
    df.loc[valid_rows.index, flag_col] = 'Safe'     # Assign "FP" to the 'FP' column for these rows

    return df

def clean_column_detail(df):
    """Cleans the DataFrame by dropping specific columns.

    Args:
    df: The DataFrame to clean.

    Returns:
    The cleaned DataFrame.
    """

    if df.empty:
        return df

    regex_pattern = '_length|_full|_final_found|_fragments|_hostname|_netloc|_path|_params|_query'
    df.drop(df.filter(regex=regex_pattern).columns, axis=1, inplace=True)

    return df

def print_max_values_call(df):
    """
    For all of the columns,
    prints the maximum value along with the corresponding 'api' and 'final_url'.
    The output format is: "column_name, max_value, api, final_url".
    If the column is empty or all values are NaN, a message is printed.
    """
    columns_to_check = ["loc_href", "loc_origin", "loc_protocol", 
                        'loc_host', 'loc_hostname', 'loc_port', 
                        'loc_pathname', 'loc_hash' ,"doc_url"]

    for col in columns_to_check:
        # Remove NaN values for accurate calculation
        valid_series = df[col].dropna()
        if valid_series.empty:
            print(f"{col} is empty or all values are NaN.")
            continue

        idx = valid_series.idxmax()
        max_val = df.at[idx, col]
        api_val = df.at[idx, "api"]
        final_url_val = df.at[idx, "final_url"]
        print(f"{col}, {max_val}, {api_val}, {final_url_val}")

def count_uniq_dom_call(df):
    """
    For each column in columns_to_check (e.g., "loc_href", "loc_origin",
    "loc_protocol", and "doc_url"), prints and returns the count of unique
    final_url values among rows where that column is not NaN.
    """
    columns_to_check = ["loc_href", "loc_origin", "loc_protocol", 
                    'loc_host', 'loc_hostname', 'loc_port', 
                    'loc_pathname', 'loc_hash' ,"doc_url"]
    results = {}
    
    for col in columns_to_check:
        # Select rows where the current column is not NaN, then count unique final_url values
        count = df.loc[df[col].notna(), "final_host"].nunique()
        results[col] = count
    
    return results

def count_uniq_dom_RP(df):
    uniq = df.drop_duplicates(subset=['final_host', 'req_host' ,'ref_pol'])
    for rp in RP_VALUES:
        print(rp, ':', uniq[uniq['ref_pol'] == rp].final_host.nunique())


def calculate_rank_statistics(rank_df):
    max_rank = rank_df['rank_of_sites'].max()
    min_rank = rank_df['rank_of_sites'].min()
    median_rank = rank_df['rank_of_sites'].median()
    
    print(f'Max value of rank_of_sites: {max_rank}')
    print(f'Min value of rank_of_sites: {min_rank}')
    print(f'Median value of rank_of_sites: {median_rank}')

def check_comma(string):
    if ',' in string:
        return True
    else:
        return False
    
def check_newline(string):
    if '\n' in string:
        return True
    else:
        return False

def tranform_legacy(row):
    legacy = row['referrer_policy'].lower()
    if check_comma(legacy):
        for r in reversed(legacy.split(',')):
            if not check_newline(r):
                return r.strip()

    match legacy:
        case 'origin-when-crossorigin' | 'origin-when-cross-origin':
            return 'origin-when-cross-origin'
        case 'never' | 'no-referrer':
            return 'no-referrer'
        case 'always' | 'unsafe-url':
            return 'unsafe-url'
        case 'strict-origin-when-cross-origin':
            return 'strict-origin-when-cross-origin'
        case 'origin':
            return 'origin'
        case 'strict-origin':
            return 'strict-origin'
        case 'no-referrer-when-downgrade':
            return 'no-referrer-when-downgrade'
        case 'same-origin':
            return 'same-origin'
        case 'default':
            return DEFAULT_RP_VALUES
        case _:
            return 'ignored'
        

def create_rp_stats_inframe_df(df, rp_values):
    rp_stats = []
    for rp_value in rp_values:
        value_counts = df[df.ref_pol_fix == rp_value].inFrame.value_counts()
        normalized_counts = df[df.ref_pol_fix == rp_value].inFrame.value_counts(normalize=True)
        inFrame_list = value_counts.index.tolist()
        value_counts_list = value_counts.values.tolist()
        for i in range(len(inFrame_list)):
            rp_stats.append({'rp_value': rp_value, 
                             'inFrame': inFrame_list[i], 
                             'value_counts': value_counts_list[i],
                             'percentage': normalized_counts[i]
                             })
    return pd.DataFrame(rp_stats)
        
def transform_response(row):
    response = row['response_ref_policy'].lower()
    if response == '':
        return DEFAULT_RP_VALUES
    if response is None:
        return 'ignored'
    if check_comma(response):
        for r in reversed(response.split(',')):
            if not check_newline(r):
                return r.strip()
    if check_newline(response):
        return 'ignored'
    if response in RP_VALUES:
        return response
    else:
        return "ignored"
    

def create_resp_rp_stats_third_party_df(df, rp_values):
    
    def third_party_req(is_same_entity_finReq):
        return is_same_entity_finReq != 'different'

    df['third_party_req'] = df['is_same_entity_finReq'].apply(third_party_req)

    rp_stats = []
    df = df.drop_duplicates(subset=['final_host', 'third_party_req', 'response_rp_fix'])
    for rp_value in rp_values:
        value_counts = df[df.response_rp_fix == rp_value].third_party_req.value_counts()
        third_party_resp_list = value_counts.index.tolist()
        value_counts_list = value_counts.values.tolist()
        # normalized_counts_list = normalized_counts.values.tolist()
        for i in range(len(third_party_resp_list)):
            rp_stats.append({
                'rp_value': rp_value, 
                'third_party_resp': third_party_resp_list[i], 
                'value_counts': value_counts_list[i]
                })
                
    return pd.DataFrame(rp_stats)

def doc_wide (df1, df2):
    meta = df1[['final_host', 'ref_pol_fix']].rename(columns={'ref_pol_fix': 'rp_effective'})
    meta = meta[meta['rp_effective'] != "ignored"]
    print('Websites that utilise meta-tags: ',meta.final_host.nunique())
    response = df2[['final_host', 'response_rp_fix']].dropna().rename(columns={'response_rp_fix': 'rp_effective'})
    response = response[response['rp_effective'] != "ignored"]
    print('Websites that utilise response:', response.final_host.nunique())
    combined = pd.concat([meta, response ], axis=0) 
    print('Websites that utilise doc-wide:', combined.final_host.nunique())
    return combined.drop_duplicates(subset=['final_host', 'rp_effective'])


def find_appearance(df, type='dom'):
    # Group by 'req_host' and 'final_host' to find unique combinations
    if type == 'dom':
        grouped = df.groupby('req_host')['final_host'].nunique()
    elif type == 'ent':
        grouped = df.groupby('req_entity')['final_host'].nunique()
    else:
        raise ValueError("type must be 'dom' or 'ent'")
    
    # Convert the result to a list of tuples
    appearance = list(grouped.items())
    
    return appearance

def make_comparison_appearance(df_full, df_circum, type="dom"):
    if type == "dom":
        key_column = 'req_host'
    elif type == "ent":
        key_column = 'req_entity'
    else:
        raise ValueError("type must be either 'dom' or 'ent'")

    # Get appearance data for both full and partial DataFrames
    full_appearance = find_appearance(df_full, type)
    circum_appearance = find_appearance(df_circum, type)

    # Convert the results into DataFrames
    full_df = pd.DataFrame(full_appearance, columns=[key_column, 'full.count'])
    partial_df = pd.DataFrame(circum_appearance, columns=[key_column, 'circum.count'])

    # Merge both DataFrames on the key column, using an outer join to include all values
    result = pd.merge(full_df, partial_df, on=key_column, how='outer')

    # Fill missing values with 0 in case some entities are only present in one DataFrame
    result.fillna(0, inplace=True)

    # Sort by 'vio.count' in descending order
    result.sort_values(by='circum.count', ascending=False, inplace=True)

    # Calculate the hit column: "partial.count (percentage%)"
    result['circumvention'] = (
        result['circum.count'].astype(int).astype(str) + 
        " (" + ((result['circum.count'] / result['full.count']).fillna(0) * 100).round(2).astype(str) + "%)"
    )

    return result

def calculate_row_circum(df):
    """
    Calculate the percentage of rows with each {type}_flag containing "circumvention". 
    and the total percentage where any flag contains 'circumvention'.
    
    Parameters:
        df (pd.DataFrame): The DataFrame containing flag columns ending with '_flag'.
    
    Returns:
        dict: A dictionary with {type}_flag and "Total" as keys, and their circumvention percentages as values.
    """
    # Identify all flag columns (those ending with '_flag')
    flag_columns = [col for col in df.columns if col.endswith('_flag')]
    
    if not flag_columns:
        raise ValueError("No flag columns found in the DataFrame.")
    
    # Initialize a dictionary to store the percentages
    circumvention_percentages = {}
    
    # Total rows in the DataFrame
    total_rows = len(df)
    
    # Calculate percentage for each flag column
    for flag_column in flag_columns:
        if total_rows == 0:
            circumvention_percentages = 0.0  # Avoid division by zero
        else:
            circumvention_rows = len(df[df[flag_column].str.contains("Circumvention", na=False)])
            circumvention_percentage = (circumvention_rows / total_rows) * 100
        circumvention_percentages[flag_column] = circumvention_percentage
    
    # Calculate the total percentage for rows with any flag containing 'circumvention'
    if total_rows == 0:
        total_circumvention_percentage = 0.0
    else:
        # Check if any of the flag columns in a row contains "circumvention"
        total_circumvention_rows = len(
            df[df[flag_columns].parallel_apply(lambda row: row.str.contains("Circumvention", na=False).any(), axis=1)]
        )
        total_circumvention_percentage = (total_circumvention_rows / total_rows) * 100
    
    # Add Total to the results
    circumvention_percentages['Total'] = total_circumvention_percentage
    
    return circumvention_percentages

def count_circumventions_vector(df, type):
    if type not in {"ref", "post", "url"}:
        print(f"Error: Invalid type '{type}'. Expected 'ref', 'post', or 'url'.")
        return
    
    flag_col = f"{type}_flag"

    vio_on_vector = df[df[flag_col] != "Safe"]
    vio_unique = vio_on_vector.drop_duplicates(subset=['final_host', 'req_host', 'ref_pol'])

    # Count Number of unique domain with RP circumventions on {type} vector
    print(f"{type}: {vio_unique.final_host.nunique()}")
    for rp in RP_VALUES:
        print(rp, ": ", vio_unique[vio_unique.ref_pol == rp].final_host.nunique())


def count_url_components(df):
    """
    Analyze the 'final_url' column in the DataFrame and return:
      1. The total number of unique hosts where the URL has a non-empty path.
      2. The total number of unique hosts where the URL has both a non-empty path and a non-empty query.
      3. The total number of unique hosts where the URL has either a non-empty path or a non-empty query.
      
    Parameters:
        df (pandas.DataFrame): DataFrame containing a 'final_url' column.
        
    Returns:
        tuple: (unique_hosts_with_path, unique_hosts_with_path_and_query, unique_hosts_with_path_or_query)
    """
    # Drop rows where final_url is missing and work on a copy to avoid SettingWithCopyWarning.
    df_valid = df.dropna(subset=['final_url']).copy()
    
    # Parse final_url to extract path and query.
    df_valid['parsed'] = df_valid['final_url'].apply(urlparse)
    df_valid['path'] = df_valid['parsed'].apply(lambda x: x.path)
    df_valid['query'] = df_valid['parsed'].apply(lambda x: x.query)
    
    # Create boolean masks based on non-empty path and/or query.
    mask_path = df_valid['path'].astype(bool)          # non-empty path
    mask_path_and_query = mask_path & df_valid['query'].astype(bool)  # both non-empty path and query
    mask_path_or_query = df_valid['path'].astype(bool) | df_valid['query'].astype(bool)  # either non-empty path or query
    
    # Count unique final_host values in each condition.
    unique_hosts_with_path = df_valid.loc[mask_path, 'final_host'].nunique()
    unique_hosts_with_path_and_query = df_valid.loc[mask_path_and_query, 'final_host'].nunique()
    unique_hosts_with_path_or_query = df_valid.loc[mask_path_or_query, 'final_host'].nunique()
    
    return unique_hosts_with_path, unique_hosts_with_path_and_query, unique_hosts_with_path_or_query

def count_url_components_10(df):
    """
    Count unique `final_host` entries based on path and query length conditions.

    Args:
        df (pd.DataFrame): DataFrame with a 'final_host' column.

    Returns:
        tuple: 
            - Total unique `final_host` entries with `path` >= 10 characters
            - Total unique `final_host` entries with `query` >= 10 characters
            - Total unique `final_host` entries with `path` and `query` >= 10 characters
            - T
    """
    # Extract components using urlparse and filter based on length conditions
    filtered_df = df[df['is_same_entity_finReq'] == "different"]
    filtered_df['parsed_url'] = filtered_df['final_url'].apply(urlparse)

    path_count = filtered_df[filtered_df['parsed_url'].apply(lambda x: len(x.path) >= 10)]['final_host'].nunique()

    path_query_count = filtered_df[
        (filtered_df['parsed_url'].apply(lambda x: len(x.path) >= 10)) & 
        (filtered_df['parsed_url'].apply(lambda x: len(x.query) >= 10))
    ]['final_host'].nunique()

    path_or_query = filtered_df[
        (filtered_df['parsed_url'].apply(lambda x: len(x.path) >= 10)) | 
        (filtered_df['parsed_url'].apply(lambda x: len(x.query) >= 10))
    ]['final_host'].nunique()
    
    # Clean up temporary column
    filtered_df.drop(columns=['parsed_url'], inplace=True)

    return path_count, path_query_count, path_or_query


def safe_literal_eval(x):
    if isinstance(x, str):
        try:
            return ast.literal_eval(x)
        except Exception as e:
            print(f"Error evaluating {x}: {e}")
            return x
    return x



def filter_df_by_encode(df, encode_choice, min_length=5):
    """
    Filters the DataFrame rows based on the leaks columns.
    
    For each row, checks if any of the leaks columns (url_leaks, referrer_leaks, post_leaks)
    contains a tuple of the form (encode, web) where:
      - encode == encode_choice, and
      - len(web) >= min_length
      
    Parameters:
    -----------
    df : pd.DataFrame
        DataFrame containing the columns 'url_leaks', 'referrer_leaks', 'post_leaks'.
    encode_choice : str
        The encode value to filter for (e.g., 'urlencode').
    min_length : int, optional (default=10)
        Minimum number of characters required for the 'web' string.
    
    Returns:
    --------
    pd.DataFrame
        A new DataFrame containing only the rows that meet the condition.
    """
    
    
    def has_valid_leak(leaks):
        # Check if leaks is a list and iterate over each tuple
        if isinstance(leaks, list):
            for leak in leaks:
                # Check if it's a tuple with exactly 2 elements (encode, web)
                if isinstance(leak, tuple) and len(leak) == 2:
                    encode, web = leak
                    if encode == encode_choice and isinstance(web, str) and len(web) >= min_length:
                        return True
        return False

    # Create a boolean mask for rows where any leaks column has a valid tuple
    mask = df.parallel_apply(lambda row: (has_valid_leak(row.get('url_leaks')) or 
                                 has_valid_leak(row.get('referer_leaks')) or 
                                 has_valid_leak(row.get('post_leaks'))), axis=1)
    
    return df[mask]