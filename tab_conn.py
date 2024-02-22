

import requests 
import xml.etree.ElementTree as ET 
import sys
import re
import math
import getpass
import os


# The namespace for the REST API is 'http://tableausoftware.com/api' for Tableau Server 9.0
# or 'http://tableau.com/api' for Tableau Server 9.1 or later
xmlns = {'t': 'http://tableau.com/api'}








class ApiCallError(Exception):
    pass


class UserDefinedFieldError(Exception):
    pass


def _encode_for_display(text):
    """
    Encodes strings so they can display as ASCII in a Windows terminal window.
    This function also encodes strings for processing by xml.etree.ElementTree functions.

    Returns an ASCII-encoded version of the text.
    Unicode characters are converted to ASCII placeholders (for example, "?").
    """
    return text.encode('ascii', errors="backslashreplace").decode('utf-8')




def _check_status(server_response, success_code):
    """
    Checks the server response for possible errors.

    'server_response'       the response received from the server
    'success_code'          the expected success code for the response
    Throws an ApiCallError exception if the API call fails.
    """
    if server_response.status_code != success_code:
        parsed_response = ET.fromstring(server_response.text)

        # Obtain the 3 xml tags from the response: error, summary, and detail tags
        error_element = parsed_response.find('t:error', namespaces=xmlns)
        summary_element = parsed_response.find('.//t:summary', namespaces=xmlns)
        detail_element = parsed_response.find('.//t:detail', namespaces=xmlns)

        # Retrieve the error code, summary, and detail if the response contains them
        code = error_element.get('code', 'unknown') if error_element is not None else 'unknown code'
        summary = summary_element.text if summary_element is not None else 'unknown summary'
        detail = detail_element.text if detail_element is not None else 'unknown detail'
        error_message = '{0}: {1} - {2}'.format(code, summary, detail)
        raise ApiCallError(error_message)
    return


def sign_in(server, username, password, site=""):
    """
    Signs in to the server specified with the given credentials

    'server'   specified server address
    'username' is the name (not ID) of the user to sign in as.
               Note that most of the functions in this example require that the user
               have server administrator permissions.
    'password' is the password for the user.
    'site'     is the ID (as a string) of the site on the server to sign in to. The
               default is "", which signs in to the default site.
    Returns the authentication token and the site ID.
    """
    url = server + "/api/{0}/auth/signin".format(VERSION)

    # Builds the request
    xml_request = ET.Element('tsRequest')
    credentials_element = ET.SubElement(xml_request, 'credentials', name=username, password=password)
    ET.SubElement(credentials_element, 'site', contentUrl=site)
    xml_request = ET.tostring(xml_request)

    # Make the request to server
    server_response = requests.post(url, data=xml_request)
    _check_status(server_response, 200)

    # ASCII encode server response to enable displaying to console
    server_response = _encode_for_display(server_response.text)

    # Reads and parses the response
    parsed_response = ET.fromstring(server_response)

    # Gets the auth token and site ID
    token = parsed_response.find('t:credentials', namespaces=xmlns).get('token')
    site_id = parsed_response.find('.//t:site', namespaces=xmlns).get('id')
    user_id = parsed_response.find('.//t:user', namespaces=xmlns).get('id')
    return token, site_id, user_id


def sign_out(server, auth_token):
    """
    Destroys the active session and invalidates authentication token.

    'server'        specified server address
    'auth_token'    authentication token that grants user access to API calls
    """
    url = server + "/api/{0}/auth/signout".format(VERSION)
    server_response = requests.post(url, headers={'x-tableau-auth': auth_token})
    _check_status(server_response, 204)
    return


def get_datasource_id(server, auth_token, site_id, datasource_name):
    """
    Gets the id of the desired data source to relocate.

    'server'            specified server address
    'auth_token'        authentication token that grants user access to API calls
    'user_id'           ID of user with access to data source
    'site_id'           ID of the site that the user is signed into
    'datasource_name'   name of data source to get ID of
    Returns the data source id and the project id that contains the data source.
    """
    url = server + "/api/{0}/sites/{1}/datasources".format(VERSION, site_id)
    server_response = requests.get(url, headers={'x-tableau-auth': auth_token})
    _check_status(server_response, 200)
    xml_response = ET.fromstring(_encode_for_display(server_response.text))

    datasources = xml_response.findall('.//t:datasource', namespaces=xmlns) #findtext
    for datasource in datasources:
        if datasource.get('name') == datasource_name:
            return datasource.get('id')
    error = "Data source named '{0}' not found.".format(datasource_name)
    raise LookupError(error)



def download(server, auth_token, site_id, datasource_id):
    """
    Downloads the desired data source from the server (temp-file).

    'server'          specified server address
    'auth_token'      authentication token that grants user access to API calls
    'site_id'         ID of the site that the user is signed into
    'datasource_id'   ID of the data soutce to download
    Returns the filename of the data source downloaded.
    """
    print("\tDownloading data source to a temp file")
    url = server + "/api/{0}/sites/{1}/datasources/{2}/content".format(VERSION, site_id, datasource_id)
    server_response = requests.get(url, headers={'x-tableau-auth': auth_token})
    _check_status(server_response, 200)

    # Header format: Content-Disposition: name="tableau_datasource"; filename="datasource-filename"
    filename = re.findall(r'filename="(.*)"', server_response.headers['Content-Disposition'])[0]
    with open(filename, 'wb') as f:
        f.write(server_response.content)
    return filename




import pandas as pd
import requests
import re

def download_to_dataframe(server, auth_token, site_id, datasource_id):
    """
    Downloads the desired data source from the server and returns it as a Pandas DataFrame.

    Args:
        server (str): Specified server address.
        auth_token (str): Authentication token that grants user access to API calls.
        site_id (str): ID of the site that the user is signed into.
        datasource_id (str): ID of the data source to download.

    Returns:
        pd.DataFrame: DataFrame containing the data from the data source.
    """
    print("\tDownloading data source to a Pandas DataFrame")
    url = f"{server}/api/{VERSION}/sites/{site_id}/datasources/{datasource_id}/content"
    server_response = requests.get(url, headers={'x-tableau-auth': auth_token})
    _check_status(server_response, 200)

    # Parse the data source content (assuming it's in CSV format)
    content = server_response.content.decode('utf-8')
    df = pd.read_csv(pd.compat.StringIO(content))

    return df



def main():




    server =""
    username =""
    password =""
    site =""
    VERSION = "3.3"
    datasource_name = ""
    
    print("\n1. Signing in to  sites to obtain authentication tokens")
    auth_token, site_id, user_id = sign_in(server, username, password, site)
    print((server, username, password, site))


    # Find data source id 

    print("\n2. Finding data source id of '{0}'".format(datasource_name))
    datasource_id = get_datasource_id(server, auth_token, site_id, datasource_name)
    print(server, auth_token, site_id, datasource_name)
    
 
    # Download data source 
    print("\n4. Downloading the data source to move")
    dataaspandasdf = download(server, auth_token, site_id, datasource_id)
    print(f"datasourceid {datasource_id}")
    print(f"pd df \n{dataaspandasdf}")

    # Sign out 
    print("\n7. Signing out and invalidating the authentication token")
    sign_out(server, auth_token)


if __name__ == "__main__":
    main()