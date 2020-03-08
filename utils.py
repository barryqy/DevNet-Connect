# NOTE: this is a Proof of Concept script, please test before using in production!

# Copyright (c) 2020 Cisco and/or its affiliates.
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.0 (the "License"). You may obtain a copy of the
# License at
#                https://developer.cisco.com/docs/licenses
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

import requests
from bs4 import BeautifulSoup
import json
import feedparser
from datetime import datetime
import os
import webexteamssdk



def write_config(config_file):
    ''' 
    This function writes to config.json
    '''
    with open("config.json", 'w') as output_file:
        json.dump(config_file, output_file, indent=4)



def get_CTR_access_token(config_file):
    ''' 
    This function requests access token for OAuth2 for other CTR API requests
    '''
    #error checking for API client details
    if config_file['client_id']:
        client_id = config_file['client_id']
    else:
        print("client_id is missing in config.json file...\n")

    if config_file['client_secret']:
        client_secret = config_file['client_secret']
    else:
        print("client_secret is missing in config.json file...\n")


    # create headers for access token request
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }

    data = {
    'grant_type': 'client_credentials'
    }

    # create headers for access token request
    response = requests.post('https://visibility.amp.cisco.com/iroh/oauth2/token', headers=headers, data=data, auth=(client_id, client_secret))

    #check if request was succesful
    if response.status_code == 200:
        
        # grab the text from the request
        rsp_dict = json.loads(response.text)
        # retrieve variables from text, global variable so that it can be used by all functions for CTR
        access_token = (rsp_dict['access_token'])
        scope = (rsp_dict['scope'])
        expiration_time = (rsp_dict['expires_in'])     
        # user feedback
        #print(f"[200] Success, access_token generated! This is the scope: {scope}. Expires in: {expiration_time} seconds.\n") 
        
        # return token
        return access_token
    else:
        # user feedback
        print(f"Access token request failed, status code: {response.status_code}\n")



def return_observables(raw_text,config_file):
    '''
    this function will parse raw text and return the observables and types
    '''
    # create headers for API request
    bearer_token = 'Bearer ' + get_CTR_access_token(config_file)

    headers = {
        'Authorization': bearer_token,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    data = json.dumps({"content":raw_text})

    response = requests.post('https://visibility.amp.cisco.com/iroh/iroh-inspect/inspect', headers=headers, data=data)
    #check if request was succesful
    if response.status_code == 200:
        return(response.text) 
    else:
        print(f"Observable parsing request failed, status code: {response.status_code}\n")


 
def return_non_clean_observables(returned_observables_json,config_file):
    '''
    this function returns only non clean observables (to remove noise)
    '''
    # create headers for API request
    bearer_token = 'Bearer ' + get_CTR_access_token(config_file)

    headers = {
        'Authorization': bearer_token,
        'Content-Type':'application/json',
        'Accept':'application/json'
        }
    
    # create empty list to store clean observables
    clean_observables = []
    
    # retrieve dispositions for observables
    response = requests.post('https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables', headers=headers, data=returned_observables_json)

    disposition_observables = json.loads(response.text)

    # parse through json and search for observables with clean disposition (1)
    for module in disposition_observables['data']:
        module_name = module['module']
        if 'verdicts' in module['data'] and module['data']['verdicts']['count'] > 0:
            docs = module['data']['verdicts']['docs']
            for doc in docs:
                observable = doc['observable']
                # if the disposition is clean / 1 then add to separate list to remove from other list
                if doc['disposition'] == 1:
                    clean_observables.append(observable)
                    #print(f"Clean observable, omitting: {observable}\n")

    non_clean_observables = [i for i in json.loads(returned_observables_json) if not i in clean_observables or clean_observables.remove(i)]
    
    non_clean_observables_json = json.dumps(non_clean_observables)

    return non_clean_observables_json


 
def clean_entry(entry_link,config_file):  
    '''
    this function removes hyperlinks and other false positives from a blog post
    ''' 
    # retrieve entire blog from original link and ingest text only
    response = requests.get(entry_link)
    soup = BeautifulSoup(response.content, "html.parser")
    entire_blog = soup.get_text()

    # split text into words
    words_entry = entire_blog.split() 
    
    # create empty list for words which do not contain any of the below noise + for every entry clear it again
    cleaned_entry = []

    # remove noise from blogs (hyperlinks etc.)
    for word in words_entry:
        if word.startswith('href="'):
            pass
        elif word.startswith('src="'):
            pass
        elif word.startswith('xmlns:'):
            pass
        elif word.startswith('url="'):
            pass
        elif word.startswith('Snort.org'):
            pass
        elif word.startswith("'https://www.googletagmanager.com"):
            pass
        else:
            cleaned_entry.append(word)
    
    # stitch the blog back together (list of words to string)
    space_words = " "
    cleaned_entry_str = space_words.join(cleaned_entry)

    # retrieve observables from text
    returned_observables_json = return_observables(cleaned_entry_str,config_file)

    # return non clean (malicious, unkown etc.) observables only
    non_clean_observables_json = return_non_clean_observables(returned_observables_json,config_file) 

    return non_clean_observables_json



def check_for_sighting(returned_observables_json,config_file):
    '''
    this function checks if there is a sighting for a specific observable
    '''
    # create headers for API request
    bearer_token = 'Bearer ' + get_CTR_access_token(config_file)

    headers = {
        'Authorization': bearer_token,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    #data = json.dumps(returned_observables_json)
    data = returned_observables_json
    with open("log.txt", 'w') as output_file:
        json.dump(returned_observables_json, output_file, indent=4)

    response = requests.post('https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables', headers=headers, data=data)
    
    #check if request was succesful
    if response.status_code == 200:
        
        returned_data = json.loads(response.text)

        
        total_amp_sighting_count = 0
        total_umbrella_sighting_count = 0
        total_email_sighting_count = 0

        # run through all modules to check for sightings (currently checking the amp, umbrella and SMA modules)
        for module in returned_data['data']:
            if module['module'] == "AMP for Endpoints":
                # json key not always there, error checking...
                if 'sightings' in module['data']:
                    # store amount of sightings
                    total_amp_sighting_count = module['data']['sightings']['count']

            if module['module'] == "Umbrella":
                # json key not always there, error checking...
                if 'sightings' in module['data']:
                    # store amount of sightings
                    total_umbrella_sighting_count = module['data']['sightings']['count']

            if module['module'] == "SMA Email":
                # json key not always there, error checking...
                if 'sightings' in module['data']:
                    # store amount of sightings
                    total_email_sighting_count = module['data']['sightings']['count']

        # create dict to store information regarding the sightings

        total_sighting_count = total_amp_sighting_count + total_umbrella_sighting_count + total_email_sighting_count

        return_sightings = {
            'total_sighting_count': total_sighting_count,
            'total_amp_sighting_count': total_amp_sighting_count,
            'total_umbrella_sighting_count': total_umbrella_sighting_count,
            'total_email_sighting_count': total_email_sighting_count
        }

        return(return_sightings)

    else:
        print(f"Sighting check request failed, status code: {response.status_code}\n")
        return(response.status_code)






def parse_rss_feed(rss_feed,rss_feed_index,config_file,token):
    '''
    this function parses a RSS feed into raw text, checks for observables and sightings and creates a case
    '''

    #store feed name
    feed_name = rss_feed['feed_name']
    rss_url = rss_feed['rss_url']

    # store the etag and modified
    if config_file['url_feeds'][rss_feed_index]['last_etag'] == '' or config_file['url_feeds'][rss_feed_index]['last_modified'] == '':
        # user feedback
        print(f"First time script runs, no last version stored. Parsing through all available {feed_name} blog posts now...\n")
        
        # retrieve all blogs and store info in config.json to check for updates in subsequent script runs
        response = feedparser.parse(rss_url)
        config_file['url_feeds'][rss_feed_index]['last_etag'] = response.etag
        config_file['url_feeds'][rss_feed_index]['last_modified'] = list(response.modified_parsed)
        write_config(config_file)

        # run through all entries and create casebook per entry     
        for entry in response.entries:

            # retrieve link for casebook description
            entry_link = entry.link

            # send the description of the blog entry (containing the body) to cleaning function to remove hyperlinks and clean observables etc.
            non_clean_observables_json = clean_entry(entry_link,config_file)

            # retrieve title for casebook indexing and webex teams message            
            entry_title = entry.title

            # if observables were returned (list not empty), create a casebook
            if non_clean_observables_json != "[]":      
                
                # retrieve target sightings for observables
                returned_sightings = check_for_sighting(non_clean_observables_json,config_file)

                # create new case in casebook
                print("Feed analysis found one instance, ready to create casebook")
                return [ feed_name,non_clean_observables_json,returned_sightings,entry_title,entry_link ]

                #new_casebook(feed_name,non_clean_observables_json,returned_sightings,entry_title,entry_link)
            else:
                print(f"No new case created in casebook (no observables found) from: {entry_title}\n")
            
           
    ### tags were stored, so check if new entries on RSS feed
    else:
        # check if new version exists
        response_update = feedparser.parse(rss_url, etag=config_file['url_feeds'][rss_feed_index]['last_etag'], modified=config_file['url_feeds'][rss_feed_index]['last_modified'])

        if response_update.status == 304:
            # no changes if status is 304
            print(f"No changes to {feed_name} RSS feed detected...\n")
        else:
            response = feedparser.parse(rss_url)
            print(f"Change detected in {feed_name} RSS feed, last modified: {response.modified}, checking for new blog posts to parse...\n")

            # run through all entries and create casebook per entry     
            for entry in response.entries:

                # retrieve title for casebook indexing or message            
                entry_title = entry.title

                # check if the blog is newer than then last one
                if (config_file['url_feeds'][rss_feed_index]['last_modified']==0) or (list(entry.published_parsed) > config_file['url_feeds'][rss_feed_index]['last_modified']):

                    # user feedback
                    print(f"Blog detected that was published later than last modified: {entry.title}\n")

                    # retrieve link for casebook description
                    entry_link = entry.link

                    # send the description of the blog entry (containing the body) to cleaning function to remove hyperlinks and clean observables etc.
                    non_clean_observables_json = clean_entry(entry_link,config_file)

                    # if observables were returned (list not empty), create a casebook
                    if non_clean_observables_json != "[]":
                        returned_sightings = check_for_sighting(non_clean_observables_json,config_file)
                        print("Feed analysis found one instance, ready to create casebook, please move on ===>")
                        return [ feed_name,non_clean_observables_json,returned_sightings,entry_title,entry_link ]
                        #new_casebook(feed_name,non_clean_observables_json,returned_sightings,entry_title,entry_link)
                    else:
                        print(f"No new case created (no observables found) from: {entry_title}\n")

                else:
                    print(f"Blog has already been parsed: {entry_title}.\n")

            # set new values in config.json file
            config_file['url_feeds'][rss_feed_index]['last_etag'] = response.etag
            config_file['url_feeds'][rss_feed_index]['last_modified'] = list(response.modified_parsed)
            write_config(config_file)
    return





