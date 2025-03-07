#!/usr/bin/python3
import xmlrpc.client
from socket import getfqdn
from datetime import datetime,timedelta
import pdb
MANAGER_USER = "infobot"
MANAGER_PASS = "infobot321"
MANAGER_URL = "http://susemanager.suselab.localdomain/rpc/api"


def main():
    session_key = None

    with xmlrpc.client.ServerProxy(MANAGER_URL) as proxy:
        try:
            session_key = proxy.auth.login(MANAGER_USER, MANAGER_PASS)
            event_data= {}

            for s in proxy.system.listSystems(session_key):
                if s['id'] not in event_data.keys():
                    event_data[s['id']] = []
                event_data[s['id']] += proxy.system.getEventHistory(session_key, s['id'])
                # print(event_data[s['id']])
            for system in event_data.keys():
                print(f"Events for system ID {system}")
                for event in event_data[system]:
                    print(f"\tSummary: {event['summary']}")
                    print(f"\tDetails: {event['details']}")
                    if 'completed' in event.keys():
                        print(f"\tDate completed: {event['completed']}")
                    else:
                        print(f"\tDate completed: <not completed>")
                    print()

            if (session_key) is not None:
                proxy.auth.logout(session_key)
        except ConnectionRefusedError as e:
            print(f'Connection error: {e}')
        except ValueError as e:
            print(f'System ID can only be numeric!')
        except xmlrpc.client.Fault as e:
            print(f'Error submitting job: {e}')
main()

