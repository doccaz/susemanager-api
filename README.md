# susemanager-api
Scripts using the SUSE Manager API

These scripts all use the SUSE Manager API to do common tasks and extract information from any SUSE Manager instance.

I get asked about how to use the API quite frequently, so I decided to make a few working examples (based on scripts I wrote waaaay back in 2014 -- I'm getting old!) and share them with the world.

## General usage instructions

Most of the scripts here have the URL to the SUMA server hardcoded in the first lines. Please change that before using.
Most of the actions will require a regular SUMA user that's at least capable of reading information (Read-only user). 
The runscripts_sm script requires an admin user, as it is indeed creating/scheduling jobs.

These scripts are meant to make it easy to customize SUSE Manager to your environment, and mainly so you can learn how to do it.

The complete SUSE Manager API reference is available at: https://documentation.suse.com/suma/5.0/api/suse-manager/index.html

## Currently available scripts

* **check_activationkey.py**: this will search for a named activation key and report if it exists or not.
* **get_eventdetails.py**: retrieves detailed information about one specific event in a system's history. Needs the system ID and the event ID.
* **get_eventhistory.py**: retrieves a list of all events for one system over the last 30 days. Requires a system ID.
* **getresults_sm.py**: this script will take a "jobs.csv" generated by runscripts_sm.py, query for all the results (including command output), and write them to a CSV.
* **list_activationkeys.py**: returns a list of all activation keys present on the system
* **list_activesystems.py**: returns a list of all ACTIVE systems (that have recently checked in with SUMA)
* **list_allgroups.py**: returns a list of all defined system groups
* **list_allsystems.py**: returns a list of all registered systems, including inactive ones
* **list_channels.py**: returns a list of all defined software channels, including child ones
* **list_custominfo.py**: returns all custominfo key/value pairs defined for a system. Requires a system ID.
* **list_cvestatus.py**: asks SUMA to return the patch status for a named CVE on all registered systems. Statuses can be PATCHED, AFFECTED_PATCH_APPLICABLE or NOT_AFFECTED.
* **list_locked.py**: returns a list of systems marked as "locked"
* **list_needsreboot.py**: returns a list of systems that currently need rebooting.
* **lookup_systemid.py**: looks up a hostname and returns the corresponding registered System ID.
* **packagesinstalled90days.py**: returns a list of all package actions that happened over the last 90 days, with status.
* **rebootsystem.py**: schedules a reboot for a system.
* **runscript_sm.py**: takes a list of hosts and a bash script, and schedules actions for every one of them. Use getresults_sm.py to fetch the results.
* **update_custominfo.py**: sets a custominfo key/value pair for a specific system.

