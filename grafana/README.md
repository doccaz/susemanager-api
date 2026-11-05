# Grafana dashboard: SUSE Manager General Reports

`suse-manager-general-reports.json` is the source of the
[SUSE Manager General Reports](https://grafana.com/grafana/dashboards/23039-suse-manager-general-reports/)
dashboard (grafana.com ID 23039).

Unlike the scripts in this repository, it doesn't use the XML-RPC API. It reads SUSE Multi-Linux
Manager's (SUSE Manager / Uyuni) **reporting database** (`reportdb`) through a Grafana PostgreSQL data
source.

## What's in it

* **Dynamic Stats**: systems with a given package installed, the latest 100 actions, and the latest 100
  package/patch operations.
* **Scheduled actions**: progress and results for one action ID.
* **Inventory**: kernel and OS distribution, group members, custom info, systems inventory, critical
  security patches and outdated systems.
* **Security by System Group**: the dashboard counterpart of `list_group_vulnerabilities.py`:
  * tiles: critical security patches pending, systems with critical patches, the oldest pending critical
    patch (days), and when the reporting database was last refreshed
  * pending security patches per group by severity (Critical/Important/Moderate/Low/Unrated), plus
    systems with critical patches and the oldest critical patch
  * patch age per group (0–30, 31–60, 61–90, over 90 days)
  * every pending security patch, oldest first, with systems affected, reboot flag and CVEs

  Use the **Groups** dropdown (multi-select, with "All") and the **Severity** filter (default Critical +
  Important) at the top to narrow it down. A system in several groups is counted in each one.

### Data freshness

The reporting database is not live. Taskomatic refreshes it with the `update-reporting-default` job
(daily by default), so the data can be up to a day old. The **Reporting DB synced** tile shows when it was
last refreshed. You can run the job on demand from *Admin → Task Schedules*.

## Requirements

* Grafana 10.4 or later, with the built-in PostgreSQL data source.
* Network access from Grafana to the SMLM server on port **5432**. On containerized SMLM 5.x the
  reporting database is published on the host; check with `ss -ltn | grep 5432` on the server and
  open the port in the firewall if needed.
* Reporting database credentials. The database, user and password created at install time are in
  the server container's `rhn.conf`:

  ```
  podman exec uyuni-server grep ^report_db_ /etc/rhn/rhn.conf
  ```

  (`report_db_name`, `report_db_user`, `report_db_password`). Prefer a dedicated read-only user for
  Grafana if your security policy requires it.

## Setup

1. **Add the data source**: *Connections → Data sources → Add → PostgreSQL*.
   * Host: `<smlm-server>:5432`
   * Database: `reportdb`
   * User / Password: from `rhn.conf`, see above
   * TLS/SSL mode: `require` (switch to `disable` only if your server doesn't offer TLS)
   * Click *Save & test*.
2. **Import the dashboard**: *Dashboards → New → Import*, then either enter ID `23039` (published
   version) or upload `suse-manager-general-reports.json` from this folder (latest version). Pick the
   data source from step 1 for both inputs.

   The file keeps the published dashboard's uid. If the dashboard is already imported, Grafana will
   offer to overwrite it; import into another folder or change the name/uid to keep both.

### Quick local test

To try it without touching an existing Grafana:

```
docker run -d --name grafana-test -p 3000:3000 grafana/grafana:10.4.15
```

Open http://localhost:3000 (admin/admin) and follow the setup steps above.

## Updating the published dashboard

Edit the dashboard in Grafana, then *Share → Export → Export for sharing externally* (this keeps the
`${DS_...}` placeholders instead of your local data source uid), save it over
`suse-manager-general-reports.json`, commit, and upload it as a new revision on grafana.com.
