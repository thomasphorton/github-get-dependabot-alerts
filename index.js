const fs = require('fs');
const { Octokit } = require('@octokit/rest');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

const GITHUB_PAT = '';
const GITHUB_ORG = '';

// Create a new Octokit instance with your GitHub API token
const octokit = new Octokit({
  auth: GITHUB_PAT
});

// Define the CSV writer
const csvWriter = createCsvWriter({
  path: 'dependabot-alerts.csv',
  header: [
    { id: 'repository', title: 'Repository' },
    { id: 'dependency', title: 'Dependency' },
    { id: 'severity', title: 'Severity' },
    { id: 'cve_id', title: 'CVE ID' },
    { id: 'cvss', title: 'CVSS' },
    { id: 'detection_date', title: 'Detection Date' },
    { id: 'update_date', title: 'Update Date' },
    { id: 'dismissed_at', title: 'Dismissed At' },
    { id: 'dismissed_by', title: 'Dismissed By' },
    { id: 'dismissed_reason', title: 'Dismissed Reason' },
    { id: 'dismissed_comment', title: 'Dismissed Comment' },
  ],
});

// Retrieve the list of repositories in the organization
octokit.paginate('GET /orgs/{org}/repos', {
  org: GITHUB_ORG,
})
.then((repos) => {
  // Loop through each repository and retrieve its Dependabot alerts and repo name
  const promises = repos.map((repo) => {
    return octokit.paginate('GET /repos/{owner}/{repo}/dependabot/alerts', {
      owner: repo.owner.login,
      repo: repo.name,
    })
    .then((alerts) => {
      return alerts.filter((alert) => alert.security_advisory.severity === 'high' || alert.security_advisory.severity === 'critical')
        .map((alert) => ({
          repository: repo.full_name,
          dependency: alert.dependency.package.name,
          severity: alert.security_advisory.severity,
          cve_id: alert.security_advisory.cve_id,
          cvss: alert.security_advisory.cvss.score,
          detection_date: alert.created_at,
          update_date: alert.updated_at,
          dismissed_at: alert.dismissed_at,
          dismissed_by: alert.dismissed_by,
          dismissed_reason: alert.dismissed_reason,
          dismissed_comment: alert.dismissed_comment,
        })
      );
    })
    .catch((error) => {
      // If the repository doesn't have Dependabot alerts enabled, skip it
      if (error.status === 404) {
        console.log(`Dependabot alerts not enabled for ${repo.full_name}`);
        return null;
      } else {
        throw error;
      }
    });
  });

  // Filter out repositories without Dependabot alerts
  return Promise.all(promises).then((results) => results.filter((result) => result !== null));
})
.then((results) => {

  // Flatten the array of arrays of alerts
  const alerts = results.flat();

  // Write the alerts to a CSV file
  csvWriter.writeRecords(alerts)
    .then(() => {
      console.log('Dependabot alerts saved to dependabot-alerts.csv');
    })
    .catch((error) => {
      console.error(error); // Add this line
    });
})
.catch((error) => {
  console.error(error);
});