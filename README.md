# Getting Dependabot Alerts for An Org

1. install dependencies with `npm i`
2. create a PAT (classic) with `repo:security_events` permissions
3. update `index.js` with your PAT and GitHub org
4. run the script `node index`
5. a CSV will be generated at `./dependabot-alerts.csv`
