# ƛ GitHub Security Updater

This is a Lambda to periodically synchronize security groups with the IP ranges for webhooks provided by GitHub's API.

The use case for this would be having a service locked down by source IP in the whitelist, which still needs to receive webhooks for repository events from GitHub (ie a CI/CD tool).

This tool uses the [Serverless Framework](https://serverless.com/) for deployment

## How it works

This will take the current set of webhook IP ranges from [GitHub's API](https://api.github.com/meta), and maintain a new security group allowing these IP ranges on ports 80 and 443.

This can maintain a security group across multiple VPCs.

## Configuration, Installation & Deployment

Clone this repository, and change to the cloned directory.

Configuration is expected to be found in AWS EC2 Systems Manager Parameter Store.

All variables live under the prefix of `/github_secgrp_updater/{STAGE}`. Replace stage with the relevant stage you are deploying (ie `/github_secgrp_updater/dev/`)

Relevant variables are shown in the table below.

| Variable             | Required | Default Value       | Description |
|----------------------|----------|---------------------|-------------|
| /vpc_ids             | Yes      |                     | A comma separated list of VPC IDs in which to maintain a security group. |
| /secgrp_name         | No       | AllowGitHubWebhooks | Override the name of the maintained security group |


Finally, deploy with the following

```
npm install serverless -g

serverless deploy
```

### Deploying multiple environments

This supports the serverless framework's concept of stages. Deploy additional stages like so:
```
serverless deploy --stage prod
```

## Contributions & Changelog
Please see the [GitHub Releases page](https://github.com/hreeder/lambda-github-secgroup-updater/releases) for the changelog of this tool.

Releases will be properly versioned following [Semantic Versioning](https://semver.org/).

Contributions are welcome, in the form of either issues or pull requests.
