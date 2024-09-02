import { readdir, readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';

import { info, setFailed } from '@actions/core';
import { exec } from '@actions/exec';
import { context } from '@actions/github';
import type { PullRequestEvent } from '@octokit/webhooks-types';

const CHANGESET_DIR = '.changeset';

(async function run() {
  try {
    const { pull_request } = context.payload as PullRequestEvent;
    const { ref } = pull_request.head;

    //TODO read it from context
    if (ref === 'changeset-release/develop') {
      info('[RemoteJS]: skipping changeset validation in release branch');

      return;
    }

    const status = await exec('yarn', ['changeset', 'status', '--since=origin/develop']);

    if (status !== 0) {
      setFailed('[RemoteJS]: The `yarn changeset status --since=origin/develop` command failed.');

      return;
    }

    const files = await readdir(CHANGESET_DIR);

    const markdowns = files.filter((file) => extname(file) === '.md');

    for (const file of markdowns) {
      const content = await readFile(join(CHANGESET_DIR, file), 'utf-8');

      const match = content.match(/(?<=---\n)([\s\S]*?)(?=\n---)/g);

      if (!match) {
        continue;
      }

      const [linesBetweenMarkers] = match;

      const lines = linesBetweenMarkers.split('\n');

      if (lines && lines.length !== 1) {
        setFailed('[RemoteJS]: Detect more than one workspace changes in changeset file.');

        break;
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      setFailed(`[RemoteJS]: An error occurred - ${error.message}`);
    }
  }
})();
