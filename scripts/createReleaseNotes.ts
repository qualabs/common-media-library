import fs from 'fs-extra';

function release(version: string, changes: string) {
	return `## Release Notes

${changes}

## Documentation
- API Docs: https://streaming-video-technology-alliance.github.io/common-media-library/

## NPM Package
\`\`\`sh
npm install @svta/common-media-library@${{ version }}
\`\`\`
`;
}

async function getChanges(version: string) {
	const changeLog = await fs.readFile('./CHANGELOG.md', 'utf8');
	const logs = changeLog.split('\n\n\n');
	const match = `## [${version}]`;
	return logs.find(log => log.includes(match)) || '';
}

async function getVersion() {
	const pkg = await fs.readJson('./package.json');
	return pkg.version;
}

const createReleaseNotes = async () => {
	const version = await getVersion();
	const changes = await getChanges(version);
	const releaseNotes = release(version, changes);
	await fs.writeFile('./RELEASE.md', releaseNotes);
};

createReleaseNotes();