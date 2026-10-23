"""Publish versioned wiki sources using the job's temporary GitHub token."""
import base64
import os
from pathlib import Path
import re
import subprocess

repo = os.environ['GITHUB_REPOSITORY']
if repo != 'navidhaghpanah/vpn-share':
    raise SystemExit('Wiki publication is restricted to the intended repository.')
token = os.environ['GH_TOKEN']
env = os.environ.copy()
env.update({
    'GIT_TERMINAL_PROMPT': '0',
    'GIT_CONFIG_COUNT': '1',
    'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader',
    'GIT_CONFIG_VALUE_0': 'AUTHORIZATION: basic ' + base64.b64encode(
        ('x-access-token:' + token).encode()).decode(),
})
target = Path(os.environ['RUNNER_TEMP'])/'vpnshare-persian-wiki'
cloned = subprocess.run(['git', 'clone', '--depth', '1',
                         f'https://github.com/{repo}.wiki.git', str(target)],
                        env=env, text=True, capture_output=True)
if cloned.returncode:
    if 'not found' not in cloned.stderr.lower():
        raise SystemExit('Could not clone the wiki. Check job permissions and connectivity.')
    message = (
        '## GitHub Wiki needs its first page\n\n'
        f'Open https://github.com/{repo}/wiki/_new and save an initial Home page. '
        'The gollum event will then run this workflow and publish the Persian pages. '
        'All documentation is already available in the repository wiki/ folder.\n')
    Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(message, encoding='utf-8')
    print('::notice::Wiki has not been initialized. Save its first Home page on GitHub; synchronization is ready.')
    raise SystemExit(0)

def git(*args, **kwargs):
    return subprocess.run(['git', '-C', str(target), *args], env=env,
                          text=True, capture_output=True, **kwargs)

names = []
for source in sorted(Path('wiki').glob('*.md')):
    # Repository links use .md; GitHub Wiki page URLs omit that extension.
    text = re.sub(r'(?<=\]\()([A-Za-z0-9_-]+)\.md(?=[)#])', r'\1',
                  source.read_text(encoding='utf-8'))
    (target/source.name).write_text(text, encoding='utf-8')
    names.append(source.name)
if not names or 'Home.md' not in names:
    raise SystemExit('Wiki source pages are missing.')
git('config', 'user.name', 'github-actions[bot]', check=True)
git('config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', check=True)
git('add', '--', *names, check=True)
diff = git('diff', '--cached', '--quiet')
if diff.returncode == 0:
    print('Wiki is already synchronized.')
    raise SystemExit(0)
if diff.returncode != 1:
    raise SystemExit('Could not inspect wiki changes.')
git('commit', '-m', 'Publish Persian VPN Share documentation', check=True)
git('push', 'origin', 'HEAD', check=True)
Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(
    f'Published {len(names)} Persian wiki files to https://github.com/{repo}/wiki\n',
    encoding='utf-8')
print(f'Published {len(names)} Persian wiki files.')
