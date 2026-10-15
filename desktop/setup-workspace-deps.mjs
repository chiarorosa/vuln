import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
async function get(url){const r=await fetch(url);if(!r.ok)throw Error(`${r.status} ${url}`);return r;}
const lib=new URL('./lib/',import.meta.url);await mkdir(lib,{recursive:true});
const version='1.9.1',url=`https://repo.maven.apache.org/maven2/org/mozilla/rhino/${version}/rhino-${version}.jar`;
const jar=Buffer.from(await (await get(url)).arrayBuffer()),sha=(await (await get(url+'.sha1')).text()).trim().split(/\s/)[0];
if(createHash('sha1').update(jar).digest('hex')!==sha)throw Error('Rhino checksum mismatch');
await writeFile(new URL('rhino.jar',lib),jar);
await writeFile(new URL('Rhino-LICENSE.txt',lib),await (await get('https://raw.githubusercontent.com/mozilla/rhino/Rhino1_9_1_Release/LICENSE.txt')).text());
await writeFile(new URL('rhino-sources.jar',lib),Buffer.from(await (await get(url.replace('.jar','-sources.jar'))).arrayBuffer()));
const page=await (await get('https://curl.se/windows/')).text();
const archiveUrl=new URL(page.match(/href="([^"<>]*curl-[^"<>]*win64-mingw\.zip)"/)?.[1]??'https://curl.se/windows/latest.cgi?p=win64-mingw.zip','https://curl.se/windows/').href;
const archive=Buffer.from(await (await get(archiveUrl)).arrayBuffer());
const checksumText=await (await get(archiveUrl+'.txt')).text();
const expected=checksumText.match(/[a-f0-9]{64}/i)?.[0];if(!expected||createHash('sha256').update(archive).digest('hex')!==expected.toLowerCase())throw Error('curl checksum mismatch');
await writeFile(new URL('curl.zip',lib),archive);
await writeFile(new URL('workspace-dependencies.json',lib),JSON.stringify({rhino:{version,url,sha256:createHash('sha256').update(jar).digest('hex'),license:'MPL-2.0',source:url.replace('.jar','-sources.jar')},curl:{url:archiveUrl,sha256:expected}},null,2));
console.log(`Verified Rhino ${version} (${jar.length} bytes) and curl (${archive.length} bytes)`);
