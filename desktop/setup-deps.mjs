import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const lib=new URL('./lib/',import.meta.url);await mkdir(lib,{recursive:true});
async function get(url){const response=await fetch(url);if(!response.ok)throw new Error(`${response.status} ${url}`);return response;}
const metadata=await (await get('https://repo.maven.apache.org/maven2/com/formdev/flatlaf/maven-metadata.xml')).text();
const version=metadata.match(/<release>([0-9.]+)<\/release>/)?.[1];if(!version)throw new Error('Invalid release metadata');
const artifact=`https://repo.maven.apache.org/maven2/com/formdev/flatlaf/${version}/flatlaf-${version}.jar`;
const bytes=Buffer.from(await (await get(artifact)).arrayBuffer());const expected=(await (await get(artifact+'.sha1')).text()).trim().split(/\s/)[0];
if(createHash('sha1').update(bytes).digest('hex')!==expected)throw new Error('FlatLaf checksum mismatch');
await writeFile(new URL('flatlaf.jar',lib),bytes);await writeFile(new URL('flatlaf-version.txt',lib),version+'\n');
await writeFile(new URL('FlatLaf-LICENSE.txt',lib),await (await get('https://raw.githubusercontent.com/JFormDesigner/FlatLaf/main/LICENSE')).text());
await writeFile(new URL('dependencies.json',lib),JSON.stringify({flatlaf:{version,url:artifact,sha256:createHash('sha256').update(bytes).digest('hex'),license:'Apache-2.0'}},null,2));
console.log(`FlatLaf ${version}: ${bytes.length} bytes`);
