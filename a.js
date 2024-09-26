import { URL } from 'node:url';
import { join } from 'node:path';

const url = new URL('/js/remoteEntry.js', 'https://local.docplanner.com/remotejs/badge/');
const urlWrong = new URL('/js/remoteEntry.js', '/remotejs/badge/');

console.log('output: ', url.toString());
console.log('error: ', urlWrong.toString());

console.log('output: ', join('/remotejs/badge/', 'js/remoteEntry.js'))
console.log('error: ', join('https://local.docplanner.com/remotejs/badge/', 'js/remoteEntry.js')) // https:/local.docplanner.com/remotejs/badge/js/remoteEntry.js
console.log('error: ', join('//local.docplanner.com/remotejs/badge/', 'js/remoteEntry.js')) // /local.docplanner.com/remotejs/badge/js/remoteEntry.js

encodeURIComponent()