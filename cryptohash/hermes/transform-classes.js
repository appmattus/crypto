/*
 * Copyright 2026 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


// Rewrites the ES2015 classes in the Hermes test bundle as functions. The Hermes CLI from hermes-engine-cli can't parse
// class syntax, which Kotlin/JS's standard library uses, so this does what React Native's Babel preset does for apps
// that run on Hermes.
//
// Usage: node transform-classes.js <input.js> <output.js>
const babel = require('@babel/core');
const fs = require('fs');

const [input, output] = process.argv.slice(2);
const result = babel.transformSync(fs.readFileSync(input, 'utf8'), {
    babelrc: false,
    configFile: false,
    sourceType: 'script',
    compact: false,
    plugins: [require.resolve('@babel/plugin-transform-classes')],
});
fs.writeFileSync(output, result.code);
