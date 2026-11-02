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

// Runs before the Kotlin/JS test code in the Hermes test bundle.
//
// The Hermes CLI has no test framework and no console, only print(). kotlin.test's JS output registers tests through
// whatever Jasmine/Mocha-style describe/it functions exist globally, so this defines minimal ones that collect the
// tests, and __hermesRunTests runs them once everything has loaded.
(function (global) {
    if (typeof global.console === 'undefined') {
        var log = function () {
            print(Array.prototype.join.call(arguments, ' '));
        };
        global.console = {log: log, info: log, warn: log, error: log, debug: log};
    }

    var root = {suites: [], tests: [], skip: false};
    var current = root;

    function suite(name, body, skip) {
        var child = {name: name, suites: [], tests: [], skip: skip || current.skip};
        current.suites.push(child);
        var parent = current;
        current = child;
        try {
            body();
        } finally {
            current = parent;
        }
    }

    function test(name, body, skip) {
        current.tests.push({name: name, body: body, skip: skip || current.skip});
    }

    global.describe = function (name, body) { suite(name, body, false); };
    global.xdescribe = function (name, body) { suite(name, body, true); };
    global.it = function (name, body) { test(name, body, false); };
    global.xit = function (name, body) { test(name, body, true); };

    // Runs every collected test and returns the number that failed
    global.__hermesRunTests = function () {
        var passed = 0, failed = 0, skipped = 0;

        function run(node, path) {
            var started = Date.now();
            var failedBefore = failed;
            node.tests.forEach(function (t) {
                var name = path.concat([t.name]).join(' > ');
                if (t.skip) {
                    skipped++;
                    return;
                }
                try {
                    var result = t.body();
                    if (result && typeof result.then === 'function') {
                        throw new Error('asynchronous tests are not supported by the Hermes runner');
                    }
                    passed++;
                } catch (e) {
                    failed++;
                    print('FAILED ' + name + '\n    ' + (e && e.stack ? e.stack : e));
                }
            });
            // One line per test class, so slow suites show up in the log as they run
            if (node.tests.length > 0) {
                print((failed > failedBefore ? 'FAIL ' : 'ok   ') + path.join(' > ') + ' (' + (Date.now() - started) + ' ms)');
            }
            node.suites.forEach(function (child) {
                run(child, path.concat([child.name]));
            });
        }

        run(root, []);
        print('Hermes: ' + passed + ' passed, ' + failed + ' failed, ' + skipped + ' skipped');
        if (passed + failed === 0) {
            print('Hermes: no tests ran');
            return 1;
        }
        return failed;
    };
})(globalThis);
