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

// Mocha's default 2s per-test timeout is too short for the larger known-answer tests on CI.
//
// Those tests also run synchronously for long enough to block the browser's event loop, so it can't answer Karma's
// socket.io heartbeat. With the defaults (a 5s ping timeout, then 2s to reconnect) Karma reports the browser as
// disconnected and fails the run, even though the tests themselves pass.
config.set({
    client: {
        mocha: {
            timeout: 60000
        }
    },
    pingTimeout: 60000,
    browserDisconnectTimeout: 60000,
    browserNoActivityTimeout: 120000
});
