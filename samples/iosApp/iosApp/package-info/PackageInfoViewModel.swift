//
// Copyright 2021 Appmattus Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import SwiftUI
import Combine
import shared

class PackageInfoViewModel: ObservableObject {

    @Published var appName = "n/a"
    @Published var packageName = "n/a"
    @Published var version = "n/a"
    @Published var buildNumber = "n/a"

    private let packageInfo = PackageInfo()

    init() {

        for _ in 1...100 {
            let sha = SHA512()
            let digest = sha.digest()
            let str = digest.toHexString()
            print(str)
        }

        let sha = SHA512()
        let digest = sha.digest()
        let str = digest.toHexString()
        
        appName = str
        packageName = packageInfo.packageName ?? "n/a"
        version = packageInfo.version ?? "n/a"
        buildNumber = packageInfo.buildNumber ?? "n/a"
    }
}
